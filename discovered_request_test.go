package fingers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestNormalizeWrappedProtocolTarget(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "ftp wrapped in https authority",
			raw:  "https://ftp//127.0.0.1:21",
			want: "ftp://127.0.0.1:21",
		},
		{
			name: "ordinary http double slash path",
			raw:  "http://example.com//assets/app.js",
			want: "http://example.com//assets/app.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeWrappedProtocolTarget(tt.raw); got != tt.want {
				t.Fatalf("normalizeWrappedProtocolTarget(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestPreflightHeadlessDocumentAllowsHTMLResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body>ok</body></html>`))
	}))
	defer server.Close()

	if err := preflightHeadlessDocument(context.Background(), server.URL, ""); err != nil {
		t.Fatalf("expected HTML response to be allowed, got %v", err)
	}
}

func TestPreflightHeadlessDocumentSkipsAttachmentResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="index.html"`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body>download</body></html>`))
	}))
	defer server.Close()

	err := preflightHeadlessDocument(context.Background(), server.URL, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported document response") {
		t.Fatalf("expected attachment response to be skipped, got %v", err)
	}
}

func TestPreflightHeadlessDocumentSkipsForcedDownloadMIMEType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(`<!doctype html><html><body>download</body></html>`))
	}))
	defer server.Close()

	err := preflightHeadlessDocument(context.Background(), server.URL, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported document response") {
		t.Fatalf("expected octet-stream response to be skipped, got %v", err)
	}
}

func TestPreflightHeadlessDocumentSkipsPHPSourceMIMEType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-httpd-php")
		_, _ = w.Write([]byte(`<?php header('Location: web/manager/#/');`))
	}))
	defer server.Close()

	err := preflightHeadlessDocument(context.Background(), server.URL, "")
	if !errors.Is(err, errHeadlessNavigationSkipped) {
		t.Fatalf("expected PHP source response to skip headless navigation, got %v", err)
	}
}

func TestExtractHTMLPageReferencesIncludesPHPHeaderLocation(t *testing.T) {
	refs := extractHTMLPageReferences([]byte(`<?php
header('Location: web/manager/#/');
`))

	if len(refs) != 1 || refs[0] != "web/manager/#/" {
		t.Fatalf("unexpected PHP header references: %#v", refs)
	}
}

func TestCheckJSRedirectRecognizesPHPHeaderLocation(t *testing.T) {
	if got := checkJSRedirect(`<?php header('Location: web/manager/#/');`); got != "web/manager/#/" {
		t.Fatalf("unexpected PHP header redirect: %q", got)
	}
}

func TestDiscoveredRequestBuilderBuildsExternalJSONEvidence(t *testing.T) {
	builder := NewDiscoveredRequestBuilder("https://example.com").
		WithAPIRoots("/api").
		AddRequestWithResponse(
			http.MethodPost,
			"https://example.com/api/orders",
			map[string]string{"Content-Type": "application/json"},
			`{"id":1}`,
			http.StatusAccepted,
			map[string]string{"X-Trace": "abc"},
			`{"accepted":true}`,
			"application/json",
		)

	if builder.Target() != "https://example.com" {
		t.Fatalf("unexpected builder target: %q", builder.Target())
	}
	if roots := builder.APIRoots(); len(roots) != 1 || roots[0] != "/api" {
		t.Fatalf("unexpected api roots: %#v", roots)
	}
	requests := builder.Requests()
	if len(requests) != 1 {
		t.Fatalf("unexpected requests: %#v", requests)
	}
	if requests[0].Method != http.MethodPost || requests[0].ContentType != "application/json" ||
		requests[0].Headers["Content-Type"] != "application/json" ||
		requests[0].ResponseCode != http.StatusAccepted ||
		requests[0].ResponseHeaders["X-Trace"] != "abc" ||
		requests[0].ResponseBody != `{"accepted":true}` ||
		requests[0].Source != "external-js-discovery" {
		t.Fatalf("unexpected request evidence: %#v", requests[0])
	}

	requests[0].Headers["Content-Type"] = "text/plain"
	if got := builder.Requests()[0].Headers["Content-Type"]; got != "application/json" {
		t.Fatalf("builder should return cloned request headers, got %q", got)
	}
}

func TestSelectShiroCandidatesUsesOnlyDynamicNonRootEndpointURLs(t *testing.T) {
	candidates := SelectShiroCandidates("https://example.com", []DiscoveredRequest{
		{URL: "https://example.com/"},
		{URL: "https://example.com/api/session?token=do-not-replay"},
		{URL: "https://example.com/api/session?duplicate=true", Method: http.MethodPost, Body: `{"password":"do-not-replay"}`},
		{URL: "https://other.example/api/session"},
		{URL: "not a url"},
	})

	if len(candidates) != 1 || candidates[0] != "https://example.com/api/session" {
		t.Fatalf("unexpected Shiro candidates: %#v", candidates)
	}
}

func TestSelectShiroCandidatesIncludesAPIRootJoinedEndpointURLs(t *testing.T) {
	candidates := SelectShiroCandidates("https://example.com", []DiscoveredRequest{
		{URL: "https://example.com/security/session?token=do-not-replay"},
		{URL: "/users/current?token=do-not-replay"},
	}, []string{"/api", "https://example.com/api", "https://other.example/api"})

	expected := []string{
		"https://example.com/api/security/session",
		"https://example.com/api/users/current",
		"https://example.com/security/session",
	}
	if len(candidates) != len(expected) {
		t.Fatalf("unexpected Shiro candidate count: got %#v want %#v", candidates, expected)
	}
	for i := range expected {
		if candidates[i] != expected[i] {
			t.Fatalf("unexpected Shiro candidates: got %#v want %#v", candidates, expected)
		}
	}
}

func TestSelectFastjsonCandidatesKeepsOnlyUniqueJSONRequests(t *testing.T) {
	requests := []DiscoveredRequest{
		{URL: "https://example.com/api/orders", Method: http.MethodPost, ContentType: "application/json", Body: `{"id":1}`},
		{URL: "https://example.com/api/orders", Method: http.MethodPost, Headers: map[string]string{"Content-Type": "application/json", "Authorization": "volatile"}, Body: `{"id":1}`},
		{URL: "https://example.com/api/orders", Method: http.MethodPost, ContentType: "application/json", Body: `{"id":2}`},
		{URL: "https://example.com/api/form", Method: http.MethodPost, ContentType: "application/x-www-form-urlencoded", Body: "id=1"},
	}

	candidates := SelectFastjsonCandidates(requests)
	if len(candidates) != 2 {
		t.Fatalf("expected two unique JSON candidates, got %#v", candidates)
	}
	if candidates[0].Body != `{"id":1}` || candidates[1].Body != `{"id":2}` {
		t.Fatalf("unexpected Fastjson candidate bodies: %#v", candidates)
	}
}

func TestScanDiscoveredRequestsShiroProbeSkipsRootAndPreservesCookieEvidence(t *testing.T) {
	var mu sync.Mutex
	paths := make([]string, 0, 2)
	cookies := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		cookies = append(cookies, r.Header.Get("Cookie"))
		mu.Unlock()
		w.Header().Add("Set-Cookie", "session=abc; Path=/")
		w.Header().Add("Set-Cookie", "rememberMe=deleteMe; Path=/; Max-Age=0")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fingerprints := ScanDiscoveredRequests(server.URL, []DiscoveredRequest{
		{URL: server.URL + "/"},
		{URL: server.URL + "/api/security/session?csrf=secret", Method: http.MethodPost, Body: `{"password":"secret"}`},
	}, true)

	if len(fingerprints) != 1 {
		t.Fatalf("expected one Shiro fingerprint match, got %#v", fingerprints)
	}
	if fingerprints[0].URL != server.URL+"/api/security/session" ||
		len(fingerprints[0].Fingerprints) != 1 || fingerprints[0].Fingerprints[0].Name != "Shiro" {
		t.Fatalf("unexpected Shiro fingerprint: %#v", fingerprints[0])
	}
	if !fingerprints[0].Fingerprints[0].HighRisk {
		t.Fatalf("expected discovered Shiro fingerprint to be high risk: %#v", fingerprints[0].Fingerprints[0])
	}
	if fingerprints[0].StatusCode != http.StatusOK || fingerprints[0].Detect != "DiscoveredRequestShiro" {
		t.Fatalf("expected Shiro result fields, got %#v", fingerprints[0])
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/api/security/session" {
		t.Fatalf("unexpected probe paths: %#v", paths)
	}
	if len(cookies) != 1 || cookies[0] != shiroRememberMeProbeCookie {
		t.Fatalf("unexpected probe cookies: %#v", cookies)
	}
}

func TestScanDiscoveredRequestsEmitsFastjsonFingerprintForProbeHit(t *testing.T) {
	var mu sync.Mutex
	requests := make([]struct {
		Method      string
		ContentType string
		Body        string
	}, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, struct {
			Method      string
			ContentType string
			Body        string
		}{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			Body:        string(body),
		})
		mu.Unlock()
		if r.Method == http.MethodPost && string(body) == fastjsonProbeBody {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"fastjson-version":"1.2.83"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	fingerprints := ScanDiscoveredRequests(server.URL, []DiscoveredRequest{
		{URL: server.URL + "/api/orders", Method: http.MethodPost, ContentType: "application/json", Body: `{"id":1}`},
		{URL: server.URL + "/api/orders", Method: http.MethodPost, ContentType: "application/json", Body: `{"id":2}`},
		{URL: server.URL + "/api/invalid", Method: http.MethodPost, ContentType: "application/json", Body: "not-json"},
	}, true)

	if len(fingerprints) != 1 || fingerprints[0].URL != server.URL+"/api/orders" ||
		len(fingerprints[0].Fingerprints) != 1 || fingerprints[0].Fingerprints[0].Name != "Fastjson" {
		t.Fatalf("unexpected Fastjson fingerprints: %#v", fingerprints)
	}
	if !fingerprints[0].Fingerprints[0].HighRisk {
		t.Fatalf("expected discovered Fastjson fingerprint to be high risk: %#v", fingerprints[0].Fingerprints[0])
	}
	if fingerprints[0].StatusCode != http.StatusCreated || fingerprints[0].Length != len(`{"fastjson-version":"1.2.83"}`) ||
		fingerprints[0].Detect != "DiscoveredRequestFastjson" {
		t.Fatalf("expected Fastjson result fields, got %#v", fingerprints[0])
	}

	mu.Lock()
	defer mu.Unlock()
	fastjsonProbes := 0
	for _, request := range requests {
		if request.Method != http.MethodPost {
			continue
		}
		fastjsonProbes++
		if request.ContentType != "application/json" || request.Body != fastjsonProbeBody {
			t.Fatalf("unexpected Fastjson probe request: %#v", request)
		}
	}
	if fastjsonProbes != 1 {
		t.Fatalf("expected one Fastjson POST probe, got %#v", requests)
	}
}

func TestScanDiscoveredRequestsKeepsJSONRequestFingerprintWithoutFastjsonHit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	fingerprints := ScanDiscoveredRequests(server.URL, []DiscoveredRequest{
		{URL: server.URL + "/api/orders", Method: http.MethodPost, ContentType: "application/json", Body: `{"id":1}`,
			ResponseCode: http.StatusCreated, ResponseBody: `{"accepted":true}`, Source: "external-js-discovery"},
	}, true)

	if len(fingerprints) != 1 || fingerprints[0].URL != server.URL+"/api/orders" ||
		len(fingerprints[0].Fingerprints) != 1 || fingerprints[0].Fingerprints[0].Name != "json-payload-required" {
		t.Fatalf("expected JSON request fingerprint without Fastjson probe evidence, got %#v", fingerprints)
	}
	if fingerprints[0].StatusCode != http.StatusCreated || fingerprints[0].Length != len(`{"accepted":true}`) ||
		fingerprints[0].Detect != "external-js-discovery" {
		t.Fatalf("expected captured JSON metadata to be retained, got %#v", fingerprints[0])
	}
}

func TestSubmitDiscoveredRequestBuilderFiltersOriginAndMergesBindings(t *testing.T) {
	var mu sync.Mutex
	probeCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodPost && string(body) == fastjsonProbeBody {
			mu.Lock()
			probeCount++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	scanner := newSubmitTestScanner(t, server.URL)
	builder := NewDiscoveredRequestBuilder(server.URL).
		AddJSONRequest(http.MethodPost, "/api/orders", `{"id":1}`).
		AddJSONRequest(http.MethodPost, "https://other.example.com/api/orders", `{"id":2}`)

	results, err := scanner.SubmitDiscoveredRequestBuilder(builder)
	if err != nil {
		t.Fatalf("SubmitDiscoveredRequestBuilder() error = %v", err)
	}
	if len(results) != 1 || results[0].URL != server.URL+"/api/orders" ||
		len(results[0].Fingerprints) != 1 || results[0].Fingerprints[0].Name != "json-payload-required" {
		t.Fatalf("unexpected submit results: %#v", results)
	}

	mu.Lock()
	defer mu.Unlock()
	if probeCount != 1 {
		t.Fatalf("expected one fastjson probe for the origin, got %d", probeCount)
	}

	scanner.mutex.Lock()
	bindings := scanner.basicURLWithFingerprint[server.URL+"/api/orders"]
	scanner.mutex.Unlock()
	if len(bindings) != 1 || bindings[0] != "json-payload-required" {
		t.Fatalf("expected fingerprint binding merged, got %#v", bindings)
	}
}

func newSubmitTestScanner(t *testing.T, target string) *FingerScanner {
	t.Helper()
	scanner, err := NewScanner(Options{
		Targets:              []string{target},
		DisableDefaultOutput: true,
		FingerprintData: []byte(`
Web:
  - name: placeholder
    rule:
      - body="placeholder-never-matches"
`),
	})
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}
	return scanner
}

func TestActiveFingerScanCollectsFaviconForHTMLPath(t *testing.T) {
	iconBody := []byte("nacos logo")
	iconHash := Mmh3Hash32(iconBody)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nacos/":
			_, _ = w.Write([]byte(`<html><head><title>Nacos</title><link rel="shortcut icon" href="console-ui/public/img/nacos-logo.png"></head><body>nacos</body></html>`))
		case "/nacos/console-ui/public/img/nacos-logo.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(iconBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	rule := `icon_hash="` + iconHash + `"`
	scanner := &FingerScanner{
		aliveURLs: []*url.URL{target},
		fingerprintRepo: BuildFingerprintRepository([]FingerEntity{{
			ProductName: "Nacos Icon",
			AllString:   rule,
			Path:        []string{"/nacos/"},
			Rule:        ParseRule(rule),
		}}),
		activeTimeoutLimit:      5,
		thread:                  1,
		client:                  resty.New(),
		basicURLWithFingerprint: map[string][]string{},
		faviconStore:            &localStore{baseDir: t.TempDir()},
	}

	var results []Result
	scanner.ActiveFingerScan(context.Background(), func(result Result) {
		if result.Detect == "Active" {
			results = append(results, result)
		}
	})

	if len(results) != 1 {
		t.Fatalf("got %d active results, want 1: %#v", len(results), results)
	}
	result := results[0]
	if result.IconHash != iconHash {
		t.Fatalf("IconHash = %q, want %q", result.IconHash, iconHash)
	}
	if result.FaviconURL != server.URL+"/nacos/console-ui/public/img/nacos-logo.png" {
		t.Fatalf("FaviconURL = %q", result.FaviconURL)
	}
	if result.Favicon == "" {
		t.Fatal("Favicon path is empty")
	}
	storedIcon, err := os.ReadFile(result.Favicon)
	if err != nil {
		t.Fatalf("read saved favicon: %v", err)
	}
	if string(storedIcon) != string(iconBody) {
		t.Fatalf("saved favicon = %q, want %q", storedIcon, iconBody)
	}
	if len(result.Fingerprints) != 1 || result.Fingerprints[0].Name != "Nacos Icon" {
		t.Fatalf("Fingerprints = %#v, want Nacos Icon", result.Fingerprints)
	}
}
