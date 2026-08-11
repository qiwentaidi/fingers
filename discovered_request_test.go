package fingers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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

func TestSelectShiroCandidatesDoesNotDuplicateExistingAPIRootPath(t *testing.T) {
	candidates := SelectShiroCandidates("https://example.com", []DiscoveredRequest{
		{URL: "https://example.com/api/security/session?token=do-not-replay"},
	}, []string{"/api"})

	if len(candidates) != 1 || candidates[0] != "https://example.com/api/security/session" {
		t.Fatalf("unexpected Shiro candidates: %#v", candidates)
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
		len(fingerprints[0].Fingerprints) != 1 || fingerprints[0].Fingerprints[0].Name != "fastjson" {
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
			ResponseCode: http.StatusCreated, ResponseBody: `{"accepted":true}`, Source: "dynamic-browser-capture"},
	}, true)

	if len(fingerprints) != 1 || fingerprints[0].URL != server.URL+"/api/orders" ||
		len(fingerprints[0].Fingerprints) != 1 || fingerprints[0].Fingerprints[0].Name != "json-payload-required" {
		t.Fatalf("expected JSON request fingerprint without Fastjson probe evidence, got %#v", fingerprints)
	}
	if fingerprints[0].StatusCode != http.StatusCreated || fingerprints[0].Length != len(`{"accepted":true}`) ||
		fingerprints[0].Detect != "dynamic-browser-capture" {
		t.Fatalf("expected captured JSON metadata to be retained, got %#v", fingerprints[0])
	}
}
