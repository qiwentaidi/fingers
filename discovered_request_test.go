package fingers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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
