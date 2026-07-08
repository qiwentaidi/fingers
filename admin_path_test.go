package fingers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestActiveFingerScanReportsAdminPathDifferentFingerprintOnNon404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><head><title>Admin Console</title></head><body>public marker admin marker</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	scanner := &FingerScanner{
		aliveURLs: []*url.URL{target},
		fingerprintRepo: BuildFingerprintRepository([]FingerEntity{
			testFingerEntity("Public Portal", nil, `body="public marker"`),
			testFingerEntity("Admin Console", nil, `title="admin console"`),
		}),
		activeTimeoutLimit:      5,
		thread:                  4,
		client:                  resty.New(),
		basicURLWithFingerprint: map[string][]string{server.URL: []string{"Public Portal"}},
	}

	results := make([]Result, 0)
	scanner.ActiveFingerScan(context.Background(), func(result Result) {
		results = append(results, result)
	})

	adminResults := filterResultsByDetect(results, adminPathDetectName)
	if len(adminResults) != 1 {
		t.Fatalf("got %d admin results, want 1: %#v", len(adminResults), adminResults)
	}

	result := adminResults[0]
	if result.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusForbidden)
	}
	if result.Path != "/admin/" {
		t.Fatalf("Path = %q, want %q", result.Path, "/admin/")
	}
	if len(result.Fingerprints) != 1 || result.Fingerprints[0].Name != "Admin Console" {
		t.Fatalf("Fingerprints = %#v, want only Admin Console", result.Fingerprints)
	}
}

func TestActiveFingerScanSkipsAdminPathWithoutDifferentFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/":
			_, _ = w.Write([]byte("<html><head><title>Public</title></head><body>public marker</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	scanner := &FingerScanner{
		aliveURLs: []*url.URL{target},
		fingerprintRepo: BuildFingerprintRepository([]FingerEntity{
			testFingerEntity("Public Portal", nil, `body="public marker"`),
		}),
		activeTimeoutLimit:      5,
		thread:                  4,
		client:                  resty.New(),
		basicURLWithFingerprint: map[string][]string{server.URL: []string{"Public Portal"}},
	}

	results := make([]Result, 0)
	scanner.ActiveFingerScan(context.Background(), func(result Result) {
		results = append(results, result)
	})

	adminResults := filterResultsByDetect(results, adminPathDetectName)
	if len(adminResults) != 0 {
		t.Fatalf("got %d admin results, want 0: %#v", len(adminResults), adminResults)
	}
}

func TestActiveFingerScanDeduplicatesAdminPathTrailingSlashFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console", "/console/":
			_, _ = w.Write([]byte("<html><head><title>Console</title></head><body>console marker</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	scanner := &FingerScanner{
		aliveURLs: []*url.URL{target},
		fingerprintRepo: BuildFingerprintRepository([]FingerEntity{
			testFingerEntity("Console", nil, `body="console marker"`),
		}),
		activeTimeoutLimit:      5,
		thread:                  1,
		client:                  resty.New(),
		basicURLWithFingerprint: map[string][]string{},
	}

	results := make([]Result, 0)
	scanner.ActiveFingerScan(context.Background(), func(result Result) {
		results = append(results, result)
	})

	adminResults := filterResultsByDetect(results, adminPathDetectName)
	if len(adminResults) != 1 {
		t.Fatalf("got %d admin results, want 1: %#v", len(adminResults), adminResults)
	}
	if adminResults[0].Path != "/console" {
		t.Fatalf("Path = %q, want %q", adminResults[0].Path, "/console")
	}
	if len(adminResults[0].Fingerprints) != 1 || adminResults[0].Fingerprints[0].Name != "Console" {
		t.Fatalf("Fingerprints = %#v, want only Console", adminResults[0].Fingerprints)
	}
}

func TestActiveFingerScanMatchesAdminPathFaviconFingerprint(t *testing.T) {
	iconBody := []byte("admin path icon")
	iconHash := Mmh3Hash32(iconBody)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/console":
			_, _ = w.Write([]byte(`<html><head><title>Console</title><link rel="icon" href="/console.ico"></head><body>console</body></html>`))
		case "/console.ico":
			w.Header().Set("Content-Type", "image/x-icon")
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

	scanner := &FingerScanner{
		aliveURLs: []*url.URL{target},
		fingerprintRepo: BuildFingerprintRepository([]FingerEntity{
			testFingerEntity("Console Icon", nil, `icon_hash="`+iconHash+`"`),
		}),
		activeTimeoutLimit:      5,
		thread:                  1,
		client:                  resty.New(),
		basicURLWithFingerprint: map[string][]string{},
		faviconStore:            noopStore{},
	}

	results := make([]Result, 0)
	scanner.ActiveFingerScan(context.Background(), func(result Result) {
		results = append(results, result)
	})

	adminResults := filterResultsByDetect(results, adminPathDetectName)
	if len(adminResults) != 1 {
		t.Fatalf("got %d admin results, want 1: %#v", len(adminResults), adminResults)
	}
	if adminResults[0].IconHash != iconHash {
		t.Fatalf("IconHash = %q, want %q", adminResults[0].IconHash, iconHash)
	}
	if adminResults[0].FaviconURL != server.URL+"/console.ico" {
		t.Fatalf("FaviconURL = %q, want %q", adminResults[0].FaviconURL, server.URL+"/console.ico")
	}
	if !hasFingerprint(adminResults[0].Fingerprints, "Console Icon") {
		t.Fatalf("Fingerprints = %#v, want Console Icon", adminResults[0].Fingerprints)
	}
}

func TestProbeHostTokenPathMatchesFaviconFingerprint(t *testing.T) {
	iconBody := []byte("host token path icon")
	iconHash := Mmh3Hash32(iconBody)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/portal/":
			_, _ = w.Write([]byte(`<html><head><title>Portal</title><link rel="icon" href="favicon.ico"></head><body>portal</body></html>`))
		case "/portal/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(iconBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	scanner := &FingerScanner{
		fingerprintRepo: BuildFingerprintRepository([]FingerEntity{
			testFingerEntity("Portal Icon", nil, `icon_hash="`+iconHash+`"`),
		}),
		client:          resty.New(),
		notFollowClient: resty.New(),
		faviconStore:    noopStore{},
	}

	result, ok := scanner.probeHostTokenPath(context.Background(), base, "/portal/")
	if !ok {
		t.Fatal("probeHostTokenPath returned no result")
	}
	if result.IconHash != iconHash {
		t.Fatalf("IconHash = %q, want %q", result.IconHash, iconHash)
	}
	if result.FaviconURL != server.URL+"/portal/favicon.ico" {
		t.Fatalf("FaviconURL = %q, want %q", result.FaviconURL, server.URL+"/portal/favicon.ico")
	}
	if !hasFingerprint(result.Fingerprints, "Portal Icon") {
		t.Fatalf("Fingerprints = %#v, want Portal Icon", result.Fingerprints)
	}
}

func testFingerEntity(name string, path []string, rule string) FingerEntity {
	return FingerEntity{
		ProductName: name,
		AllString:   rule,
		Path:        path,
		Rule:        ParseRule(rule),
	}
}

func filterResultsByDetect(results []Result, detect string) []Result {
	filtered := make([]Result, 0)
	for _, result := range results {
		if result.Detect == detect {
			filtered = append(filtered, result)
		}
	}
	return filtered
}

func hasFingerprint(fingerprints []FingerprintMatch, name string) bool {
	for _, fp := range fingerprints {
		if fp.Name == name {
			return true
		}
	}
	return false
}
