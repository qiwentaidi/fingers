package fingers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/qiwentaidi/clients"
)

const shiroRememberMeProbeCookie = "rememberMe=true"
const fastjsonProbeBody = `{"\u0040\u0074\u0079\u0070\u0065":"java.lang.AutoCloseabl\u0065"}`

// DiscoveredRequest is a request observed while a browser loads or interacts
// with a target. Special-purpose detectors use this evidence instead of
// guessing paths, methods, or request payloads.
type DiscoveredRequest struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             string            `json:"body,omitempty"`
	ContentType      string            `json:"contentType,omitempty"`
	ResponseHeaders  map[string]string `json:"-"`
	ResponseBody     string            `json:"-"`
	ResponseCode     int               `json:"-"`
	ResponseMIMEType string            `json:"-"`
	Source           string            `json:"source,omitempty"`
}

// ScanDiscoveredRequests runs request-aware fingerprint checks against dynamic
// browser evidence. Shiro uses URL-only rememberMe probing, while Fastjson uses
// captured JSON request bodies to avoid guessing payload-capable endpoints.
func ScanDiscoveredRequests(targetURL string, requests []DiscoveredRequest, enabled bool, apiRoots ...[]string) []Result {
	if !enabled || len(requests) == 0 {
		return nil
	}

	results := scanFastjsonDiscoveredEndpoints(requests)
	results = append(results, scanShiroDiscoveredEndpoints(targetURL, requests, flattenAPIRoots(apiRoots)...)...)
	return mergeFingerprintResults(results)
}

func (s *FingerScanner) scanDiscoveredRequestFingerprints(ctx context.Context, callback ResultCallback) {
	if s == nil || ctx.Err() != nil || len(s.aliveURLs) == 0 {
		return
	}
	for _, target := range s.aliveURLs {
		if ctx.Err() != nil || target == nil {
			return
		}
		results := ScanDiscoveredRequests(target.String(), s.discoveredRequestsForTarget(target), true)
		for _, result := range results {
			if ctx.Err() != nil {
				return
			}
			s.logScanResult(result.Detect, result)
			if callback != nil {
				callback(result)
			}
			s.mutex.Lock()
			if s.basicURLWithFingerprint == nil {
				s.basicURLWithFingerprint = make(map[string][]string)
			}
			s.basicURLWithFingerprint[result.URL] = append(s.basicURLWithFingerprint[result.URL], matchedFingerprintNames(result.Fingerprints)...)
			s.mutex.Unlock()
		}
	}
}

// SelectShiroCandidates returns only concrete, same-origin, non-root endpoint
// URLs. Shiro's rememberMe probe must not inherit a captured method, headers,
// body, or query values, and it must never create a root-path probe.
func SelectShiroCandidates(targetURL string, requests []DiscoveredRequest, apiRoots ...[]string) []string {
	target, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil
	}

	seen := make(map[string]struct{}, len(requests))
	roots := normalizeShiroAPIRoots(target, flattenAPIRoots(apiRoots))
	for _, request := range requests {
		candidate, err := url.Parse(strings.TrimSpace(request.URL))
		if err != nil {
			continue
		}
		if isStaticAssetPath(candidate.Path) {
			continue
		}
		if candidate.Scheme != "" && candidate.Host != "" {
			addShiroCandidate(target, candidate, seen)
		}

		for _, root := range roots {
			if joined := buildShiroAPIRootCandidate(root, candidate.Path); joined != nil {
				addShiroCandidate(target, joined, seen)
			}
		}
	}

	result := make([]string, 0, len(seen))
	for candidate := range seen {
		result = append(result, candidate)
	}
	sort.Strings(result)
	return result
}

func flattenAPIRoots(groups [][]string) []string {
	if len(groups) == 0 {
		return nil
	}
	var result []string
	for _, group := range groups {
		result = append(result, group...)
	}
	return result
}

func normalizeShiroAPIRoots(target *url.URL, apiRoots []string) []*url.URL {
	roots := make([]*url.URL, 0, len(apiRoots))
	seen := make(map[string]struct{}, len(apiRoots))
	for _, rawRoot := range apiRoots {
		root := strings.TrimSpace(rawRoot)
		if root == "" {
			continue
		}

		parsed, err := url.Parse(root)
		if err != nil {
			continue
		}
		if parsed.Scheme != "" || parsed.Host != "" {
			if parsed.Scheme == "" || parsed.Host == "" || !sameOrigin(target, parsed) {
				continue
			}
		} else {
			parsed = target.ResolveReference(parsed)
		}

		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		parsed.RawFragment = ""
		parsed.RawPath = ""
		if parsed.Path == "" {
			parsed.Path = "/"
		}
		key := parsed.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, parsed)
	}
	return roots
}

func buildShiroAPIRootCandidate(root *url.URL, requestPath string) *url.URL {
	if root == nil {
		return nil
	}
	path := strings.TrimSpace(requestPath)
	if path == "" || isRootPath(path) {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	rootPath := strings.TrimRight(root.Path, "/")
	if rootPath != "" && rootPath != "/" && path != rootPath && !strings.HasPrefix(path, rootPath+"/") {
		path = rootPath + "/" + strings.TrimLeft(path, "/")
	}

	candidate := *root
	candidate.Path = path
	candidate.RawPath = ""
	return &candidate
}

func addShiroCandidate(target, candidate *url.URL, seen map[string]struct{}) {
	if target == nil || candidate == nil || !sameOrigin(target, candidate) || isRootPath(candidate.Path) {
		return
	}

	candidateCopy := *candidate
	candidateCopy.RawQuery = ""
	candidateCopy.ForceQuery = false
	candidateCopy.Fragment = ""
	candidateCopy.RawFragment = ""
	candidateCopy.RawPath = ""
	seen[candidateCopy.String()] = struct{}{}
}

// SelectFastjsonCandidates keeps full captured JSON requests so payload-aware
// detection can de-duplicate by the fields that affect request semantics.
func SelectFastjsonCandidates(requests []DiscoveredRequest) []DiscoveredRequest {
	seen := make(map[string]struct{}, len(requests))
	result := make([]DiscoveredRequest, 0, len(requests))
	for _, request := range requests {
		if !isJSONRequest(request) {
			continue
		}
		fingerprint := DiscoveredRequestFingerprint(request)
		if fingerprint == "" {
			continue
		}
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		result = append(result, request)
	}
	return result
}

// DiscoveredRequestFingerprint is stable for the fields that affect a JSON
// request. It excludes volatile authentication headers.
func DiscoveredRequestFingerprint(request DiscoveredRequest) string {
	parsed, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		method = http.MethodGet
	}
	return strings.Join([]string{
		method,
		strings.ToLower(parsed.Scheme),
		strings.ToLower(parsed.Host),
		parsed.EscapedPath(),
		parsed.RawQuery,
		discoveredRequestContentType(request),
		strings.TrimSpace(request.Body),
	}, "\x00")
}

func scanShiroDiscoveredEndpoints(targetURL string, requests []DiscoveredRequest, apiRoots ...string) []Result {
	candidates := SelectShiroCandidates(targetURL, requests, apiRoots)
	findings := make([]Result, 0, len(candidates))
	for _, candidate := range candidates {
		response, err := clients.DoRequest(http.MethodGet, candidate, map[string]string{"Cookie": shiroRememberMeProbeCookie}, nil, 10, clients.NewRestyClient(nil, true))
		if err != nil || response == nil {
			continue
		}

		setCookies := response.Header().Values("Set-Cookie")
		if !hasShiroDeleteMeCookie(setCookies) {
			continue
		}

		body := response.Body()
		result := newFingerprintResult(candidate)
		result.StatusCode = response.StatusCode()
		result.Length = len(body)
		result.Title = clients.GetTitle(body)
		result.Detect = "DiscoveredRequestShiro"
		result.Fingerprints = []FingerprintMatch{{Name: "Shiro", HighRisk: true}}
		findings = append(findings, result)
	}
	return findings
}

func scanFastjsonDiscoveredEndpoints(requests []DiscoveredRequest) []Result {
	candidates := SelectFastjsonCandidates(requests)
	seen := make(map[string]struct{}, len(candidates))
	results := make([]Result, 0, len(candidates))
	for _, candidate := range candidates {
		if !hasJSONBody(candidate) {
			continue
		}
		requestURL := strings.TrimSpace(candidate.URL)
		if _, exists := seen[requestURL]; exists {
			continue
		}
		seen[requestURL] = struct{}{}

		result := newFingerprintResult(requestURL)
		result.StatusCode = candidate.ResponseCode
		result.Length = len(candidate.ResponseBody)
		result.Title = clients.GetTitle([]byte(candidate.ResponseBody))
		result.Detect = candidate.Source
		result.Fingerprints = []FingerprintMatch{{Name: "json-payload-required"}}

		response, err := clients.DoRequest(
			http.MethodPost,
			requestURL,
			map[string]string{"Content-Type": "application/json"},
			strings.NewReader(fastjsonProbeBody),
			10,
			clients.NewRestyClient(nil, true),
		)
		if err != nil || response == nil {
			results = append(results, result)
			continue
		}

		body := response.Body()
		if bytes.Contains(body, []byte("fastjson-version")) {
			result.StatusCode = response.StatusCode()
			result.Length = len(body)
			result.Title = clients.GetTitle(body)
			result.Detect = "DiscoveredRequestFastjson"
			result.Fingerprints = []FingerprintMatch{{Name: "Fastjson", HighRisk: true}}
		}

		results = append(results, result)
	}
	return results
}

func newFingerprintResult(rawURL string) Result {
	return Result{URL: rawURL}
}

func mergeFingerprintResults(items []Result) []Result {
	byURL := make(map[string]Result, len(items))
	for _, item := range items {
		if item.URL == "" || len(item.Fingerprints) == 0 {
			continue
		}
		current := byURL[item.URL]
		if current.URL == "" {
			current = item
		} else {
			mergeFingerprintResultDetails(&current, item)
			current.Fingerprints = append(current.Fingerprints, item.Fingerprints...)
		}
		current.Fingerprints = dedupeFingerprintMatches(current.Fingerprints)
		byURL[item.URL] = current
	}

	urls := make([]string, 0, len(byURL))
	for requestURL := range byURL {
		urls = append(urls, requestURL)
	}
	sort.Strings(urls)
	results := make([]Result, 0, len(urls))
	for _, requestURL := range urls {
		results = append(results, byURL[requestURL])
	}
	return results
}

func mergeFingerprintResultDetails(current *Result, incoming Result) {
	if current.StatusCode == 0 {
		current.StatusCode = incoming.StatusCode
	}
	if current.Length == 0 {
		current.Length = incoming.Length
	}
	if current.Title == "" {
		current.Title = incoming.Title
	}
	if current.Detect == "" {
		current.Detect = incoming.Detect
	}
}

func dedupeFingerprintMatches(matches []FingerprintMatch) []FingerprintMatch {
	seen := make(map[string]struct{}, len(matches))
	result := make([]FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		key := match.Name
		if match.Name == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, match)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func hasShiroDeleteMeCookie(values []string) bool {
	for _, value := range values {
		pair := strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
		keyValue := strings.SplitN(pair, "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(keyValue[0]), "rememberMe") && strings.EqualFold(strings.TrimSpace(keyValue[1]), "deleteMe") {
			return true
		}
	}
	return false
}

func isJSONRequest(request DiscoveredRequest) bool {
	contentType := discoveredRequestContentType(request)
	return strings.Contains(contentType, "application/json") || strings.HasSuffix(contentType, "+json")
}

func hasJSONBody(request DiscoveredRequest) bool {
	body := strings.TrimSpace(request.Body)
	return body != "" && json.Valid([]byte(body))
}

func discoveredRequestContentType(request DiscoveredRequest) string {
	if contentType := strings.ToLower(strings.TrimSpace(request.ContentType)); contentType != "" {
		return contentType
	}
	for key, value := range request.Headers {
		if strings.EqualFold(key, "Content-Type") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func isRootPath(path string) bool {
	return strings.TrimSpace(path) == "" || path == "/"
}
