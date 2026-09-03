package fingers

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/publicsuffix"
)

const (
	contextActiveDetectName   = "ActiveContext"
	maxJSContextResourceBytes = 2 * 1024 * 1024
	maxJSContextPaths         = 4
	maxJSFingerprintResources = 12
	maxJSFingerprintBytes     = 8 * 1024 * 1024
	maxJSFingerprintFileBytes = 6 * 1024 * 1024
)

var (
	jsRoutePattern           = regexp.MustCompile(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[?|#][^"|']{0,}|)))(?:"|')`)
	jsBaseURLPattern         = regexp.MustCompile(`(?i)\bbaseURL\s*[:=]\s*["'\x60]([^"'\x60]{1,256})["'\x60]`)
	apiContextSegmentPattern = regexp.MustCompile(`(?i)^(?:api|[a-z0-9]+[-_]?api|api[-_a-z0-9]+|rest|service|backend|graphql)$`)
	versionSegmentPattern    = regexp.MustCompile(`(?i)^v?\d+$`)
)

var ignoredJSContextSegments = map[string]struct{}{
	"asset": {}, "assets": {}, "build": {}, "chunk": {}, "chunks": {},
	"component": {}, "components": {}, "css": {}, "dist": {}, "font": {},
	"fonts": {}, "image": {}, "images": {}, "img": {}, "js": {}, "node_modules": {},
	"page": {}, "pages": {}, "public": {}, "route": {}, "router": {}, "routes": {},
	"src": {}, "static": {}, "style": {}, "styles": {}, "view": {}, "views": {},
}

var ignoredJSContextExtensions = []string{
	".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".less", ".map",
	".png", ".scss", ".svg", ".ts", ".tsx", ".ttf", ".vue", ".webp", ".woff", ".woff2",
}

type jsContextEvidence struct {
	routes        []string
	explicitBases []string
}

type jsContextCacheEntry struct {
	ready    chan struct{}
	evidence jsContextEvidence
}

type jsBodyCacheEntry struct {
	ready chan struct{}
	body  []byte
}

type jsContextCandidateStats struct {
	path       string
	explicit   int
	apiHits    int
	commonHits int
}

const maxJSContextFetchWorkers = 4

// loadJSContextEvidenceBatch downloads external JS evidence with bounded
// parallelism while preserving jsURLs order in the returned slice. Shared
// cache entries make repeat callers (route extraction after context
// discovery) effectively free.
func (s *FingerScanner) loadJSContextEvidenceBatch(ctx context.Context, pageURL *url.URL, jsURLs []string) []jsContextEvidence {
	evidence := make([]jsContextEvidence, len(jsURLs))
	if len(jsURLs) == 0 || ctx.Err() != nil {
		return evidence
	}
	workers := len(jsURLs)
	if workers > maxJSContextFetchWorkers {
		workers = maxJSContextFetchWorkers
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for index, jsURL := range jsURLs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(index int, jsURL string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			evidence[index] = s.loadJSContextEvidence(ctx, pageURL, jsURL)
		}(index, jsURL)
	}
	wg.Wait()
	return evidence
}

func (s *FingerScanner) discoverJSContextPaths(ctx context.Context, pageURL *url.URL, htmlBody []byte) {
	if s == nil || pageURL == nil || ctx.Err() != nil {
		return
	}

	jsURLs, inlineScripts := extractPageJSSources(pageURL, htmlBody)
	evidence := make([]jsContextEvidence, 0, len(jsURLs)+len(inlineScripts))
	for _, script := range inlineScripts {
		evidence = append(evidence, extractJSContextEvidence(pageURL, []byte(script)))
	}
	evidence = append(evidence, s.loadJSContextEvidenceBatch(ctx, pageURL, jsURLs)...)

	s.storeJSContextPaths(pageURL, deriveJSContextPaths(evidence))
}

func extractPageJSSources(pageURL *url.URL, htmlBody []byte) ([]string, []string) {
	if pageURL == nil || len(htmlBody) == 0 {
		return nil, nil
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(htmlBody))
	if err != nil {
		return nil, nil
	}

	seen := make(map[string]struct{})
	jsURLs := make([]string, 0)
	inlineScripts := make([]string, 0)
	doc.Find("script").Each(func(_ int, selection *goquery.Selection) {
		if src, ok := selection.Attr("src"); ok {
			resolved, resolveErr := pageURL.Parse(strings.TrimSpace(src))
			if resolveErr != nil || !sameOriginURL(pageURL, resolved) {
				return
			}
			resolved.Fragment = ""
			key := resolved.String()
			if _, exists := seen[key]; exists {
				return
			}
			seen[key] = struct{}{}
			jsURLs = append(jsURLs, key)
			return
		}
		if script := strings.TrimSpace(selection.Text()); script != "" {
			inlineScripts = append(inlineScripts, script)
		}
	})
	return jsURLs, inlineScripts
}

func (s *FingerScanner) collectPageJSFingerprintBody(ctx context.Context, pageURL *url.URL, htmlBody []byte) []byte {
	if s == nil || pageURL == nil || len(htmlBody) == 0 || ctx.Err() != nil {
		return nil
	}

	jsURLs, inlineScripts := extractPageJSSources(pageURL, htmlBody)
	if len(jsURLs) == 0 && len(inlineScripts) == 0 {
		return nil
	}

	var combined []byte
	appendContent := func(content []byte) bool {
		content = bytes.TrimSpace(content)
		if len(content) == 0 || len(combined) >= maxJSFingerprintBytes {
			return len(combined) < maxJSFingerprintBytes
		}
		separatorBytes := 0
		if len(combined) > 0 {
			separatorBytes = 1
		}
		remaining := maxJSFingerprintBytes - len(combined) - separatorBytes
		if remaining <= 0 {
			return false
		}
		if len(content) > remaining {
			content = content[:remaining]
		}
		if separatorBytes > 0 {
			combined = append(combined, '\n')
		}
		combined = append(combined, content...)
		return len(combined) < maxJSFingerprintBytes
	}

	for _, script := range inlineScripts {
		if !appendContent([]byte(script)) {
			return combined
		}
	}
	for index, jsURL := range jsURLs {
		if ctx.Err() != nil || index >= maxJSFingerprintResources {
			break
		}
		if !appendContent(s.loadJSFingerprintBody(ctx, jsURL)) {
			break
		}
	}
	return combined
}

func (s *FingerScanner) loadJSFingerprintBody(ctx context.Context, jsURL string) []byte {
	s.jsContextMutex.Lock()
	if s.jsBodyCache == nil {
		s.jsBodyCache = make(map[string]*jsBodyCacheEntry)
	}
	if cached, ok := s.jsBodyCache[jsURL]; ok {
		s.jsContextMutex.Unlock()
		select {
		case <-cached.ready:
			return append([]byte(nil), cached.body...)
		case <-ctx.Done():
			return nil
		}
	}
	entry := &jsBodyCacheEntry{ready: make(chan struct{})}
	s.jsBodyCache[jsURL] = entry
	s.jsContextMutex.Unlock()

	body := s.fetchJSFingerprintBody(ctx, jsURL)
	s.jsContextMutex.Lock()
	entry.body = append([]byte(nil), body...)
	close(entry.ready)
	s.jsContextMutex.Unlock()
	return body
}

func (s *FingerScanner) fetchJSFingerprintBody(ctx context.Context, jsURL string) []byte {
	if s.client == nil {
		return nil
	}
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeaders(s.headers).
		SetDoNotParseResponse(true).
		Get(jsURL)
	if err != nil || resp == nil || resp.RawResponse == nil || resp.RawResponse.Body == nil {
		return nil
	}
	defer resp.RawResponse.Body.Close()
	if resp.StatusCode() < 200 || resp.StatusCode() >= 400 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.RawResponse.Body, maxJSFingerprintFileBytes+1))
	if err != nil || len(body) > maxJSFingerprintFileBytes {
		return nil
	}
	return body
}

func (s *FingerScanner) loadJSContextEvidence(ctx context.Context, pageURL *url.URL, jsURL string) jsContextEvidence {
	s.jsContextMutex.Lock()
	if s.jsContextCache == nil {
		s.jsContextCache = make(map[string]*jsContextCacheEntry)
	}
	if cached, ok := s.jsContextCache[jsURL]; ok {
		s.jsContextMutex.Unlock()
		select {
		case <-cached.ready:
			return cached.evidence
		case <-ctx.Done():
			return jsContextEvidence{}
		}
	}
	entry := &jsContextCacheEntry{ready: make(chan struct{})}
	s.jsContextCache[jsURL] = entry
	s.jsContextMutex.Unlock()

	evidence := s.fetchJSContextEvidence(ctx, pageURL, jsURL)
	s.jsContextMutex.Lock()
	entry.evidence = evidence
	close(entry.ready)
	s.jsContextMutex.Unlock()
	return evidence
}

func (s *FingerScanner) fetchJSContextEvidence(ctx context.Context, pageURL *url.URL, jsURL string) jsContextEvidence {
	if s.client == nil {
		return jsContextEvidence{}
	}
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeaders(s.headers).
		SetDoNotParseResponse(true).
		Get(jsURL)
	if err != nil || resp == nil || resp.RawResponse == nil || resp.RawResponse.Body == nil {
		return jsContextEvidence{}
	}
	defer resp.RawResponse.Body.Close()
	if resp.StatusCode() < 200 || resp.StatusCode() >= 400 {
		return jsContextEvidence{}
	}

	body, err := io.ReadAll(io.LimitReader(resp.RawResponse.Body, maxJSContextResourceBytes+1))
	if err != nil || len(body) > maxJSContextResourceBytes {
		return jsContextEvidence{}
	}
	return extractJSContextEvidence(pageURL, body)
}

func extractJSContextEvidence(pageURL *url.URL, content []byte) jsContextEvidence {
	evidence := jsContextEvidence{}
	for _, match := range jsRoutePattern.FindAll(content, -1) {
		if route := normalizeJSRoutePath(pageURL, string(match), false); route != "" {
			evidence.routes = append(evidence.routes, route)
		}
	}
	for _, match := range jsBaseURLPattern.FindAllSubmatch(content, -1) {
		if len(match) < 2 {
			continue
		}
		if base := normalizeJSRoutePath(pageURL, string(match[1]), true); base != "" {
			evidence.explicitBases = append(evidence.explicitBases, base)
		}
	}
	return evidence
}

func normalizeJSRoutePath(pageURL *url.URL, raw string, allowBare bool) string {
	if pageURL == nil {
		return ""
	}
	raw = strings.TrimSpace(strings.Trim(raw, "\"'`"))
	raw = strings.ReplaceAll(raw, `\/`, "/")
	if raw == "" || raw == "/" || strings.Contains(raw, "${") || strings.Contains(raw, "{{") {
		return ""
	}
	if strings.HasPrefix(raw, "//") {
		raw = pageURL.Scheme + ":" + raw
	}

	reference, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if !reference.IsAbs() && !strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "./") && !strings.HasPrefix(raw, "../") {
		if !allowBare {
			return ""
		}
		reference, err = url.Parse("./" + raw)
		if err != nil {
			return ""
		}
	}
	resolved := pageURL.ResolveReference(reference)
	if !sameOriginURL(pageURL, resolved) {
		return ""
	}
	normalized := path.Clean(resolved.Path)
	if normalized == "." || normalized == "/" || !strings.HasPrefix(normalized, "/") {
		return ""
	}
	low := strings.ToLower(normalized)
	for _, extension := range ignoredJSContextExtensions {
		if strings.HasSuffix(low, extension) {
			return ""
		}
	}
	return strings.TrimRight(normalized, "/")
}

func deriveJSContextPaths(evidence []jsContextEvidence) []string {
	stats := make(map[string]*jsContextCandidateStats)
	statFor := func(candidate string) *jsContextCandidateStats {
		candidate = normalizeContextPath(candidate)
		if candidate == "" {
			return nil
		}
		if current, ok := stats[candidate]; ok {
			return current
		}
		current := &jsContextCandidateStats{path: candidate}
		stats[candidate] = current
		return current
	}

	seenRoutes := make(map[string]struct{})
	for _, item := range evidence {
		for _, base := range item.explicitBases {
			if current := statFor(base); current != nil {
				current.explicit++
			}
		}
		for _, route := range item.routes {
			route = normalizeContextPath(route)
			if route == "" {
				continue
			}
			if _, ok := seenRoutes[route]; ok {
				continue
			}
			seenRoutes[route] = struct{}{}
			segments := splitContextPath(route)
			if len(segments) < 2 || isIgnoredJSContextSegment(segments[0]) {
				continue
			}
			if current := statFor("/" + segments[0]); current != nil {
				current.commonHits++
			}
			for index, segment := range segments {
				if !apiContextSegmentPattern.MatchString(segment) {
					continue
				}
				for _, candidate := range apiContextRootCandidates(segments, index) {
					if current := statFor(candidate); current != nil {
						current.apiHits++
					}
				}
				break
			}
		}
	}

	candidates := make([]*jsContextCandidateStats, 0, len(stats))
	for _, current := range stats {
		if current.explicit == 0 && current.apiHits == 0 && current.commonHits < 2 {
			continue
		}
		candidates = append(candidates, current)
	}
	sort.Slice(candidates, func(i, j int) bool {
		leftScore := candidates[i].explicit*100 + candidates[i].apiHits*10 + candidates[i].commonHits
		rightScore := candidates[j].explicit*100 + candidates[j].apiHits*10 + candidates[j].commonHits
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		leftDepth := len(splitContextPath(candidates[i].path))
		rightDepth := len(splitContextPath(candidates[j].path))
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return candidates[i].path < candidates[j].path
	})

	limit := len(candidates)
	if limit > maxJSContextPaths {
		limit = maxJSContextPaths
	}
	result := make([]string, 0, limit)
	for _, candidate := range candidates[:limit] {
		result = append(result, candidate.path)
	}
	return result
}

// deriveAPIContextPaths mirrors trailblazer's Filter.APIRoots semantics. It
// intentionally returns API roots only; callers decide whether those roots
// are eligible for context-enabled active fingerprint probes.
func deriveAPIContextPaths(rawPaths []string) []string {
	blacklist := []string{"proxy", "jsonp", "callback", "tk", "map", "military", "static", "resource", "google", "baidu"}
	allowSimple := regexp.MustCompile(`(?i)^/(?:api|v\d+|rest|service|backend|graphql)/?$`)
	segmentAPI := regexp.MustCompile(`(?i)^(?:api|[a-z0-9]+[-_]?api|api[-_a-z0-9]+)$`)
	seen := make(map[string]struct{})
	roots := make([]string, 0)
	appendRoot := func(value string) {
		value = normalizeContextPath(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		roots = append(roots, value)
	}

	for _, raw := range rawPaths {
		p := normalizeContextPath(raw)
		if p == "" || len(p) < 3 || len(p) > 120 || strings.Contains(p, "?") {
			continue
		}
		low := strings.ToLower(p)
		skip := false
		for _, keyword := range blacklist {
			if strings.Contains(low, keyword) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if allowSimple.MatchString(p) {
			appendRoot(p)
			continue
		}

		segments := splitContextPath(p)
		for index, segment := range segments {
			if !segmentAPI.MatchString(segment) {
				continue
			}
			for _, candidate := range apiContextRootCandidates(segments, index) {
				appendRoot(candidate)
			}
			break
		}
	}

	sort.Strings(roots)
	return roots
}

// apiContextRootCandidates returns every deployable context prefix that leads
// to a recognized API segment. For example, /gateway/api/v1/users yields
// /gateway, /gateway/api, and /gateway/api/v1 so active rules can be probed
// beneath reverse-proxy contexts as well as the API root itself.
func apiContextRootCandidates(segments []string, apiIndex int) []string {
	if apiIndex < 0 || apiIndex >= len(segments) {
		return nil
	}

	last := apiIndex + 1
	if last < len(segments) && versionSegmentPattern.MatchString(segments[last]) {
		last++
	}

	candidates := make([]string, 0, last)
	for end := 1; end <= last; end++ {
		candidates = append(candidates, "/"+strings.Join(segments[:end], "/"))
	}
	return candidates
}

func (s *FingerScanner) storeJSContextPaths(target *url.URL, candidates []string) {
	if target == nil || len(candidates) == 0 {
		return
	}
	key := contextOriginKey(target)
	s.jsContextMutex.Lock()
	defer s.jsContextMutex.Unlock()
	if s.jsContextPaths == nil {
		s.jsContextPaths = make(map[string][]string)
	}
	capacity := len(s.jsContextPaths[key]) + len(candidates)
	seen := make(map[string]struct{}, capacity)
	merged := make([]string, 0, capacity)
	for _, candidate := range append(append([]string(nil), s.jsContextPaths[key]...), candidates...) {
		candidate = normalizeContextPath(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		merged = append(merged, candidate)
		if len(merged) == maxJSContextPaths {
			break
		}
	}
	s.jsContextPaths[key] = merged
}

func (s *FingerScanner) contextPathsForTarget(target *url.URL) []string {
	if s == nil || target == nil {
		return nil
	}
	s.jsContextMutex.Lock()
	defer s.jsContextMutex.Unlock()
	return append([]string(nil), s.jsContextPaths[contextOriginKey(target)]...)
}

func buildContextBaseURL(target *url.URL, contextPath string) *url.URL {
	if target == nil {
		return nil
	}
	contextPath = normalizeContextPath(contextPath)
	if contextPath == "" {
		return nil
	}
	return &url.URL{Scheme: target.Scheme, Host: target.Host, Path: contextPath}
}

func normalizeContextPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	normalized := path.Clean(raw)
	if normalized == "." || normalized == "/" {
		return ""
	}
	return strings.TrimRight(normalized, "/")
}

func splitContextPath(raw string) []string {
	if raw = normalizeContextPath(raw); raw == "" {
		return nil
	}
	return strings.Split(strings.Trim(raw, "/"), "/")
}

func isIgnoredJSContextSegment(segment string) bool {
	_, ignored := ignoredJSContextSegments[strings.ToLower(strings.TrimSpace(segment))]
	return ignored
}

func sameOriginURL(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

// sameContextURL accepts the hosts that belong to the page's site boundary.
// API calls commonly use a sibling subdomain (for example api.example.com),
// while literal-IP targets have no registrable domain and must match exactly.
// Scheme and port are intentionally ignored here: the browser has already
// shown that the URL was requested while loading this target page.
func sameContextURL(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	leftHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(left.Hostname())), ".")
	rightHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(right.Hostname())), ".")
	if leftHost == "" || rightHost == "" {
		return false
	}
	leftIP := net.ParseIP(leftHost)
	rightIP := net.ParseIP(rightHost)
	if leftIP != nil || rightIP != nil {
		return leftIP != nil && rightIP != nil && leftIP.Equal(rightIP)
	}
	if leftHost == rightHost {
		return true
	}
	leftRoot, leftErr := publicsuffix.EffectiveTLDPlusOne(leftHost)
	rightRoot, rightErr := publicsuffix.EffectiveTLDPlusOne(rightHost)
	return leftErr == nil && rightErr == nil && strings.EqualFold(leftRoot, rightRoot)
}

func contextOriginKey(target *url.URL) string {
	if target == nil {
		return ""
	}
	return strings.ToLower(target.Scheme) + "://" + strings.ToLower(target.Host)
}
