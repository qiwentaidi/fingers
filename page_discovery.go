package fingers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/qiwentaidi/fingers/internal/logger"
)

const (
	maxDiscoveredPagesPerTarget = 12
	defaultPageDiscoveryWorkers = 5
)

const (
	discoveredLinkDetect     = "DiscoveredLink"
	renderedDOMDetect        = "RenderedDOM"
	apiResponseDetect        = "APIResponse"
	apiResponseContextDetect = "APIResponseContext"
	jsRouteDetect            = "JSRoute"
)

var (
	pageReferencePattern = regexp.MustCompile(`(?i)https?://[^\s"'<>\\]+|/(?:[a-z0-9][a-z0-9._~!$&'()*+,;=:@%/-]*)`)
	metaRefreshPattern   = regexp.MustCompile(`(?i)(?:^|;)\s*url\s*=\s*([^;]+)`)
)

type pageCandidate struct {
	URL    string
	Detect string
	Score  int
}

type pageDiscoveryTarget struct {
	URL        *url.URL
	Body       []byte
	HasContext bool
}

// discoverPageCandidates gathers only first-level pages exposed by the
// original target. It does not crawl candidate pages or interact with them.
func (s *FingerScanner) discoverPageCandidates(ctx context.Context) {
	if s == nil || ctx.Err() != nil || len(s.aliveURLs) == 0 {
		return
	}

	targets := s.pageDiscoveryTargets()
	if len(targets) == 0 {
		return
	}

	stage := "dynamic"
	if s.screenshotBrowser != nil {
		stage = "headless"
	}
	progress := newScanProgress(stage, len(targets), s.shouldPrintDefaultOutput())
	defer progress.Finish()

	workers := pageDiscoveryWorkerCount(len(targets))
	jobs := make(chan pageDiscoveryTarget)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for target := range jobs {
				s.discoverPageCandidateTarget(ctx, target, progress)
			}
		}()
	}

sendJobs:
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- target:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *FingerScanner) pageDiscoveryTargets() []pageDiscoveryTarget {
	seenOrigins := make(map[string]struct{})
	targets := make([]pageDiscoveryTarget, 0, len(s.aliveURLs))
	for _, target := range s.aliveURLs {
		if target == nil || !isHTTPURL(target.String()) {
			continue
		}
		origin := contextOriginKey(target)
		if _, seen := seenOrigins[origin]; seen {
			continue
		}
		seenOrigins[origin] = struct{}{}

		body, statusCode, hasContext := s.pageContext(target)
		if statusCode == http.StatusBadGateway || (hasContext && len(body) == 0) {
			continue
		}
		targets = append(targets, pageDiscoveryTarget{URL: target, Body: body, HasContext: hasContext})
	}
	return targets
}

func pageDiscoveryWorkerCount(total int) int {
	if total <= 0 {
		return 0
	}
	if total < defaultPageDiscoveryWorkers {
		return total
	}
	return defaultPageDiscoveryWorkers
}

func (s *FingerScanner) discoverPageCandidateTarget(ctx context.Context, target pageDiscoveryTarget, progress *scanProgress) {
	defer progress.Processed()
	if ctx.Err() != nil || target.URL == nil {
		progress.Skipped()
		return
	}
	if len(target.Body) > 0 {
		// Static JS context evidence and page routes complement browser
		// evidence; neither source suppresses the other.
		s.discoverJSContextPaths(ctx, target.URL, target.Body)
		for _, raw := range extractHTMLPageReferences(target.Body) {
			s.storePageCandidate(target.URL, raw, discoveredLinkDetect)
		}
		for _, raw := range s.extractJSPageReferences(ctx, target.URL, target.Body) {
			s.storePageCandidate(target.URL, raw, jsRouteDetect)
		}
	}

	if s.screenshotBrowser == nil {
		if len(target.Body) > 0 {
			progress.Matched()
		} else {
			progress.Skipped()
		}
		return
	}
	progress.Requested()
	capture, err := s.screenshotBrowser.CapturePageLoad(ctx, target.URL.String())
	if err != nil && s.shouldPrintDefaultOutput() {
		logger.Default.Debug("[headless] capture page candidates for %s partially failed: %v", target.URL, err)
	}
	if err != nil {
		progress.Failed()
	} else {
		progress.Matched()
	}
	s.storeDiscoveredRequests(target.URL, capture.APIRequests)
	dynamicPaths := make([]string, 0, len(capture.RequestURLs))
	for _, raw := range capture.RequestURLs {
		requestURL, parseErr := url.Parse(raw)
		if parseErr != nil || !sameContextURL(target.URL, requestURL) {
			continue
		}
		dynamicPaths = append(dynamicPaths, requestURL.Path)
	}
	s.storeJSContextPaths(target.URL, deriveAPIContextPaths(dynamicPaths))
	for _, raw := range capture.DOMURLs {
		s.storePageCandidate(target.URL, raw, renderedDOMDetect)
	}
	for _, response := range capture.APIResponses {
		responseURL, parseErr := url.Parse(response.URL)
		if parseErr != nil || !sameContextURL(target.URL, responseURL) {
			continue
		}
		for _, raw := range extractJSONPageReferences(response.Body) {
			// A root-relative route in an API response belongs to the document
			// origin, not necessarily the API subdomain that returned it.
			s.storePageCandidate(target.URL, raw, apiResponseDetect)
			for _, contextPath := range derivePageContextReferences(target.URL, raw) {
				s.storePageCandidate(target.URL, contextPath, apiResponseContextDetect)
			}
		}
	}
}

func extractHTMLPageReferences(body []byte) []string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	refs := make([]string, 0)
	doc.Find("a[href],area[href],iframe[src],frame[src],link[rel='canonical'][href]").Each(func(_ int, selection *goquery.Selection) {
		if value, ok := selection.Attr("href"); ok {
			refs = append(refs, value)
			return
		}
		if value, ok := selection.Attr("src"); ok {
			refs = append(refs, value)
		}
	})
	doc.Find("meta[http-equiv]").Each(func(_ int, selection *goquery.Selection) {
		httpEquiv, _ := selection.Attr("http-equiv")
		content, _ := selection.Attr("content")
		if !strings.EqualFold(strings.TrimSpace(httpEquiv), "refresh") {
			return
		}
		if match := metaRefreshPattern.FindStringSubmatch(content); len(match) > 1 {
			refs = append(refs, strings.Trim(strings.TrimSpace(match[1]), "\"'"))
		}
	})
	return refs
}

func (s *FingerScanner) extractJSPageReferences(ctx context.Context, pageURL *url.URL, htmlBody []byte) []string {
	jsURLs, inlineScripts := extractPageJSSources(pageURL, htmlBody)
	refs := make([]string, 0)
	for _, script := range inlineScripts {
		refs = append(refs, extractJSContextEvidence(pageURL, []byte(script)).routes...)
	}
	for _, jsURL := range jsURLs {
		if ctx.Err() != nil {
			return refs
		}
		refs = append(refs, s.loadJSContextEvidence(ctx, pageURL, jsURL).routes...)
	}
	return refs
}

func extractJSONPageReferences(body []byte) []string {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil
	}
	refs := make([]string, 0)
	var visit func(any)
	visit = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			for _, child := range item {
				visit(child)
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		case string:
			refs = append(refs, pageReferencePattern.FindAllString(item, -1)...)
		}
	}
	visit(value)
	return refs
}

func (s *FingerScanner) storePageCandidate(target *url.URL, raw string, detect string) {
	candidateURL, score := normalizePageCandidateURL(target, raw)
	if candidateURL == "" {
		return
	}
	score += pageCandidateSourceScore(detect)
	// An author-written same-origin absolute link is an especially strong
	// signal for a deliberately exposed subsystem (for example /ipisc/).
	// Browser DOM properties normalize every relative href to absolute, so the
	// bonus is intentionally limited to the original static HTML source.
	if detect == discoveredLinkDetect && score > pageCandidateSourceScore(detect) {
		score += 100
	}

	key := contextOriginKey(target)
	s.pageDiscoveryMutex.Lock()
	defer s.pageDiscoveryMutex.Unlock()
	if s.discoveredPageCandidates == nil {
		s.discoveredPageCandidates = make(map[string]map[string]pageCandidate)
	}
	if s.discoveredPageCandidates[key] == nil {
		s.discoveredPageCandidates[key] = make(map[string]pageCandidate)
	}
	if current, exists := s.discoveredPageCandidates[key][candidateURL]; exists {
		if current.Detect == detect {
			current.Score++
			s.discoveredPageCandidates[key][candidateURL] = current
			return
		}
		if current.Score >= score {
			return
		}
	}
	s.discoveredPageCandidates[key][candidateURL] = pageCandidate{URL: candidateURL, Detect: detect, Score: score}
}

// derivePageContextReferences turns a concrete page returned by an API into
// its two-segment site context. For example, /ysz/zx/tj/8382.shtml contributes
// /ysz/zx, which can carry a distinct CMS fingerprint from the article page.
func derivePageContextReferences(target *url.URL, raw string) []string {
	candidateURL, _ := normalizePageCandidateURL(target, raw)
	if candidateURL == "" {
		return nil
	}
	parsed, err := url.Parse(candidateURL)
	if err != nil {
		return nil
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 3 {
		return nil
	}
	return []string{"/" + strings.Join(segments[:2], "/") + "/"}
}

func normalizePageCandidateURL(target *url.URL, raw string) (string, int) {
	if target == nil {
		return "", 0
	}
	raw = strings.TrimSpace(strings.Trim(raw, "\"'`"))
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") {
		return "", 0
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return "", 0
	}
	resolved := target.ResolveReference(reference)
	if !sameOriginURL(target, resolved) {
		return "", 0
	}
	resolved.RawQuery = ""
	resolved.ForceQuery = false
	resolved.Fragment = ""
	resolved.RawFragment = ""
	hadTrailingSlash := strings.HasSuffix(resolved.Path, "/")
	resolved.Path = path.Clean(resolved.Path)
	if resolved.Path == "." || resolved.Path == "/" || !isDiscoverablePagePath(resolved.Path) {
		return "", 0
	}
	if hadTrailingSlash {
		resolved.Path += "/"
	}
	resolved.RawPath = ""
	score := 0
	if reference.IsAbs() {
		score += 20
	}
	return resolved.String(), score
}

func isDiscoverablePagePath(candidatePath string) bool {
	low := strings.ToLower(candidatePath)
	for _, unsafePart := range []string{"/logout", "/signout", "/delete", "/remove", "/destroy", "/reset"} {
		if strings.Contains(low, unsafePart) {
			return false
		}
	}
	for _, prefix := range []string{"/api/", "/jsonapi/", "/rest/", "/service/", "/graphql"} {
		if strings.HasPrefix(low, prefix) {
			return false
		}
	}
	switch strings.ToLower(path.Ext(low)) {
	case "", ".action", ".asp", ".aspx", ".do", ".htm", ".html", ".jsp", ".php", ".shtml":
		return true
	default:
		return false
	}
}

func pageCandidateSourceScore(detect string) int {
	switch detect {
	case apiResponseDetect:
		return 100
	case apiResponseContextDetect:
		return 120
	case renderedDOMDetect:
		return 80
	case discoveredLinkDetect:
		return 60
	case jsRouteDetect:
		return 40
	default:
		return 0
	}
}

func (s *FingerScanner) discoveredPagesForTarget(target *url.URL) []pageCandidate {
	if s == nil || target == nil {
		return nil
	}
	s.pageDiscoveryMutex.Lock()
	candidates := make([]pageCandidate, 0, len(s.discoveredPageCandidates[contextOriginKey(target)]))
	for _, candidate := range s.discoveredPageCandidates[contextOriginKey(target)] {
		candidates = append(candidates, candidate)
	}
	s.pageDiscoveryMutex.Unlock()
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].URL < candidates[j].URL
	})
	if len(candidates) > maxDiscoveredPagesPerTarget {
		candidates = candidates[:maxDiscoveredPagesPerTarget]
	}
	return candidates
}

// scanDiscoveredPages passively fingerprints only the first-level pages found
// during initial target loading. They are not added to aliveURLs and therefore
// cannot trigger a second round of active probes or recursive discovery.
func (s *FingerScanner) scanDiscoveredPages(ctx context.Context, callback ResultCallback) {
	if s == nil || ctx.Err() != nil {
		return
	}
	seen := make(map[string]struct{})
	targets := make([]passiveScanTarget, 0)
	for _, target := range s.aliveURLs {
		knownFingerprints := s.knownFingerprintsForActiveTarget(target, target)
		for _, candidate := range s.discoveredPagesForTarget(target) {
			if _, exists := seen[candidate.URL]; exists {
				continue
			}
			parsed, err := url.Parse(candidate.URL)
			if err != nil {
				continue
			}
			seen[candidate.URL] = struct{}{}
			targets = append(targets, passiveScanTarget{
				URL:               parsed,
				Detect:            candidate.Detect,
				KnownFingerprints: knownFingerprints,
			})
		}
	}
	if len(targets) > 0 {
		threads := s.thread
		if threads > 4 {
			threads = 4
		}
		s.fingerScanTargets(ctx, callback, targets, threads, "discovered-page")
	}
}
