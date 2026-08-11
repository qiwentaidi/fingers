package fingers

import (
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/qiwentaidi/clients"
	"github.com/qiwentaidi/fingers/internal/logger"
	httputil "github.com/qiwentaidi/utils/http"

	"github.com/panjf2000/ants/v2"
)

const (
	hostTokenPathProbeTimeout = 5
	hostTokenPathDetectName   = "HostTokenPath"
	hostTokenActivePathName   = "HostTokenActivePath"
)

var ignoredHostTokenPathTokens = map[string]struct{}{
	"localhost": {},
	"www":       {},
	"www1":      {},
	"www2":      {},
}

var publicSuffixHostTokens = map[string]struct{}{
	"ac":        {},
	"biz":       {},
	"cn":        {},
	"co":        {},
	"com":       {},
	"dev":       {},
	"dns":       {},
	"edu":       {},
	"ftp":       {},
	"gov":       {},
	"hk":        {},
	"imap":      {},
	"info":      {},
	"int":       {},
	"io":        {},
	"jp":        {},
	"localhost": {},
	"mil":       {},
	"name":      {},
	"net":       {},
	"online":    {},
	"org":       {},
	"site":      {},
	"test":      {},
	"top":       {},
	"tw":        {},
	"uk":        {},
	"us":        {},
	"xyz":       {},
}

type hostTokenPathProbeTask struct {
	base              *url.URL
	path              string
	knownFingerprints []string
}

type hostTokenActivePathProbeTask struct {
	base              *url.URL
	path              string
	fingers           []FingerEntity
	knownFingerprints []string
}

type hostTokenPathProbeResult struct {
	task          hostTokenPathProbeTask
	probed        bool
	reachable     bool
	entryStatus   int
	finalStatus   int
	candidateURL  *url.URL
	finalURL      *url.URL
	body          []byte
	contentLength int
	server        string
	contentType   string
	headers       []byte
	rawResponse   string
	fingerprint   hostTokenResponseFingerprint
}

// hostTokenResponseFingerprint is deliberately small and comparable. It is
// used only to recognize the same response template within a single scan, not
// as a security primitive.
type hostTokenResponseFingerprint struct {
	contentType string
	bodyLength  int
	bodyMD5     [md5.Size]byte
}

func deriveHostTokenPaths(u *url.URL) []string {
	if u == nil {
		return nil
	}
	tokens := deriveHostTokens(u.Hostname())
	paths := make([]string, 0, len(tokens))
	for _, token := range tokens {
		paths = append(paths, "/"+token+"/")
	}
	return paths
}

func deriveHostTokens(hostname string) []string {
	hostname = strings.ToLower(strings.Trim(hostname, "[] "))
	if hostname == "" || net.ParseIP(hostname) != nil {
		return nil
	}

	seen := make(map[string]struct{})
	tokens := make([]string, 0)
	labels := strings.Split(hostname, ".")
	suffixStart := len(labels)
	for suffixStart > 0 {
		label := strings.Trim(labels[suffixStart-1], "-_ ")
		if _, ok := publicSuffixHostTokens[label]; !ok {
			break
		}
		suffixStart--
	}

	for idx, label := range labels {
		if idx >= suffixStart {
			continue
		}
		label = strings.Trim(label, "-_ ")
		if label == "" || strings.HasPrefix(label, "xn--") {
			continue
		}
		appendHostToken(&tokens, seen, label)
		for _, part := range strings.FieldsFunc(label, func(r rune) bool {
			return !isHostTokenAlphaNumeric(r)
		}) {
			appendHostToken(&tokens, seen, part)
		}
	}
	return tokens
}

func appendHostToken(tokens *[]string, seen map[string]struct{}, token string) {
	token = strings.ToLower(strings.Trim(token, "-_ "))
	if len(token) < 2 || len(token) > 64 {
		return
	}
	if _, ignored := ignoredHostTokenPathTokens[token]; ignored {
		return
	}
	if _, ok := seen[token]; ok {
		return
	}

	hasLetter := false
	for _, r := range token {
		if !isHostTokenPathChar(r) {
			return
		}
		if r >= 'a' && r <= 'z' {
			hasLetter = true
		}
	}
	if !hasLetter {
		return
	}

	seen[token] = struct{}{}
	*tokens = append(*tokens, token)
}

func isHostTokenPathChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

func isHostTokenAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func (s *FingerScanner) HostTokenPathProbe(ctx context.Context, callback ResultCallback) {
	if s == nil || len(s.aliveURLs) == 0 {
		return
	}

	pathTasks := s.hostTokenPathProbeTasks()
	if len(pathTasks) == 0 {
		return
	}
	baselines := s.hostTokenSoft404Baselines(ctx, pathTasks)
	prefixResults := s.probeHostTokenPaths(ctx, pathTasks)
	discovered := make([]*url.URL, 0)
	localFanoutTasks := make([]hostTokenPathProbeTask, 0)

	for _, probeResult := range prefixResults {
		if ctx.Err() != nil {
			break
		}

		// A successful derived root that is indistinguishable from a random
		// missing path is a SPA shell or reverse-proxy catch-all. Do not promote
		// it to aliveURLs and, crucially, do not fan out active path probes below
		// it.
		if s.isHostTokenSoft404(probeResult, baselines) {
			continue
		}

		if probeResult.probed && probeResult.reachable {
			if result, ok := s.hydrateHostTokenPathResult(ctx, probeResult); ok {
				// Reachable, non-catch-all roots are scanned by ActiveFingerScan after
				// this method returns. Scheduling them here as well used to issue the
				// same active-path requests twice.
				if parsed, err := url.Parse(result.URL); err == nil {
					discovered = append(discovered, parsed)
				}
				s.handleHostTokenPathResult(ctx, callback, result, probeResult.task.knownFingerprints)
				continue
			}
		}

		// Preserve the important existing behavior for hard 404s and uncertain
		// responses: a missing context root can still contain a real application
		// at a deeper fingerprint path.
		localFanoutTasks = append(localFanoutTasks, probeResult.task)
	}

	activeTasks := s.hostTokenActivePathProbeTasks(localFanoutTasks)
	s.probeHostTokenActivePaths(ctx, activeTasks, callback)

	if len(discovered) > 0 {
		s.aliveURLs = append(s.aliveURLs, discovered...)
	}
}

func (s *FingerScanner) probeHostTokenPaths(ctx context.Context, tasks []hostTokenPathProbeTask) []hostTokenPathProbeResult {
	if len(tasks) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	retChan := make(chan hostTokenPathProbeResult, len(tasks))
	progress := newScanProgress("host-token", len(tasks), s.shouldPrintDefaultOutput())
	defer progress.Finish()
	thread := s.thread
	if thread <= 0 {
		thread = 1
	}
	threadPool, err := ants.NewPoolWithFunc(thread, func(raw interface{}) {
		defer wg.Done()
		defer progress.Processed()
		task := raw.(hostTokenPathProbeTask)
		progress.Requested()
		result := s.probeHostTokenPathResponse(ctx, task)
		if !result.probed {
			progress.Failed()
		} else if result.reachable {
			progress.Matched()
		} else {
			progress.Skipped()
		}
		retChan <- result
	})
	if err != nil {
		return nil
	}
	defer threadPool.Release()

	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		if err := threadPool.Invoke(task); err != nil {
			progress.Skipped()
			progress.Processed()
			wg.Done()
		}
	}
	wg.Wait()
	close(retChan)

	results := make([]hostTokenPathProbeResult, 0, len(tasks))
	for result := range retChan {
		results = append(results, result)
	}
	return results
}

func (s *FingerScanner) probeHostTokenActivePaths(ctx context.Context, tasks []hostTokenActivePathProbeTask, callback ResultCallback) {
	if len(tasks) == 0 || ctx.Err() != nil {
		return
	}

	var wg sync.WaitGroup
	resultChan := make(chan struct {
		result Result
		known  []string
	}, len(tasks))
	progress := newScanProgress("host-token-active", len(tasks), s.shouldPrintDefaultOutput())
	defer progress.Finish()
	thread := s.thread
	if thread <= 0 {
		thread = 1
	}
	threadPool, err := ants.NewPoolWithFunc(thread, func(raw interface{}) {
		defer wg.Done()
		defer progress.Processed()
		task := raw.(hostTokenActivePathProbeTask)
		progress.Requested()
		if result, ok := s.probeHostTokenActivePath(ctx, task); ok {
			progress.Matched()
			resultChan <- struct {
				result Result
				known  []string
			}{result: result, known: task.knownFingerprints}
		} else {
			progress.Skipped()
		}
	})
	if err != nil {
		return
	}
	defer threadPool.Release()

	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		if err := threadPool.Invoke(task); err != nil {
			progress.Skipped()
			progress.Processed()
			wg.Done()
		}
	}
	wg.Wait()
	close(resultChan)
	for item := range resultChan {
		s.handleHostTokenPathResult(ctx, callback, item.result, item.known)
	}
}

func (s *FingerScanner) hostTokenPathProbeTasks() []hostTokenPathProbeTask {
	seen := make(map[string]struct{})
	tasks := make([]hostTokenPathProbeTask, 0)

	for _, target := range s.aliveURLs {
		if target == nil || (target.Scheme != "http" && target.Scheme != "https") {
			continue
		}

		base := &url.URL{
			Scheme: target.Scheme,
			Host:   target.Host,
		}
		knownFingerprints := s.knownFingerprintsForActiveTarget(target, nil)
		for _, path := range deriveHostTokenPaths(base) {
			if sameURLPath(target.Path, path) {
				continue
			}
			candidate := buildHostTokenPathURL(base, path)
			key := candidate.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tasks = append(tasks, hostTokenPathProbeTask{
				base:              base,
				path:              path,
				knownFingerprints: knownFingerprints,
			})
		}
	}

	return tasks
}

func (s *FingerScanner) hostTokenActivePathProbeTasks(prefixTasks []hostTokenPathProbeTask) []hostTokenActivePathProbeTask {
	activePathMap := groupActiveFingerprintsByPath(s.getActiveFingerprintDB())
	if len(prefixTasks) == 0 || len(activePathMap) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	tasks := make([]hostTokenActivePathProbeTask, 0)
	for _, prefixTask := range prefixTasks {
		base := buildHostTokenPathURL(prefixTask.base, prefixTask.path)
		for path, fingers := range activePathMap {
			if len(fingers) == 0 {
				continue
			}
			fullURL := buildActiveProbeURL(base, path)
			if _, ok := seen[fullURL]; ok {
				continue
			}
			seen[fullURL] = struct{}{}
			tasks = append(tasks, hostTokenActivePathProbeTask{
				base:              base,
				path:              path,
				fingers:           fingers,
				knownFingerprints: prefixTask.knownFingerprints,
			})
		}
	}

	return tasks
}

func sameURLPath(left string, right string) bool {
	return strings.Trim(strings.TrimSpace(left), "/") == strings.Trim(strings.TrimSpace(right), "/")
}

func buildHostTokenPathURL(base *url.URL, path string) *url.URL {
	next := *base
	next.Path = path
	next.RawPath = ""
	next.RawQuery = ""
	next.Fragment = ""
	return &next
}

func (s *FingerScanner) probeHostTokenActivePath(ctx context.Context, task hostTokenActivePathProbeTask) (Result, bool) {
	if task.base == nil || ctx.Err() != nil {
		return Result{}, false
	}

	fullURL := buildActiveProbeURL(task.base, task.path)
	resp, err := clients.DoRequest("GET", fullURL, s.headers, nil, hostTokenPathProbeTimeout, s.client)
	if err != nil || resp == nil || resp.StatusCode() == http.StatusNotFound {
		return Result{}, false
	}

	rawResponse := ""
	if s.enableRawResponse {
		rawResponse = dumpRawResponsePacket(resp)
	}
	if ctx.Err() != nil {
		return Result{}, false
	}

	body := httputil.LimitResponseBytes(resp.Body(), maxInfoReponseSize)
	title := clients.GetTitle(body)
	if exclude, _ := excludeInterference(resp.StatusCode(), title); exclude {
		return Result{}, false
	}

	server := resp.Header().Get("Server")
	contentType := resp.Header().Get("Content-Type")
	headers, _, _ := httputil.DumpResponseHeadersAndRaw(resp.RawResponse)
	iconResult := FaviconResult{}
	if isImagePath(fullURL) {
		iconResult = hashIconBytes(body)
	}
	web := &WebInfo{
		HeadeString:   strings.ToLower(string(headers)),
		ContentType:   strings.ToLower(contentType),
		BodyString:    strings.ToLower(string(body)),
		Path:          strings.ToLower(task.path),
		Title:         strings.ToLower(title),
		Server:        strings.ToLower(server),
		ContentLength: len(resp.Body()),
		Port:          httputil.GetPort(task.base),
		StatusCode:    resp.StatusCode(),
		IconHash:      iconResult.Mmh3Hash,
		IconMd5:       iconResult.Md5Hash,
	}

	fingerprints := Scan(web, task.fingers)
	fingerprints = filterInvalidHostTokenFingerprints(resp.StatusCode(), fingerprints)
	if len(fingerprints) == 0 {
		return Result{}, false
	}

	var screenshotPath string
	if s.screenshot && (task.base.Scheme == "https" || task.base.Scheme == "http") {
		if screenshotPath, err = s.captureScreenshot(ctx, fullURL); err != nil {
			if s.shouldReportScreenshotDiagnostics() {
				logger.Default.Warning("%s 截屏失败: %v", fullURL, err)
			}
		}
	}

	resultPath := task.path
	if parsed, parseErr := url.Parse(fullURL); parseErr == nil {
		resultPath = parsed.Path
	}
	return Result{
		URL:          fullURL,
		Scheme:       task.base.Scheme,
		Host:         task.base.Host,
		Port:         web.Port,
		StatusCode:   web.StatusCode,
		Length:       web.ContentLength,
		Title:        title,
		Server:       server,
		ContentType:  contentType,
		Path:         resultPath,
		Fingerprints: fingerprints,
		Detect:       hostTokenActivePathName,
		Screenshot:   screenshotPath,
		IconHash:     iconResult.Mmh3Hash,
		IconMd5:      iconResult.Md5Hash,
		RawResponse:  rawResponse,
	}, true
}

func (s *FingerScanner) probeHostTokenPathResponse(ctx context.Context, task hostTokenPathProbeTask) hostTokenPathProbeResult {
	result := hostTokenPathProbeResult{task: task}
	if task.base == nil || ctx.Err() != nil {
		return result
	}

	candidateURL := buildHostTokenPathURL(task.base, task.path)
	result.candidateURL = candidateURL
	candidate := candidateURL.String()
	entryResp, err := clients.DoRequest("GET", candidate, s.headers, nil, hostTokenPathProbeTimeout, s.notFollowClient)
	if err != nil || entryResp == nil {
		return result
	}

	result.probed = true
	result.entryStatus = entryResp.StatusCode()
	rawResponse := ""
	if s.enableRawResponse {
		rawResponse = dumpRawResponsePacket(entryResp)
	}

	finalResp := entryResp
	if entryResp.StatusCode() >= 300 && entryResp.StatusCode() < 400 {
		finalResp, err = clients.DoRequest("GET", candidate, s.headers, nil, hostTokenPathProbeTimeout, s.client)
		if err != nil || finalResp == nil {
			return result
		}
		if s.enableRawResponse {
			if finalRawResponse := dumpRawResponsePacket(finalResp); finalRawResponse != "" {
				if rawResponse != "" {
					rawResponse += "\n\n--- final response ---\n\n"
				}
				rawResponse += finalRawResponse
			}
		}
	}
	if ctx.Err() != nil {
		return result
	}

	result.finalStatus = finalResp.StatusCode()
	result.reachable = isHostTokenPathProbeStatus(result.finalStatus)
	result.finalURL = candidateURL
	if finalResp.RawResponse != nil && finalResp.RawResponse.Request != nil && finalResp.RawResponse.Request.URL != nil {
		result.finalURL = finalResp.RawResponse.Request.URL
	}

	responseBody := finalResp.Body()
	result.body = httputil.LimitResponseBytes(responseBody, maxInfoReponseSize)
	result.contentLength = len(responseBody)
	result.server = finalResp.Header().Get("Server")
	result.contentType = finalResp.Header().Get("Content-Type")
	result.headers, _, _ = httputil.DumpResponseHeadersAndRaw(finalResp.RawResponse)
	result.rawResponse = rawResponse
	result.fingerprint = newHostTokenResponseFingerprint(result.contentType, result.body, result.contentLength)
	return result
}

// probeHostTokenPath preserves the focused, fully-hydrated probe used by
// callers and tests. HostTokenPathProbe itself uses probeHostTokenPathResponse
// first so it can decide whether the path deserves the expensive work.
func (s *FingerScanner) probeHostTokenPath(ctx context.Context, base *url.URL, candidatePath string) (Result, bool) {
	return s.hydrateHostTokenPathResult(ctx, s.probeHostTokenPathResponse(ctx, hostTokenPathProbeTask{
		base: base,
		path: candidatePath,
	}))
}

func (s *FingerScanner) hydrateHostTokenPathResult(ctx context.Context, probe hostTokenPathProbeResult) (Result, bool) {
	if !probe.probed || !probe.reachable || probe.candidateURL == nil || probe.finalURL == nil || ctx.Err() != nil {
		return Result{}, false
	}

	title := clients.GetTitle(probe.body)
	if exclude, _ := excludeInterference(probe.finalStatus, title); exclude {
		return Result{}, false
	}
	faviconResult := getFaviconWithStorage(probe.finalURL, s.headers, s.client, s.faviconStore)
	web := &WebInfo{
		HeadeString:   strings.ToLower(string(probe.headers)),
		ContentType:   strings.ToLower(probe.contentType),
		BodyString:    strings.ToLower(string(probe.body)),
		Path:          strings.ToLower(probe.task.path),
		Title:         strings.ToLower(title),
		Server:        strings.ToLower(probe.server),
		ContentLength: probe.contentLength,
		Port:          httputil.GetPort(probe.candidateURL),
		StatusCode:    probe.entryStatus,
		IconHash:      faviconResult.Mmh3Hash,
		IconMd5:       faviconResult.Md5Hash,
	}

	fingerprints := Scan(web, s.getFingerprintDB())
	if checkHoneypotWithHeaders(web.HeadeString) {
		fingerprints = []FingerprintMatch{{Name: "疑似蜜罐"}}
	}

	var screenshotPath string
	if s.screenshot && (probe.candidateURL.Scheme == "https" || probe.candidateURL.Scheme == "http") {
		capturedPath, err := s.captureScreenshot(ctx, probe.candidateURL.String())
		if err != nil {
			if s.shouldReportScreenshotDiagnostics() {
				logger.Default.Warning("%s 截屏失败: %v", probe.candidateURL.String(), err)
			}
		} else {
			screenshotPath = capturedPath
		}
	}

	return Result{
		URL:          probe.candidateURL.String(),
		Scheme:       probe.candidateURL.Scheme,
		Host:         probe.candidateURL.Host,
		Port:         web.Port,
		StatusCode:   web.StatusCode,
		Length:       web.ContentLength,
		Title:        title,
		Server:       probe.server,
		ContentType:  probe.contentType,
		Path:         probe.task.path,
		Fingerprints: fingerprints,
		Detect:       hostTokenPathDetectName,
		Screenshot:   screenshotPath,
		Favicon:      faviconResult.FilePath,
		FaviconURL:   faviconResult.URL,
		IconHash:     faviconResult.Mmh3Hash,
		IconMd5:      faviconResult.Md5Hash,
		RawResponse:  probe.rawResponse,
	}, true
}

func newHostTokenResponseFingerprint(contentType string, body []byte, contentLength int) hostTokenResponseFingerprint {
	return hostTokenResponseFingerprint{
		contentType: strings.ToLower(strings.TrimSpace(contentType)),
		bodyLength:  contentLength,
		bodyMD5:     md5.Sum(body),
	}
}

func (s *FingerScanner) hostTokenSoft404Baselines(ctx context.Context, tasks []hostTokenPathProbeTask) map[string]hostTokenResponseFingerprint {
	baselines := make(map[string]hostTokenResponseFingerprint)
	for _, task := range tasks {
		if ctx.Err() != nil || task.base == nil {
			break
		}
		origin := hostTokenOriginKey(task.base)
		if _, exists := baselines[origin]; exists {
			continue
		}
		probeURL := buildHostTokenPathURL(task.base, hostTokenSoft404ProbePath())
		resp, err := clients.DoRequest("GET", probeURL.String(), s.headers, nil, hostTokenPathProbeTimeout, s.client)
		if err != nil || resp == nil || !isHostTokenPathProbeStatus(resp.StatusCode()) {
			continue
		}
		responseBody := resp.Body()
		body := httputil.LimitResponseBytes(responseBody, maxInfoReponseSize)
		// Empty success responses are too weak a signal to prune a candidate.
		if len(body) == 0 {
			continue
		}
		baselines[origin] = newHostTokenResponseFingerprint(resp.Header().Get("Content-Type"), body, len(responseBody))
	}
	return baselines
}

func (s *FingerScanner) isHostTokenSoft404(result hostTokenPathProbeResult, baselines map[string]hostTokenResponseFingerprint) bool {
	if !result.probed || !result.reachable || result.candidateURL == nil || len(result.body) == 0 {
		return false
	}
	baseline, exists := baselines[hostTokenOriginKey(result.candidateURL)]
	return exists && result.fingerprint == baseline
}

func hostTokenOriginKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func hostTokenSoft404ProbePath() string {
	bytes := make([]byte, 12)
	if _, err := cryptorand.Read(bytes); err == nil {
		return "/.fingers-soft404-probe-" + hex.EncodeToString(bytes) + "/"
	}
	return "/.fingers-soft404-probe/"
}

func (s *FingerScanner) handleHostTokenPathResult(ctx context.Context, callback ResultCallback, result Result, knownFingerprints []string) {
	if ctx.Err() != nil || len(result.Fingerprints) == 0 {
		return
	}
	result.Fingerprints = differentFingerprintMatches(result.Fingerprints, knownFingerprints)
	if len(result.Fingerprints) == 0 {
		return
	}

	s.mutex.Lock()
	if s.basicURLWithFingerprint == nil {
		s.basicURLWithFingerprint = make(map[string][]string)
	}
	s.basicURLWithFingerprint[result.URL] = append(s.basicURLWithFingerprint[result.URL], matchedFingerprintNames(result.Fingerprints)...)
	s.mutex.Unlock()

	detect := result.Detect
	if detect == "" {
		detect = hostTokenPathDetectName
	}
	s.logScanResult(detect, result)
	if callback != nil && ctx.Err() == nil {
		callback(result)
	}
}

func isHostTokenPathProbeStatus(statusCode int) bool {
	return statusCode >= 200 && statusCode < 400
}

func filterInvalidHostTokenFingerprints(statusCode int, fingerprints []FingerprintMatch) []FingerprintMatch {
	if statusCode != http.StatusMethodNotAllowed || len(fingerprints) == 0 {
		return fingerprints
	}

	filtered := make([]FingerprintMatch, 0, len(fingerprints))
	for _, fp := range fingerprints {
		if isInvalidHostTokenWAFMatch(fp) {
			continue
		}
		filtered = append(filtered, fp)
	}
	return filtered
}

func isInvalidHostTokenWAFMatch(fp FingerprintMatch) bool {
	text := strings.ToLower(fp.Name + " " + fp.Description + " " + fp.MatchedRule)
	for _, marker := range []string{
		"waf",
		"web application firewall",
		"云防护",
		"云盾",
		"防火墙",
		"应用防火墙",
		"访问被阻断",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
