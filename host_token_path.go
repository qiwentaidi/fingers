package fingers

import (
	"context"
	"net"
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
	base *url.URL
	path string
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

	tasks := s.hostTokenPathProbeTasks()
	if len(tasks) == 0 {
		return
	}

	var wg sync.WaitGroup
	retChan := make(chan Result, len(tasks))
	done := make(chan struct{})
	discovered := make([]*url.URL, 0)

	go func() {
		for result := range retChan {
			if ctx.Err() != nil {
				break
			}

			s.mutex.Lock()
			if s.basicURLWithFingerprint == nil {
				s.basicURLWithFingerprint = make(map[string][]string)
			}
			s.basicURLWithFingerprint[result.URL] = append(s.basicURLWithFingerprint[result.URL], matchedFingerprintNames(result.Fingerprints)...)
			s.mutex.Unlock()

			if parsed, err := url.Parse(result.URL); err == nil {
				discovered = append(discovered, parsed)
			}

			s.logScanResult(hostTokenPathDetectName, result)
			if callback != nil && ctx.Err() == nil {
				callback(result)
			}
		}
		close(done)
	}()

	thread := s.thread
	if thread <= 0 {
		thread = 1
	}
	threadPool, err := ants.NewPoolWithFunc(thread, func(raw interface{}) {
		defer wg.Done()
		if ctx.Err() != nil {
			return
		}

		task := raw.(hostTokenPathProbeTask)
		if result, ok := s.probeHostTokenPath(ctx, task.base, task.path); ok {
			retChan <- result
		}
	})
	if err != nil {
		close(retChan)
		<-done
		return
	}
	defer threadPool.Release()

	for _, task := range tasks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		if err := threadPool.Invoke(task); err != nil {
			wg.Done()
		}
	}

	wg.Wait()
	close(retChan)
	<-done

	if len(discovered) > 0 {
		s.aliveURLs = append(s.aliveURLs, discovered...)
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
				base: base,
				path: path,
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

func (s *FingerScanner) probeHostTokenPath(ctx context.Context, base *url.URL, candidatePath string) (Result, bool) {
	if base == nil || ctx.Err() != nil {
		return Result{}, false
	}

	candidateURL := buildHostTokenPathURL(base, candidatePath)
	candidate := candidateURL.String()
	entryResp, err := clients.DoRequest("GET", candidate, s.headers, nil, hostTokenPathProbeTimeout, s.notFollowClient)
	if err != nil || entryResp == nil || !isHostTokenPathProbeStatus(entryResp.StatusCode()) {
		return Result{}, false
	}

	rawResponse := ""
	if s.enableRawResponse {
		rawResponse = dumpRawResponsePacket(entryResp)
	}

	finalResp := entryResp
	if entryResp.StatusCode() >= 300 && entryResp.StatusCode() < 400 {
		finalResp, err = clients.DoRequest("GET", candidate, s.headers, nil, hostTokenPathProbeTimeout, s.client)
		if err != nil || finalResp == nil {
			return Result{}, false
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

	if !isHostTokenPathProbeStatus(finalResp.StatusCode()) || ctx.Err() != nil {
		return Result{}, false
	}

	finalURL := candidateURL
	if finalResp.RawResponse != nil && finalResp.RawResponse.Request != nil && finalResp.RawResponse.Request.URL != nil {
		finalURL = finalResp.RawResponse.Request.URL
	}
	faviconResult := getFaviconWithStorage(finalURL, s.headers, s.client, s.faviconStore)

	body := httputil.LimitResponseBytes(finalResp.Body(), maxInfoReponseSize)
	title := clients.GetTitle(body)
	if exclude, _ := excludeInterference(finalResp.StatusCode(), title); exclude {
		return Result{}, false
	}

	server := finalResp.Header().Get("Server")
	contentType := finalResp.Header().Get("Content-Type")
	headers, _, _ := httputil.DumpResponseHeadersAndRaw(finalResp.RawResponse)
	web := &WebInfo{
		HeadeString:   strings.ToLower(string(headers)),
		ContentType:   strings.ToLower(contentType),
		BodyString:    strings.ToLower(string(body)),
		Path:          strings.ToLower(candidatePath),
		Title:         strings.ToLower(title),
		Server:        strings.ToLower(server),
		ContentLength: len(finalResp.Body()),
		Port:          httputil.GetPort(candidateURL),
		StatusCode:    entryResp.StatusCode(),
		IconHash:      faviconResult.Mmh3Hash,
		IconMd5:       faviconResult.Md5Hash,
	}

	var fingerprintDB []FingerEntity
	if s.fingerprintRepo != nil {
		fingerprintDB = s.fingerprintRepo.GetFingerprintDB()
	}
	fingerprints := Scan(web, fingerprintDB)
	if checkHoneypotWithHeaders(web.HeadeString) {
		fingerprints = []FingerprintMatch{{
			Name: "疑似蜜罐",
		}}
	}

	var screenshotPath string
	if s.screenshot && (candidateURL.Scheme == "https" || candidateURL.Scheme == "http") {
		if screenshotPath, err = s.captureScreenshot(ctx, candidate); err != nil {
			if s.shouldPrintDefaultOutput() {
				logger.Default.Warning("%s 截屏失败: %v", candidate, err)
			}
		}
	}

	return Result{
		URL:          candidate,
		Scheme:       candidateURL.Scheme,
		Host:         candidateURL.Host,
		Port:         web.Port,
		StatusCode:   web.StatusCode,
		Length:       web.ContentLength,
		Title:        title,
		Server:       server,
		ContentType:  contentType,
		Path:         candidatePath,
		Fingerprints: fingerprints,
		Detect:       hostTokenPathDetectName,
		Screenshot:   screenshotPath,
		Favicon:      faviconResult.FilePath,
		FaviconURL:   faviconResult.URL,
		IconHash:     faviconResult.Mmh3Hash,
		IconMd5:      faviconResult.Md5Hash,
		RawResponse:  rawResponse,
	}, true
}

func isHostTokenPathProbeStatus(statusCode int) bool {
	return statusCode >= 200 && statusCode < 400
}
