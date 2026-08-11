package fingers

import (
	"bytes"
	"context"
	"net/http"
	stdhttputil "net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/qiwentaidi/fingers/internal/cdncheck"
	"github.com/qiwentaidi/fingers/internal/logger"

	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
	httputil "github.com/qiwentaidi/utils/http"

	"github.com/go-resty/resty/v2"
	"github.com/panjf2000/ants/v2"
)

const maxInfoReponseSize = 1024 * 200 // 100KB

type WebInfo struct {
	Protocol      string
	Port          int
	Path          string
	Title         string
	StatusCode    int
	IconHash      string // mmh3
	IconMd5       string // md5
	BodyString    string
	JSBodyString  string
	JSBodyLoader  func() string
	HeadeString   string
	ContentType   string
	Server        string
	ContentLength int
	Banner        string // tcp指纹ß
	Cert          string // TLS证书
}

type FingerScanner struct {
	urls                  []*url.URL
	fingerprintRepo       *FingerprintRepository
	aliveURLs             []*url.URL // 默认指纹扫描结束后，存活的URL，以便后续主动指纹过滤目标
	activeTimeoutLimit    int        // 主动指纹扫描超时超过该次数就不再扫描该目标
	thread                int        // 指纹线程
	deepScan              bool       // 代表主动指纹探测
	rootPath              bool       // 主动指纹是否采取根路径扫描
	screenshot            bool       // 是否截屏
	screenshotDiagnostics bool       // 是否输出浏览器/截图诊断日志
	enableAssetTagProbe   bool
	enableRawResponse     bool
	enableDefaultOutput   bool
	headers               map[string]string // 请求头
	client                *resty.Client
	notFollowClient       *resty.Client
	proxy                 string
	faviconStore          assetStore
	screenshotStore       assetStore
	screenshotBrowser     *screenshotBrowser
	// dnsxClient              *dnsx.DNSX
	basicURLWithFingerprint  map[string][]string // 后续nuclei需要扫描的目标列表
	mutex                    sync.RWMutex
	jsContextMutex           sync.Mutex
	jsContextPaths           map[string][]string
	jsContextCache           map[string]*jsContextCacheEntry
	jsBodyCache              map[string]*jsBodyCacheEntry
	pageContextBodies        map[string][]byte
	pageContextStatusCodes   map[string]int
	discoveredRequestMutex   sync.Mutex
	discoveredRequests       map[string][]DiscoveredRequest
	pageDiscoveryMutex       sync.Mutex
	discoveredPageCandidates map[string]map[string]pageCandidate
}

func newFingerScanner(options Options, repo *FingerprintRepository, faviconStore assetStore, screenshotStore assetStore) *FingerScanner {
	// 解析目标列表
	targets := options.Targets

	urls := make([]*url.URL, 0, len(targets)) // 提前分配容量

	for _, t := range targets {
		t = strings.TrimRight(t, "/")
		if !strings.Contains(t, "://") {
			t = "http://" + t
		}
		t = normalizeWrappedProtocolTarget(t)

		u, err := url.Parse(t)
		if err != nil {
			logger.Default.Warning("parse url err: %v", err)
			continue
		}
		urls = append(urls, u)
	}

	if len(urls) == 0 {
		logger.Default.Warning("No available targets found, please check input")
		return nil
	}

	basicURLWithFingerprint := make(map[string][]string)

	return &FingerScanner{
		urls:                     urls,
		fingerprintRepo:          repo,
		client:                   clients.NewRestyClientWithProxy(nil, true, options.Proxy),
		notFollowClient:          clients.NewRestyClientWithProxy(nil, false, options.Proxy),
		proxy:                    options.Proxy,
		thread:                   options.Thread,
		deepScan:                 options.DeepScan,
		rootPath:                 options.RootPath,
		activeTimeoutLimit:       options.ActiveTimeoutLimit,
		screenshot:               options.EnableScreenshot,
		screenshotDiagnostics:    options.ScreenshotDiagnostics,
		enableAssetTagProbe:      options.EnableAssetTagProbe,
		enableRawResponse:        options.EnableRawResponse,
		enableDefaultOutput:      !options.DisableDefaultOutput,
		faviconStore:             faviconStore,
		screenshotStore:          screenshotStore,
		basicURLWithFingerprint:  basicURLWithFingerprint,
		jsContextPaths:           make(map[string][]string),
		jsContextCache:           make(map[string]*jsContextCacheEntry),
		jsBodyCache:              make(map[string]*jsBodyCacheEntry),
		pageContextBodies:        make(map[string][]byte),
		pageContextStatusCodes:   make(map[string]int),
		discoveredRequests:       make(map[string][]DiscoveredRequest),
		discoveredPageCandidates: make(map[string]map[string]pageCandidate),
		headers:                  parseHeadersToMap(options.CustomHeaders, options.Headers),
	}
}

var wrappedNonWebTargetSchemes = map[string]struct{}{
	"amqp":       {},
	"ftp":        {},
	"imap":       {},
	"ldap":       {},
	"ldaps":      {},
	"mongodb":    {},
	"mqtt":       {},
	"mysql":      {},
	"oracle":     {},
	"pop3":       {},
	"postgres":   {},
	"postgresql": {},
	"rdp":        {},
	"redis":      {},
	"rtsp":       {},
	"smb":        {},
	"smtp":       {},
	"snmp":       {},
	"ssh":        {},
	"tcp":        {},
	"telnet":     {},
	"udp":        {},
	"vnc":        {},
}

func normalizeWrappedProtocolTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasPrefix(u.Path, "//") {
		return raw
	}

	wrappedScheme := strings.ToLower(u.Host)
	if _, ok := wrappedNonWebTargetSchemes[wrappedScheme]; !ok {
		return raw
	}

	normalized := wrappedScheme + ":" + u.Path
	if u.RawQuery != "" {
		normalized += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		normalized += "#" + u.Fragment
	}
	return normalized
}

func (s *FingerScanner) shouldPrintDefaultOutput() bool {
	return s != nil && s.enableDefaultOutput
}

func (s *FingerScanner) shouldReportScreenshotDiagnostics() bool {
	return s != nil && (s.enableDefaultOutput || s.screenshotDiagnostics)
}

func (s *FingerScanner) formatDefaultFingerprintOutput(pr Result) string {
	var fingerprintDisplay []string
	if pr.AssetTags.AssetType != "" || pr.AssetTags.ProductName != "" {
		fingerprintDisplay = append(fingerprintDisplay, pr.AssetTags.AssetType+": "+pr.AssetTags.ProductName)
	}
	for _, fp := range pr.Fingerprints {
		label := logger.WithDescription(fp.Name, fp.Description)
		extractedValues := make([]string, 0, len(fp.Extractions))
		for _, extraction := range fp.Extractions {
			if strings.TrimSpace(extraction.Value) == "" {
				continue
			}
			extractedValues = append(extractedValues, extraction.Value)
		}
		if len(extractedValues) > 0 {
			label = label + " " + strings.Join(extractedValues, " ")
		}
		if fp.HighRisk {
			fingerprintDisplay = append(fingerprintDisplay, logger.Red(label))
		} else {
			fingerprintDisplay = append(fingerprintDisplay, logger.Title(label))
		}
	}
	if len(fingerprintDisplay) == 0 {
		fingerprintDisplay = []string{"无指纹"}
	}
	return strings.Join(fingerprintDisplay, " | ")
}

func (s *FingerScanner) logScanResult(scanType string, pr Result) {
	if !s.shouldPrintDefaultOutput() {
		return
	}
	logger.Default.PrintRaw("[%s] %s [%s] [%d] [%s] [%s]\n",
		scanType,
		pr.URL,
		logger.ColorStatus(pr.StatusCode),
		pr.Length,
		pr.Title,
		s.formatDefaultFingerprintOutput(pr),
	)
}

func dumpRawResponsePacket(resp *resty.Response) string {
	if resp == nil || resp.RawResponse == nil {
		return ""
	}
	headers, err := stdhttputil.DumpResponse(resp.RawResponse, false)
	if err != nil {
		return ""
	}
	return string(append(headers, resp.Body()...))
}

type passiveScanTarget struct {
	URL               *url.URL
	Detect            string
	RecordAlive       bool
	CaptureImage      bool
	KnownFingerprints []string
}

// FingerScan 执行初始目标的指纹扫描。
func (s *FingerScanner) FingerScan(ctrlCtx context.Context, callback ResultCallback) {
	targets := make([]passiveScanTarget, 0, len(s.urls))
	for _, target := range s.urls {
		targets = append(targets, passiveScanTarget{
			URL:          target,
			Detect:       "Default",
			RecordAlive:  true,
			CaptureImage: true,
		})
	}
	s.fingerScanTargets(ctrlCtx, callback, targets, s.thread, "finger")
}

// fingerScanTargets runs the complete passive fingerprint database against a
// bounded list of URLs. Discovered pages deliberately do not become active
// scan targets, so path discovery remains one-level and side-effect free.
func (s *FingerScanner) fingerScanTargets(ctrlCtx context.Context, callback ResultCallback, targets []passiveScanTarget, threads int, stage string) {
	if threads <= 0 {
		threads = 1
	}
	if stage == "" {
		stage = "finger"
	}
	var wg sync.WaitGroup
	single := make(chan struct{})
	count := len(targets)
	progress := newScanProgress(stage, count, s.shouldPrintDefaultOutput())
	defer progress.Finish()
	retChan := make(chan Result, count)
	go func() {
		for pr := range retChan {
			// 检查任务是否被取消
			if ctrlCtx.Err() != nil {
				// 任务已取消，停止处理结果
				if s.shouldPrintDefaultOutput() {
					logger.Default.Info("指纹扫描结果处理已取消")
				}
				break
			}
			if pr.StatusCode != 0 {
				scanType := "Finger"
				if pr.Detect != "" && pr.Detect != "Default" {
					scanType = pr.Detect
				}
				s.logScanResult(scanType, pr)
				// 调用回调函数前再次检查 context
				if callback != nil && ctrlCtx.Err() == nil {
					callback(pr)
				}
			}
		}
		close(single)
	}()
	// 指纹扫描
	fscan := func(scanTarget passiveScanTarget) {
		u := scanTarget.URL
		// 在函数入口检查 context
		if ctrlCtx.Err() != nil || u == nil {
			progress.Skipped()
			return
		}

		// 非web资产目标将其直接绑定到后续漏洞扫描的目标组中，跳过后续的指纹扫描
		if u.Scheme != "http" && u.Scheme != "https" {
			s.basicURLWithFingerprint[u.String()] = append(s.basicURLWithFingerprint[u.String()], u.Scheme)
			progress.Skipped()
			return
		}

		var (
			rawHeaders  []byte
			server      string
			contentType string
			statusCode  int
			rawResponse string
		)

		// 先进行一次不会重定向的扫描，可以获得重定向前页面的响应头中获取指纹
		progress.Requested()
		resp, err := clients.DoRequest("GET", u.String(), s.headers, nil, 10, s.notFollowClient)
		if err == nil && resp.StatusCode() >= 300 && resp.StatusCode() < 400 {
			rawHeaders = httputil.DumpResponseHeadersOnly(resp.RawResponse)
			if s.enableRawResponse {
				rawResponse = dumpRawResponsePacket(resp)
			}
		}

		// 在网络请求后检查 context
		if ctrlCtx.Err() != nil {
			progress.Skipped()
			return
		}

		// 正常请求指纹
		resp, err = clients.DoRequest("GET", u.String(), s.headers, nil, 10, s.client)
		if err != nil {
			if len(rawHeaders) > 0 {
				// gologger.Debug(s.ctx, fmt.Sprintf("%s has error to 302, response headers: %s", u.String(), string(rawHeaders)))
				statusCode = 302
			} else {
				if s.shouldPrintDefaultOutput() {
					logger.Default.Debug("request %s error: %v", u.String(), err)
				}
				progress.Failed()
				return
			}
		}
		if s.enableRawResponse {
			finalRawResponse := dumpRawResponsePacket(resp)
			switch {
			case rawResponse != "" && finalRawResponse != "":
				rawResponse += "\n\n--- final response ---\n\n" + finalRawResponse
			case finalRawResponse != "":
				rawResponse = finalRawResponse
			}
		}

		finalURL := u
		if resp != nil && resp.RawResponse != nil && resp.RawResponse.Request != nil && resp.RawResponse.Request.URL != nil {
			finalURL = resp.RawResponse.Request.URL
		}

		responseBody := resp.Body()
		body := httputil.LimitResponseBytes(responseBody, maxInfoReponseSize)
		if resp != nil && resp.RawResponse != nil {
			// 合并请求头数据, fix 0.1.0 raw.RawResponse 可能为 nil 导致的崩溃
			rawHeaders = append(rawHeaders, httputil.DumpResponseHeadersOnly(resp.RawResponse)...)
		}

		// 在执行额外扫描前检查 context
		if ctrlCtx.Err() != nil {
			progress.Skipped()
			return
		}

		// 请求Logo并保存到本地
		faviconResult := getFaviconWithStorage(finalURL, s.headers, s.client, s.faviconStore)

		// Shiro detection is limited to the origin root. A Shiro server commonly
		// places rememberMe=deleteMe after unrelated cookies, so Header.Get("Set-Cookie")
		// would discard the identifying value.
		if rootURL, parseErr := url.Parse(httputil.GetBasicURL(finalURL.String())); parseErr == nil {
			rawHeaders = append(rawHeaders, s.ShiroScan(rootURL)...)
		}

		// 跟随JS重定向，并替换成重定向后的数据
		redirectBody := s.GetJSRedirectResponse(finalURL, string(body))
		if redirectBody != nil {
			// JS重定向后，body数据不应该直接覆盖 fix in 2.0.8
			body = append(body, redirectBody...)
			// body = redirectBody
		}
		if scanTarget.RecordAlive && s.deepScan {
			s.storeJSContextPage(finalURL, responseBody, resp.StatusCode())
		}
		// 网站正常响应
		title := clients.GetTitle(body)
		statusCode = resp.StatusCode()

		if exclude, _ := excludeInterference(statusCode, title); exclude {
			progress.Skipped()
			return
		}

		server = resp.Header().Get("Server")
		contentType = resp.Header().Get("Content-Type")
		web := &WebInfo{
			HeadeString: strings.ToLower(string(rawHeaders)),
			ContentType: strings.ToLower(contentType),
			Cert:        strings.ToLower(GetTLSString(finalURL.Scheme, finalURL.Host)),
			BodyString:  strings.ToLower(string(body)),
			JSBodyLoader: func() string {
				return strings.ToLower(string(s.collectPageJSFingerprintBody(ctrlCtx, finalURL, responseBody)))
			},
			Path:          strings.ToLower(finalURL.Path),
			Title:         strings.ToLower(title),
			Server:        strings.ToLower(server),
			ContentLength: len(resp.Body()),
			Port:          httputil.GetPort(finalURL),
			IconHash:      faviconResult.Mmh3Hash,
			IconMd5:       faviconResult.Md5Hash,
			StatusCode:    statusCode,
		}

		var assets *Tag
		if s.enableAssetTagProbe {
			if detected, ok := cdncheck.Detect(finalURL.Hostname()); ok {
				assets = &Tag{
					ProductName: detected.ProductName,
					AssetType:   detected.AssetType,
					Source:      detected.Source,
				}
			}
		}

		if scanTarget.RecordAlive {
			s.aliveURLs = append(s.aliveURLs, finalURL)
		}

		fingerprints := Scan(web, s.fingerprintRepo.GetFingerprintDB())

		// if s.FastjsonScan(u) {
		// 	fingerprints = append(fingerprints, "Fastjson")
		// }

		if checkHoneypotWithHeaders(web.HeadeString) {
			fingerprints = []FingerprintMatch{{
				Name: "疑似蜜罐",
			}}
		}
		if len(scanTarget.KnownFingerprints) > 0 {
			fingerprints = differentFingerprintMatches(fingerprints, scanTarget.KnownFingerprints)
		}
		// A discovered page is only useful when it contributes a fingerprint.
		// In particular, JS route extraction often yields client-side routes that
		// the server answers with a plain 404 page; reporting those as fingerprint
		// results produces noisy false discoveries.
		if scanTarget.Detect != "" && scanTarget.Detect != "Default" && len(fingerprints) == 0 {
			progress.Skipped()
			return
		}

		// 在截屏前检查 context（截屏是耗时操作）
		if ctrlCtx.Err() != nil {
			progress.Skipped()
			return
		}
		if len(fingerprints) > 0 {
			progress.Matched()
		}

		// 截屏
		var screenshotPath string
		if scanTarget.CaptureImage && s.screenshot && (finalURL.Scheme == "https" || finalURL.Scheme == "http") {
			if screenshotPath, err = s.captureScreenshot(ctrlCtx, finalURL.String()); err != nil {
				if s.shouldReportScreenshotDiagnostics() {
					logger.Default.Warning("%s 截屏失败: %v", finalURL.String(), err)
				}
			}
		}

		s.mutex.Lock()
		// 合并普通指纹和高危指纹（用于后续 Nuclei 扫描的标签）
		allFingerprints := matchedFingerprintNames(fingerprints)
		s.basicURLWithFingerprint[finalURL.String()] = append(s.basicURLWithFingerprint[finalURL.String()], allFingerprints...)
		s.mutex.Unlock()

		result := Result{
			URL:          finalURL.String(),
			Scheme:       finalURL.Scheme,
			Host:         finalURL.Host,
			Port:         web.Port,
			StatusCode:   web.StatusCode,
			Length:       web.ContentLength,
			Title:        title,
			Server:       server,
			ContentType:  contentType,
			Path:         finalURL.Path,
			Fingerprints: fingerprints,
			Detect:       scanTarget.Detect,
			Screenshot:   screenshotPath,
			Favicon:      faviconResult.FilePath, // favicon图片路径
			FaviconURL:   faviconResult.URL,
			IconHash:     faviconResult.Mmh3Hash,
			IconMd5:      faviconResult.Md5Hash,
			RawResponse:  rawResponse,
		}

		if assets != nil {
			result.AssetTags = *assets
		}

		retChan <- result
	}
	threadPool, _ := ants.NewPoolWithFunc(threads, func(target interface{}) {
		defer wg.Done()
		defer progress.Processed()
		if ctrlCtx.Err() != nil {
			progress.Skipped()
			return
		}
		fscan(target.(passiveScanTarget))
	})
	defer threadPool.Release()
	for _, target := range targets {
		if ctrlCtx.Err() != nil {
			return
		}
		wg.Add(1)
		if err := threadPool.Invoke(target); err != nil {
			progress.Skipped()
			progress.Processed()
			wg.Done()
		}
	}
	wg.Wait()
	close(retChan)
	<-single
}

type ActiveFingerDetect struct {
	URL               *url.URL
	Fpe               []FingerEntity
	MultiPath         *FingerEntity
	Path              string
	Detect            string
	KnownFingerprints []string
}

// 让每一个路径都只绑定一个实体
func groupActiveFingerprintsByPath(fingers []FingerEntity) map[string][]FingerEntity {
	pathMap := make(map[string][]FingerEntity)
	for _, finger := range fingers {
		for _, path := range finger.Path {
			if path == "" {
				continue
			}
			pathMap[path] = append(pathMap[path], finger)
		}
	}
	return pathMap
}

// ActiveFingerScan 执行主动指纹扫描
func (s *FingerScanner) ActiveFingerScan(ctx context.Context, callback ResultCallback) {
	if s.activeTimeoutLimit == 0 {
		if s.shouldPrintDefaultOutput() {
			logger.Default.Info("ActiveTimeoutLimit is 0, skipping active fingerprint scanning")
		}
		return
	}
	if len(s.aliveURLs) == 0 {
		if s.shouldPrintDefaultOutput() {
			logger.Default.Warning("No surviving target found, active fingerprint scanning has been skipped")
		}
		return
	}

	// 检查 context
	if ctx.Err() != nil {
		if s.shouldPrintDefaultOutput() {
			logger.Default.Info("主动指纹扫描已取消")
		}
		return
	}

	var wg sync.WaitGroup
	visited := sync.Map{}        // 记录已访问路径
	timeoutCounter := sync.Map{} // 记录每个目标的超时次数
	seenAdminPathFingerprints := make(map[string]struct{})
	single := make(chan struct{})
	retChan := make(chan Result, len(s.urls))
	count := s.ActiveCounts()
	progress := newScanProgress("active", count, s.shouldPrintDefaultOutput())
	defer progress.Finish()

	go func() {
		for pr := range retChan {
			// 检查任务是否被取消
			if ctx.Err() != nil {
				if s.shouldPrintDefaultOutput() {
					logger.Default.Info("主动指纹扫描结果处理已取消")
				}
				break
			}
			detect := pr.Detect
			if detect == "" {
				detect = "Active"
			}
			if detect == adminPathDetectName {
				var ok bool
				pr, ok = deduplicateAdminPathResult(pr, seenAdminPathFingerprints)
				if !ok {
					continue
				}
				s.mutex.Lock()
				if s.basicURLWithFingerprint == nil {
					s.basicURLWithFingerprint = make(map[string][]string)
				}
				mapKey := adminPathDedupeTarget(pr)
				s.basicURLWithFingerprint[mapKey] = append(s.basicURLWithFingerprint[mapKey], matchedFingerprintNames(pr.Fingerprints)...)
				s.mutex.Unlock()
			}
			s.logScanResult(detect, pr)
			// 调用回调函数前检查 context
			if callback != nil && ctx.Err() == nil {
				callback(pr)
			}
		}
		close(single)
	}()

	// 主动指纹扫描线程池
	threadPool, _ := ants.NewPoolWithFunc(s.thread, func(tfp interface{}) {
		defer wg.Done()
		defer progress.Processed()

		// 在 goroutine 中检查 context
		if ctx.Err() != nil {
			progress.Skipped()
			return
		}

		fp := tfp.(ActiveFingerDetect)
		if fp.URL == nil {
			progress.Skipped()
			return
		}
		if fp.MultiPath != nil {
			progress.Requested()
			result, ok, outcome := s.probeMultiPathFingerprint(ctx, fp, &timeoutCounter)
			switch outcome {
			case scanProgressOutcomeFailed:
				progress.Failed()
			case scanProgressOutcomeMatched:
				progress.Matched()
			default:
				progress.Skipped()
			}
			if ok {
				retChan <- result
			}
			return
		}
		detect := fp.Detect
		if detect == "" {
			detect = "Active"
		}
		fullURL := buildActiveProbeURL(fp.URL, fp.Path)
		baseURL := fp.URL.String()

		if val, ok := timeoutCounter.Load(baseURL); ok && val.(int) >= s.activeTimeoutLimit {
			if s.shouldPrintDefaultOutput() {
				logger.Default.Warning("Target %s has reached the timeout limit, skipping active scan", baseURL)
			}
			progress.Skipped()
			return
		}

		// A context probe can resolve to a path already covered by the regular
		// active map. Deduplicate by the final URL so the target is requested
		// only once, regardless of which detection class submitted it first.
		visitKey := fullURL
		if _, ok := visited.Load(visitKey); ok {
			progress.Skipped()
			return
		}
		visited.Store(visitKey, true)

		progress.Requested()
		resp, err := clients.DoRequest("GET", fullURL, s.headers, nil, 5, s.client)
		if err != nil {
			v, _ := timeoutCounter.LoadOrStore(baseURL, 1)
			timeoutCounter.Store(baseURL, v.(int)+1)
			progress.Failed()
			return
		}
		if detect == adminPathDetectName && resp.StatusCode() == http.StatusNotFound {
			progress.Skipped()
			return
		}
		rawResponse := ""
		if s.enableRawResponse {
			rawResponse = dumpRawResponsePacket(resp)
		}

		// 在处理响应前检查 context
		if ctx.Err() != nil {
			progress.Skipped()
			return
		}

		body := resp.Body()
		server := resp.Header().Get("Server")
		contentType := resp.Header().Get("Content-Type")
		title := clients.GetTitle(body)

		headers, _, _ := httputil.DumpResponseHeadersAndRaw(resp.RawResponse)
		faviconResult := FaviconResult{}
		if isImagePath(fullURL) {
			faviconResult = hashIconBytes(body)
		} else if detect == adminPathDetectName {
			if probeURL, parseErr := url.Parse(fullURL); parseErr == nil {
				faviconResult = getFaviconWithStorage(probeURL, s.headers, s.client, s.faviconStore)
			}
		}
		ti := &WebInfo{
			HeadeString:   strings.ToLower(string(headers)),
			ContentType:   strings.ToLower(contentType),
			BodyString:    strings.ToLower(string(body)),
			Path:          strings.ToLower(fp.Path),
			Title:         strings.ToLower(title),
			Server:        strings.ToLower(server),
			ContentLength: len(body),
			Port:          httputil.GetPort(fp.URL),
			StatusCode:    resp.StatusCode(),
			IconHash:      faviconResult.Mmh3Hash,
			IconMd5:       faviconResult.Md5Hash,
		}
		result := Scan(ti, fp.Fpe)
		if detect == adminPathDetectName {
			result = differentFingerprintMatches(result, fp.KnownFingerprints)
		}

		if len(result) > 0 {
			resultPath := fp.Path
			if detect == contextActiveDetectName {
				if parsedURL, parseErr := url.Parse(fullURL); parseErr == nil {
					resultPath = parsedURL.Path
				}
			}
			// 截屏
			var screenshotPath string
			if s.screenshot && (fp.URL.Scheme == "https" || fp.URL.Scheme == "http") {
				if screenshotPath, err = s.captureScreenshot(ctx, fullURL); err != nil {
					if s.shouldReportScreenshotDiagnostics() {
						logger.Default.Warning("%s 截屏失败: %v", fp.URL.String(), err)
					}
				}
			}

			// 在保存结果前检查 context
			if ctx.Err() != nil {
				progress.Skipped()
				return
			}
			progress.Matched()

			if detect != adminPathDetectName {
				s.mutex.Lock()
				if s.basicURLWithFingerprint == nil {
					s.basicURLWithFingerprint = make(map[string][]string)
				}
				s.basicURLWithFingerprint[fp.URL.String()] = append(s.basicURLWithFingerprint[fp.URL.String()], matchedFingerprintNames(result)...)
				s.mutex.Unlock()
			}

			retChan <- Result{
				URL:          fullURL,
				StatusCode:   ti.StatusCode,
				Length:       ti.ContentLength,
				Title:        title,
				Server:       server,
				ContentType:  contentType,
				Path:         resultPath,
				Fingerprints: result,
				Detect:       detect,
				Port:         ti.Port,
				Scheme:       fp.URL.Scheme,
				Host:         fp.URL.Host,
				Screenshot:   screenshotPath,
				Favicon:      faviconResult.FilePath,
				FaviconURL:   faviconResult.URL,
				IconHash:     faviconResult.Mmh3Hash,
				IconMd5:      faviconResult.Md5Hash,
				RawResponse:  rawResponse,
			}
		} else {
			progress.Skipped()
		}
	})
	defer threadPool.Release()
	submitActiveTask := func(task ActiveFingerDetect) {
		wg.Add(1)
		if err := threadPool.Invoke(task); err != nil {
			progress.Skipped()
			progress.Processed()
			wg.Done()
		}
	}

	activePathMap := groupActiveFingerprintsByPath(s.getActiveFingerprintDB())
	contextActivePathMap := groupActiveFingerprintsByPath(s.getContextActiveFingerprintDB())
	multiPathFingerprints := s.getMultiPathFingerprintDB()
	fullFingerprintDB := s.getFingerprintDB()
	for _, target := range s.aliveURLs {
		// 在外层循环检查 context
		if ctx.Err() != nil {
			if s.shouldPrintDefaultOutput() {
				logger.Default.Info("主动指纹扫描已取消，停止提交新任务")
			}
			break
		}

		activeTarget := target
		if s.rootPath {
			activeTarget, _ = url.Parse(httputil.GetBasicURL(target.String()))
		}
		if activeTarget == nil {
			continue
		}

		for _, fingerprint := range multiPathFingerprints {
			if len(fingerprint.PathRules) == 0 {
				continue
			}
			base := activeTarget.String()
			if val, ok := timeoutCounter.Load(base); ok && val.(int) >= s.activeTimeoutLimit {
				progress.Skipped()
				progress.Processed()
				continue
			}

			multiPath := fingerprint
			submitActiveTask(ActiveFingerDetect{
				URL:       activeTarget,
				MultiPath: &multiPath,
				Detect:    "Active",
			})
		}

		activeProbeURLs := make(map[string]struct{}, len(activePathMap))
		for path := range activePathMap {
			activeProbeURLs[buildActiveProbeURL(activeTarget, path)] = struct{}{}
		}
		contextProbeURLs := make(map[string]struct{})

		for path, fingers := range activePathMap {
			// 在内层循环也检查 context
			if ctx.Err() != nil {
				break
			}

			base := activeTarget.String()
			if val, ok := timeoutCounter.Load(base); ok && val.(int) >= s.activeTimeoutLimit {
				progress.Skipped()
				progress.Processed()
				continue
			}

			submitActiveTask(ActiveFingerDetect{
				URL:    activeTarget,
				Fpe:    fingers,
				Path:   path,
				Detect: "Active",
			})
		}

		for _, contextPath := range s.contextPathsForTarget(target) {
			contextTarget := buildContextBaseURL(target, contextPath)
			if contextTarget == nil || sameURLPath(activeTarget.Path, contextTarget.Path) {
				continue
			}
			for path, fingers := range contextActivePathMap {
				if ctx.Err() != nil {
					break
				}
				probeURL := buildActiveProbeURL(contextTarget, path)
				if _, exists := activeProbeURLs[probeURL]; exists {
					continue
				}
				if _, exists := contextProbeURLs[probeURL]; exists {
					continue
				}
				contextProbeURLs[probeURL] = struct{}{}

				base := contextTarget.String()
				if val, ok := timeoutCounter.Load(base); ok && val.(int) >= s.activeTimeoutLimit {
					progress.Skipped()
					progress.Processed()
					continue
				}

				submitActiveTask(ActiveFingerDetect{
					URL:    contextTarget,
					Fpe:    fingers,
					Path:   path,
					Detect: contextActiveDetectName,
				})
			}
		}

		if len(fullFingerprintDB) == 0 {
			continue
		}
		knownFingerprints := s.knownFingerprintsForActiveTarget(target, activeTarget)
		for _, path := range basicAdminBackendPaths {
			// 在内层循环也检查 context
			if ctx.Err() != nil {
				break
			}

			base := activeTarget.String()
			if val, ok := timeoutCounter.Load(base); ok && val.(int) >= s.activeTimeoutLimit {
				progress.Skipped()
				progress.Processed()
				continue
			}

			submitActiveTask(ActiveFingerDetect{
				URL:               activeTarget,
				Fpe:               fullFingerprintDB,
				Path:              path,
				Detect:            adminPathDetectName,
				KnownFingerprints: knownFingerprints,
			})
		}
	}

	wg.Wait()
	close(retChan)
	<-single
}

func (s *FingerScanner) probeMultiPathFingerprint(ctx context.Context, task ActiveFingerDetect, timeoutCounter *sync.Map) (Result, bool, scanProgressOutcome) {
	if task.URL == nil || task.MultiPath == nil || len(task.MultiPath.PathRules) == 0 {
		return Result{}, false, scanProgressOutcomeSkipped
	}

	baseURL := task.URL.String()
	if val, ok := timeoutCounter.Load(baseURL); ok && val.(int) >= s.activeTimeoutLimit {
		return Result{}, false, scanProgressOutcomeSkipped
	}

	matched := make(map[string]FingerprintMatch)
	var firstWeb *WebInfo
	var firstURL string
	var firstTitle string
	var firstServer string
	var firstContentType string
	var rawResponses []string

	for _, pathRule := range task.MultiPath.PathRules {
		if ctx.Err() != nil {
			return Result{}, false, scanProgressOutcomeSkipped
		}

		fullURL := buildActiveProbeURL(task.URL, pathRule.Path)
		resp, err := clients.DoRequest("GET", fullURL, s.headers, nil, 5, s.client)
		if err != nil {
			v, _ := timeoutCounter.LoadOrStore(baseURL, 1)
			timeoutCounter.Store(baseURL, v.(int)+1)
			return Result{}, false, scanProgressOutcomeFailed
		}

		body := resp.Body()
		server := resp.Header().Get("Server")
		contentType := resp.Header().Get("Content-Type")
		title := clients.GetTitle(body)
		headers, _, _ := httputil.DumpResponseHeadersAndRaw(resp.RawResponse)
		responsePath := pathRule.Path
		if parsedURL, parseErr := url.Parse(fullURL); parseErr == nil {
			responsePath = parsedURL.Path
		}

		web := &WebInfo{
			Protocol:      strings.ToLower(task.URL.Scheme),
			HeadeString:   strings.ToLower(string(headers)),
			ContentType:   strings.ToLower(contentType),
			Cert:          strings.ToLower(GetTLSString(task.URL.Scheme, task.URL.Host)),
			BodyString:    strings.ToLower(string(body)),
			Path:          strings.ToLower(responsePath),
			Title:         strings.ToLower(title),
			Server:        strings.ToLower(server),
			ContentLength: len(body),
			Port:          httputil.GetPort(task.URL),
			StatusCode:    resp.StatusCode(),
		}

		pathMatches := Scan(web, pathRule.Fingerprints)
		if len(pathMatches) == 0 {
			return Result{}, false, scanProgressOutcomeSkipped
		}
		mergeFingerprintMatches(matched, pathMatches)

		if firstWeb == nil {
			firstWeb = web
			firstURL = fullURL
			firstTitle = title
			firstServer = server
			firstContentType = contentType
		}
		if s.enableRawResponse {
			rawResponses = append(rawResponses, dumpRawResponsePacket(resp))
		}
	}

	if firstWeb == nil || ctx.Err() != nil {
		return Result{}, false, scanProgressOutcomeSkipped
	}

	var screenshotPath string
	if s.screenshot && (task.URL.Scheme == "https" || task.URL.Scheme == "http") {
		var err error
		screenshotPath, err = s.captureScreenshot(ctx, firstURL)
		if err != nil && s.shouldReportScreenshotDiagnostics() {
			logger.Default.Warning("%s 截屏失败: %v", firstURL, err)
		}
	}

	fingerprints := fingerprintMatchesFromMap(matched)
	s.mutex.Lock()
	if s.basicURLWithFingerprint == nil {
		s.basicURLWithFingerprint = make(map[string][]string)
	}
	s.basicURLWithFingerprint[baseURL] = append(s.basicURLWithFingerprint[baseURL], matchedFingerprintNames(fingerprints)...)
	s.mutex.Unlock()

	return Result{
		URL:          firstURL,
		Scheme:       task.URL.Scheme,
		Host:         task.URL.Host,
		Port:         firstWeb.Port,
		StatusCode:   firstWeb.StatusCode,
		Length:       firstWeb.ContentLength,
		Title:        firstTitle,
		Server:       firstServer,
		ContentType:  firstContentType,
		Path:         firstWeb.Path,
		Fingerprints: fingerprints,
		Detect:       "Active",
		Screenshot:   screenshotPath,
		RawResponse:  strings.Join(rawResponses, "\n\n--- path_rules response ---\n\n"),
	}, true, scanProgressOutcomeMatched
}

func buildActiveProbeURL(base *url.URL, probePath string) string {
	if base == nil {
		return probePath
	}
	next := *base
	next.RawQuery = ""
	next.Fragment = ""
	if probePath == "" {
		return next.String()
	}
	if !strings.HasPrefix(probePath, "/") {
		probePath = "/" + probePath
	}
	basePath := strings.TrimRight(next.Path, "/")
	if basePath == "" {
		next.Path = probePath
	} else {
		next.Path = basePath + probePath
	}
	next.RawPath = ""
	return next.String()
}

func (s *FingerScanner) getFingerprintDB() []FingerEntity {
	if s == nil || s.fingerprintRepo == nil {
		return nil
	}
	return s.fingerprintRepo.GetFingerprintDB()
}

func (s *FingerScanner) getActiveFingerprintDB() []FingerEntity {
	if s == nil || s.fingerprintRepo == nil {
		return nil
	}
	return s.fingerprintRepo.GetActiveFingerprintDB()
}

func (s *FingerScanner) getContextActiveFingerprintDB() []FingerEntity {
	if s == nil || s.fingerprintRepo == nil {
		return nil
	}
	return s.fingerprintRepo.GetContextActiveFingerprintDB()
}

func (s *FingerScanner) getMultiPathFingerprintDB() []FingerEntity {
	if s == nil || s.fingerprintRepo == nil {
		return nil
	}
	return s.fingerprintRepo.GetMultiPathFingerprintDB()
}

func (s *FingerScanner) knownFingerprintsForActiveTarget(target *url.URL, activeTarget *url.URL) []string {
	if s == nil || s.basicURLWithFingerprint == nil {
		return nil
	}

	seenKeys := make(map[string]struct{})
	keys := make([]string, 0, 4)
	appendKnownFingerprintKey := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if _, ok := seenKeys[raw]; ok {
			return
		}
		seenKeys[raw] = struct{}{}
		keys = append(keys, raw)
	}

	if target != nil {
		appendKnownFingerprintKey(target.String())
		appendKnownFingerprintKey(httputil.GetBasicURL(target.String()))
	}
	if activeTarget != nil {
		appendKnownFingerprintKey(activeTarget.String())
		appendKnownFingerprintKey(httputil.GetBasicURL(activeTarget.String()))
	}

	seenNames := make(map[string]struct{})
	names := make([]string, 0)
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, key := range keys {
		for _, name := range s.basicURLWithFingerprint[key] {
			if name == "" {
				continue
			}
			if _, ok := seenNames[name]; ok {
				continue
			}
			seenNames[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

// 统计主动指纹总共要扫描的目标
func (s *FingerScanner) ActiveCounts() int {
	if s == nil || len(s.aliveURLs) == 0 {
		return 0
	}

	activePathCount := len(groupActiveFingerprintsByPath(s.getActiveFingerprintDB()))
	multiPathCount := 0
	for _, fingerprint := range s.getMultiPathFingerprintDB() {
		if len(fingerprint.PathRules) > 0 {
			multiPathCount++
		}
	}
	adminPathCount := 0
	if len(s.getFingerprintDB()) > 0 {
		adminPathCount = len(basicAdminBackendPaths)
	}

	total := 0
	for _, target := range s.aliveURLs {
		if target == nil {
			continue
		}
		total += activePathCount + multiPathCount + adminPathCount
		activeTarget := target
		if s.rootPath {
			activeTarget, _ = url.Parse(httputil.GetBasicURL(target.String()))
		}
		if activeTarget == nil {
			continue
		}
		activeProbeURLs := make(map[string]struct{}, activePathCount)
		for path := range groupActiveFingerprintsByPath(s.getActiveFingerprintDB()) {
			activeProbeURLs[buildActiveProbeURL(activeTarget, path)] = struct{}{}
		}
		contextProbeURLs := make(map[string]struct{})
		for _, contextPath := range s.contextPathsForTarget(target) {
			contextTarget := buildContextBaseURL(target, contextPath)
			if contextTarget == nil || sameURLPath(activeTarget.Path, contextTarget.Path) {
				continue
			}
			for path := range groupActiveFingerprintsByPath(s.getContextActiveFingerprintDB()) {
				probeURL := buildActiveProbeURL(contextTarget, path)
				if _, exists := activeProbeURLs[probeURL]; exists {
					continue
				}
				if _, exists := contextProbeURLs[probeURL]; exists {
					continue
				}
				contextProbeURLs[probeURL] = struct{}{}
				total++
			}
		}
	}
	return total
}

func (s *FingerScanner) URLWithFingerprintMap() map[string][]string {
	return s.basicURLWithFingerprint
}

func (web *WebInfo) JSBody() string {
	if web == nil {
		return ""
	}
	if web.JSBodyString != "" || web.JSBodyLoader == nil {
		return web.JSBodyString
	}
	web.JSBodyString = web.JSBodyLoader()
	web.JSBodyLoader = nil
	return web.JSBodyString
}

func extractionSourceContent(web *WebInfo, source string) string {
	switch source {
	case "header":
		return web.HeadeString
	case "body":
		return web.BodyString
	case "js_body", "js":
		return web.JSBody()
	case "server":
		return web.Server
	case "title":
		return web.Title
	case "cert":
		return web.Cert
	case "path":
		return web.Path
	case "content_type":
		return web.ContentType
	case "banner":
		return web.Banner
	default:
		return ""
	}
}

func extractFingerprintValues(finger FingerEntity, web *WebInfo) []FingerprintExtraction {
	if len(finger.Extract) == 0 || web == nil {
		return nil
	}

	seen := make(map[string]struct{})
	results := make([]FingerprintExtraction, 0)
	for _, extract := range finger.Extract {
		source := strings.ToLower(strings.TrimSpace(extract.From))
		pattern := strings.TrimSpace(extract.Regex)
		if source == "" || pattern == "" {
			continue
		}

		content := extractionSourceContent(web, source)
		if content == "" {
			continue
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			logger.Default.Warning("[fingerprint] 提取规则错误 %s %s: %v", finger.ProductName, pattern, err)
			continue
		}

		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			value := ""
			if len(match) > 1 {
				value = strings.TrimSpace(match[1])
			} else if len(match) > 0 {
				value = strings.TrimSpace(match[0])
			}
			if value == "" {
				continue
			}

			name := extract.Name
			if strings.TrimSpace(name) == "" {
				name = finger.ProductName
			}

			dedupKey := finger.ProductName + "\x00" + name + "\x00" + source + "\x00" + value
			if _, ok := seen[dedupKey]; ok {
				continue
			}
			seen[dedupKey] = struct{}{}
			results = append(results, FingerprintExtraction{
				Fingerprint: finger.ProductName,
				Name:        name,
				Source:      source,
				Value:       value,
			})
		}
	}

	return results
}

func matchedFingerprintNames(fingerprints []FingerprintMatch) []string {
	names := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		names = append(names, fp.Name)
	}
	return arrayutil.RemoveDuplicates(names)
}

func mergeFingerprintMatches(target map[string]FingerprintMatch, matches []FingerprintMatch) {
	for _, match := range matches {
		existing, ok := target[match.Name]
		if !ok {
			target[match.Name] = match
			continue
		}
		existing.HighRisk = existing.HighRisk || match.HighRisk
		existing.Vuln = existing.Vuln || match.Vuln
		if strings.TrimSpace(existing.Description) == "" {
			existing.Description = match.Description
		}
		if existing.MatchedRule == "" {
			existing.MatchedRule = match.MatchedRule
		}
		for _, extraction := range match.Extractions {
			seen := false
			for _, previous := range existing.Extractions {
				if previous.Name == extraction.Name && previous.Source == extraction.Source && previous.Value == extraction.Value {
					seen = true
					break
				}
			}
			if !seen {
				existing.Extractions = append(existing.Extractions, extraction)
			}
		}
		target[match.Name] = existing
	}
}

func fingerprintMatchesFromMap(matches map[string]FingerprintMatch) []FingerprintMatch {
	result := make([]FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		result = append(result, match)
	}
	return result
}

// Scan 扫描指纹，返回结构化指纹结果。
func Scan(web *WebInfo, targetDB []FingerEntity) []FingerprintMatch {
	fingerprintMap := make(map[string]*FingerprintMatch)

	for _, finger := range targetDB {
		if _, exists := fingerprintMap[finger.ProductName]; exists && fingerHasRuleKey(finger, "js_body") {
			continue
		}

		expr, _ := buildFingerprintExpression(finger, web, false)
		r, known, err := boolEvalWithUnknown(expr)
		if err != nil {
			logger.Default.Warning("[fingerprint] 错误指纹: %v", finger.AllString)
			continue
		}
		if !known {
			expr, _ = buildFingerprintExpression(finger, web, true)
			r, err = boolEval(expr)
			if err != nil {
				logger.Default.Warning("[fingerprint] 错误指纹: %v", finger.AllString)
				continue
			}
		}
		if r {
			match, exists := fingerprintMap[finger.ProductName]
			if !exists {
				match = &FingerprintMatch{
					Name:        finger.ProductName,
					Description: finger.Description,
					HighRisk:    finger.HighRisk,
					Vuln:        finger.Vuln,
					MatchedRule: finger.AllString,
				}
				fingerprintMap[finger.ProductName] = match
			}
			if strings.TrimSpace(match.Description) == "" {
				match.Description = finger.Description
			}
			match.HighRisk = match.HighRisk || finger.HighRisk
			match.Vuln = match.Vuln || finger.Vuln
			if match.MatchedRule == "" {
				match.MatchedRule = finger.AllString
			}
			for _, extraction := range extractFingerprintValues(finger, web) {
				seen := false
				for _, existing := range match.Extractions {
					if existing.Name == extraction.Name && existing.Source == extraction.Source && existing.Value == extraction.Value {
						seen = true
						break
					}
				}
				if !seen {
					match.Extractions = append(match.Extractions, extraction)
				}
			}
		}
	}

	results := make([]FingerprintMatch, 0, len(fingerprintMap))
	for _, match := range fingerprintMap {
		results = append(results, *match)
	}
	return results
}

func buildFingerprintExpression(finger FingerEntity, web *WebInfo, includeJSBody bool) (string, bool) {
	expr := finger.AllString
	hasUnknown := false
	for _, rule := range finger.Rule {
		replacement := "F"
		if isJSBodyRule(rule) && !includeJSBody {
			replacement = "U"
			hasUnknown = true
		} else if evaluateWebRule(rule, web) {
			replacement = "T"
		}
		expr = expr[:rule.Start] + replacement + expr[rule.End:]
	}
	return expr, hasUnknown
}

func boolEvalWithUnknown(expr string) (bool, bool, error) {
	if !strings.Contains(expr, "U") {
		result, err := boolEval(expr)
		return result, true, err
	}

	trueResult, err := boolEval(strings.ReplaceAll(expr, "U", "T"))
	if err != nil {
		return false, false, err
	}
	falseResult, err := boolEval(strings.ReplaceAll(expr, "U", "F"))
	if err != nil {
		return false, false, err
	}
	if trueResult == falseResult {
		return trueResult, true, nil
	}
	return false, false, nil
}

func evaluateWebRule(rule RuleData, web *WebInfo) bool {
	switch rule.Key {
	case "header":
		return dataCheckString(rule.Op, web.HeadeString, rule.ValueLC)
	case "body":
		return dataCheckString(rule.Op, web.BodyString, rule.ValueLC)
	case "js_body":
		return dataCheckString(rule.Op, web.JSBody(), rule.ValueLC)
	case "server":
		return dataCheckString(rule.Op, web.Server, rule.ValueLC)
	case "title":
		return dataCheckString(rule.Op, web.Title, rule.ValueLC)
	case "cert":
		return dataCheckString(rule.Op, web.Cert, rule.ValueLC)
	case "port":
		value, err := strconv.Atoi(rule.Value)
		return err == nil && dataCheckInt(rule.Op, web.Port, value)
	case "protocol":
		return (rule.Op == 0 && web.Protocol == rule.ValueLC) || (rule.Op == 1 && web.Protocol != rule.ValueLC)
	case "path":
		return dataCheckString(rule.Op, web.Path, rule.ValueLC)
	case "icon_hash":
		value, err := strconv.Atoi(rule.Value)
		hashIcon, errHash := strconv.Atoi(web.IconHash)
		return err == nil && errHash == nil && dataCheckInt(rule.Op, hashIcon, value)
	case "icon_md5", "icon_mdhash":
		return dataCheckString(rule.Op, web.IconMd5, rule.ValueLC)
	case "status":
		value, err := strconv.Atoi(rule.Value)
		return err == nil && dataCheckInt(rule.Op, web.StatusCode, value)
	case "body_length":
		value, err := strconv.Atoi(rule.Value)
		return err == nil && dataCheckInt(rule.Op, web.ContentLength, value)
	case "content_type":
		return dataCheckString(rule.Op, web.ContentType, rule.ValueLC)
	case "banner":
		return dataCheckString(rule.Op, web.Banner, rule.ValueLC)
	}
	return false
}

func fingerHasRuleKey(finger FingerEntity, key string) bool {
	for _, rule := range finger.Rule {
		if strings.EqualFold(rule.Key, key) || (key == "js_body" && strings.EqualFold(rule.Key, "js")) {
			return true
		}
	}
	return false
}

func isJSBodyRule(rule RuleData) bool {
	return strings.EqualFold(rule.Key, "js_body") || strings.EqualFold(rule.Key, "js")
}

func (s *FingerScanner) GetJSRedirectResponse(u *url.URL, respRaw string) []byte {
	var nextCheckUrl string
	newPath := checkJSRedirect(respRaw)
	// 跳转到ie.html需要忽略，fix in v1.7.5
	if newPath == "" || newPath == "/html/ie.html" {
		return nil
	}
	newPath = strings.Trim(newPath, " ")
	newPath = strings.Trim(newPath, "'")
	newPath = strings.Trim(newPath, "\"")
	if strings.HasPrefix(newPath, "https://") || strings.HasPrefix(newPath, "http://") {
		if strings.Contains(newPath, u.Host) {
			nextCheckUrl = newPath
		}
	} else {
		if len(newPath) > 0 {
			if newPath[0] == '/' {
				newPath = newPath[1:]
			}
		}
		nextCheckUrl = getRealPath(u.Scheme+"://"+u.Host) + "/" + newPath

	}
	resp, err := clients.SimpleGet(nextCheckUrl, s.client)
	if err != nil {
		return nil
	}
	return resp.Body()
}

func (s *FingerScanner) shiroProbeRequest(u *url.URL) (*resty.Response, error) {
	if u == nil {
		return nil, nil
	}
	shiroHeader := map[string]string{
		"Cookie": "rememberMe=true",
	}
	return clients.DoRequest("GET", u.String(), shiroHeader, nil, 10, s.client)
}

// ShiroScan sends the same invalid rememberMe cookie used by Shiro's standard
// clearing behavior and returns every Set-Cookie header as raw header lines.
func (s *FingerScanner) ShiroScan(u *url.URL) []byte {
	resp, err := s.shiroProbeRequest(u)
	if err != nil || resp == nil {
		return nil
	}

	var rawHeaders []byte
	for _, cookie := range resp.Header().Values("Set-Cookie") {
		rawHeaders = append(rawHeaders, "Set-Cookie: "...)
		rawHeaders = append(rawHeaders, cookie...)
		rawHeaders = append(rawHeaders, '\n')
	}
	return rawHeaders
}

// 探测Fastjson
// {"\u+040\u+074\u+079\u+070\u+065":"java.lang.AutoCloseabl\u+065" unicode 绕过 waf
func (s *FingerScanner) FastjsonScan(u *url.URL) bool {
	jsonHeader := map[string]string{
		"Content-Type": "application/json",
	}
	resp, err := clients.DoRequest("POST", u.String(), jsonHeader, strings.NewReader(`{"\u+040\u+074\u+079\u+070\u+065":"java.lang.AutoCloseabl\u+065"`), 10, s.client)
	if err != nil {
		return false
	}
	return bytes.Contains(resp.Body(), []byte("fastjson-version"))
}

// parseHeadersToMap 解析请求头为map格式
func parseHeadersToMap(customHeaders string, headersList []string) map[string]string {
	headers := make(map[string]string)

	// 先处理字符串格式的自定义请求头
	if customHeaders != "" {
		lines := strings.Split(customHeaders, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// 解析 "Key: Value" 格式
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if key != "" {
					headers[key] = value
				}
			}
		}
	}

	// 再处理列表格式的请求头
	for _, header := range headersList {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		// 解析 "Key: Value" 格式
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" {
				headers[key] = value
			}
		}
	}

	return headers
}

// 排除干扰结果，主要是云防护或者WAF等内容

func excludeInterference(statusCode int, title string) (bool, string) {
	if strings.Contains(title, "阿里云 Web应用防火墙") && statusCode == 410 {
		return true, "阿里云 Web应用防火墙"
	}

	if statusCode == 422 {
		return true, "CDN防护"
	}

	if statusCode == 418 {
		return true, "WAF防护"
	}

	return false, ""
}
