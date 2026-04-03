package fingers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/qiwentaidi/fingers/internal/cdncheck"
	"github.com/qiwentaidi/fingers/internal/logger"

	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
	httputil "github.com/qiwentaidi/utils/http"
	randutil "github.com/qiwentaidi/utils/rand"

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
	HeadeString   string
	ContentType   string
	Server        string
	ContentLength int
	Banner        string // tcp指纹ß
	Cert          string // TLS证书
}

type FingerScanner struct {
	urls                []*url.URL
	fingerprintRepo     *FingerprintRepository
	aliveURLs           []*url.URL // 默认指纹扫描结束后，存活的URL，以便后续主动指纹过滤目标
	activeTimeoutLimit  int        // 主动指纹扫描超时超过该次数就不再扫描该目标
	thread              int        // 指纹线程
	deepScan            bool       // 代表主动指纹探测
	rootPath            bool       // 主动指纹是否采取根路径扫描
	screenshot          bool       // 是否截屏
	enableAssetTagProbe bool
	enableDefaultOutput bool
	headers             map[string]string // 请求头
	client              *resty.Client
	notFollowClient     *resty.Client
	faviconStore        assetStore
	screenshotStore     assetStore
	// dnsxClient              *dnsx.DNSX
	basicURLWithFingerprint map[string][]string // 后续nuclei需要扫描的目标列表
	mutex                   sync.RWMutex
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
		urls:                    urls,
		fingerprintRepo:         repo,
		client:                  clients.NewRestyClientWithProxy(nil, true, options.Proxy),
		notFollowClient:         clients.NewRestyClientWithProxy(nil, false, options.Proxy),
		thread:                  options.Thread,
		deepScan:                options.DeepScan,
		rootPath:                options.RootPath,
		activeTimeoutLimit:      options.ActiveTimeoutLimit,
		screenshot:              options.EnableScreenshot,
		enableAssetTagProbe:     options.EnableAssetTagProbe,
		enableDefaultOutput:     !options.DisableDefaultOutput,
		faviconStore:            faviconStore,
		screenshotStore:         screenshotStore,
		basicURLWithFingerprint: basicURLWithFingerprint,
		headers:                 parseHeadersToMap(options.CustomHeaders, options.Headers),
	}
}

func (s *FingerScanner) shouldPrintDefaultOutput() bool {
	return s != nil && s.enableDefaultOutput
}

func (s *FingerScanner) fingerprintLabel(name string) string {
	return logger.WithDescription(name, s.fingerprintRepo.DescriptionByName(name))
}

func (s *FingerScanner) formatDefaultFingerprintOutput(pr Result) string {
	var fingerprintDisplay []string
	if pr.AssetTags.AssetType != "" || pr.AssetTags.ProductName != "" {
		fingerprintDisplay = append(fingerprintDisplay, pr.AssetTags.AssetType+": "+pr.AssetTags.ProductName)
	}
	for _, fp := range pr.Fingerprints {
		fingerprintDisplay = append(fingerprintDisplay, logger.Title(s.fingerprintLabel(fp)))
	}
	for _, fp := range pr.HighRiskFingerprints {
		fingerprintDisplay = append(fingerprintDisplay, logger.Red(s.fingerprintLabel(fp)))
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

// FingerScan 执行指纹扫描
func (s *FingerScanner) FingerScan(ctrlCtx context.Context, callback ResultCallback) {
	var wg sync.WaitGroup
	single := make(chan struct{})
	count := len(s.urls)
	retChan := make(chan Result, count)
	var id int32
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
				s.logScanResult("Finger", pr)
				// 调用回调函数前再次检查 context
				if callback != nil && ctrlCtx.Err() == nil {
					callback(pr)
				}
			}
			s.IncreaseActiveProgress(&id, count)
		}
		close(single)
	}()
	// 指纹扫描
	fscan := func(u *url.URL) {
		// 在函数入口检查 context
		if ctrlCtx.Err() != nil {
			return
		}

		// 非web资产目标将其直接绑定到后续漏洞扫描的目标组中，跳过后续的指纹扫描
		if u.Scheme != "http" && u.Scheme != "https" {
			s.basicURLWithFingerprint[u.String()] = append(s.basicURLWithFingerprint[u.String()], u.Scheme)
			return
		}

		var (
			rawHeaders  []byte
			server      string
			contentType string
			statusCode  int
		)

		// 先进行一次不会重定向的扫描，可以获得重定向前页面的响应头中获取指纹
		resp, err := clients.DoRequest("GET", u.String(), s.headers, nil, 10, s.notFollowClient)
		if err == nil && resp.StatusCode() == 302 {
			rawHeaders = httputil.DumpResponseHeadersOnly(resp.RawResponse)
		}

		// 在网络请求后检查 context
		if ctrlCtx.Err() != nil {
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
				return
			}
		}

		body := httputil.LimitResponseBytes(resp.Body(), maxInfoReponseSize)
		if resp != nil && resp.RawResponse != nil {
			// 合并请求头数据, fix 0.1.0 raw.RawResponse 可能为 nil 导致的崩溃
			rawHeaders = append(rawHeaders, httputil.DumpResponseHeadersOnly(resp.RawResponse)...)
		}

		// 在执行额外扫描前检查 context
		if ctrlCtx.Err() != nil {
			return
		}

		// 请求Logo并保存到本地
		faviconResult := getFaviconWithStorage(u, s.headers, s.client, s.faviconStore)

		// 发送shiro探测
		rawHeaders = append(rawHeaders, fmt.Appendf(nil, "Set-Cookie: %s", s.ShiroScan(u))...)

		// 跟随JS重定向，并替换成重定向后的数据
		redirectBody := s.GetJSRedirectResponse(u, string(body))
		if redirectBody != nil {
			// JS重定向后，body数据不应该直接覆盖 fix in 2.0.8
			body = append(body, redirectBody...)
			// body = redirectBody
		}
		// 网站正常响应
		title := clients.GetTitle(body)
		statusCode = resp.StatusCode()

		if exclude, _ := excludeInterference(statusCode, title); exclude {
			return
		}

		server = resp.Header().Get("Server")
		contentType = resp.Header().Get("Content-Type")
		web := &WebInfo{
			HeadeString:   strings.ToLower(string(rawHeaders)),
			ContentType:   strings.ToLower(contentType),
			Cert:          strings.ToLower(GetTLSString(u.Scheme, u.Host)),
			BodyString:    strings.ToLower(string(body)),
			Path:          strings.ToLower(u.Path),
			Title:         strings.ToLower(title),
			Server:        strings.ToLower(server),
			ContentLength: len(resp.Body()),
			Port:          httputil.GetPort(u),
			IconHash:      faviconResult.Mmh3Hash,
			IconMd5:       faviconResult.Md5Hash,
			StatusCode:    statusCode,
		}

		var assets *Tag
		if s.enableAssetTagProbe {
			if detected, ok := cdncheck.Detect(u.Hostname()); ok {
				assets = &Tag{
					ProductName: detected.ProductName,
					AssetType:   detected.AssetType,
					Source:      detected.Source,
				}
			}
		}

		s.aliveURLs = append(s.aliveURLs, u)

		fingerprints, highRiskFingerprints, vulnFingerprints := Scan(web, s.fingerprintRepo.GetFingerprintDB())

		// if s.FastjsonScan(u) {
		// 	fingerprints = append(fingerprints, "Fastjson")
		// }

		if checkHoneypotWithHeaders(web.HeadeString) {
			fingerprints = []string{"疑似蜜罐"}
		}

		// 在截屏前检查 context（截屏是耗时操作）
		if ctrlCtx.Err() != nil {
			return
		}

		// 截屏
		var screenshotPath string
		if s.screenshot && (u.Scheme == "https" || u.Scheme == "http") {
			if screenshotPath, err = captureScreenshot(ctrlCtx, u.String(), s.screenshotStore, s.shouldPrintDefaultOutput()); err != nil {
				if s.shouldPrintDefaultOutput() {
					logger.Default.Warning("%s 截屏失败: %v", u.String(), err)
				}
			}
		}

		s.mutex.Lock()
		// 合并普通指纹和高危指纹（用于后续 Nuclei 扫描的标签）
		allFingerprints := arrayutil.RemoveDuplicates(append(fingerprints, highRiskFingerprints...))
		s.basicURLWithFingerprint[u.String()] = append(s.basicURLWithFingerprint[u.String()], allFingerprints...)
		s.mutex.Unlock()

		result := Result{
			URL:                  u.String(),
			Scheme:               u.Scheme,
			Host:                 u.Host,
			Port:                 web.Port,
			StatusCode:           web.StatusCode,
			Length:               web.ContentLength,
			Title:                title,
			Fingerprints:         fingerprints,         // 普通指纹（单独存储）
			HighRiskFingerprints: highRiskFingerprints, // 高危指纹（单独存储）
			VulnFingerprints:     vulnFingerprints,     // ⚠️ 漏洞指纹（单独存储）
			Detect:               "Default",
			Screenshot:           screenshotPath,
			Favicon:              faviconResult.FilePath, // favicon图片路径
		}

		if assets != nil {
			result.AssetTags = *assets
		}

		retChan <- result
	}
	threadPool, _ := ants.NewPoolWithFunc(s.thread, func(target interface{}) {
		defer wg.Done()
		if ctrlCtx.Err() != nil {
			return
		}
		fscan(target.(*url.URL))
	})
	defer threadPool.Release()
	for _, target := range s.urls {
		if ctrlCtx.Err() != nil {
			return
		}
		wg.Add(1)
		threadPool.Invoke(target)
	}
	wg.Wait()
	close(retChan)
	<-single
}

type ActiveFingerDetect struct {
	URL  *url.URL
	Fpe  []FingerEntity
	Path string
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

	var id int32
	var wg sync.WaitGroup
	visited := sync.Map{}        // 记录已访问路径
	timeoutCounter := sync.Map{} // 记录每个目标的超时次数
	single := make(chan struct{})
	retChan := make(chan Result, len(s.urls))

	go func() {
		for pr := range retChan {
			// 检查任务是否被取消
			if ctx.Err() != nil {
				if s.shouldPrintDefaultOutput() {
					logger.Default.Info("主动指纹扫描结果处理已取消")
				}
				break
			}
			s.logScanResult("Active", pr)
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

		// 在 goroutine 中检查 context
		if ctx.Err() != nil {
			return
		}

		fp := tfp.(ActiveFingerDetect)
		fullURL := fp.URL.String() + fp.Path
		baseURL := fp.URL.String()

		if val, ok := timeoutCounter.Load(baseURL); ok && val.(int) >= s.activeTimeoutLimit {
			if s.shouldPrintDefaultOutput() {
				logger.Default.Warning("Target %s has reached the timeout limit, skipping active scan", baseURL)
			}
			return
		}

		if _, ok := visited.Load(fullURL); ok {
			return
		}
		visited.Store(fullURL, true)

		resp, err := clients.DoRequest("GET", fullURL, s.headers, nil, 5, s.client)
		if err != nil {
			v, _ := timeoutCounter.LoadOrStore(baseURL, 1)
			timeoutCounter.Store(baseURL, v.(int)+1)
			return
		}

		// 在处理响应前检查 context
		if ctx.Err() != nil {
			return
		}

		body := resp.Body()
		server := resp.Header().Get("Server")
		contentType := resp.Header().Get("Content-Type")
		title := clients.GetTitle(body)

		headers, _, _ := httputil.DumpResponseHeadersAndRaw(resp.RawResponse)
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
		}
		result, highRiskResult, vulnResult := Scan(ti, fp.Fpe)

		if len(result) > 0 || len(highRiskResult) > 0 || len(vulnResult) > 0 {
			// 截屏
			var screenshotPath string
			if s.screenshot && (fp.URL.Scheme == "https" || fp.URL.Scheme == "http") {
				if screenshotPath, err = captureScreenshot(ctx, fullURL, s.screenshotStore, s.shouldPrintDefaultOutput()); err != nil {
					if s.shouldPrintDefaultOutput() {
						logger.Default.Warning("%s 截屏失败: %v", fp.URL.String(), err)
					}
				}
			}

			// 在保存结果前检查 context
			if ctx.Err() != nil {
				return
			}

			s.mutex.Lock()
			s.basicURLWithFingerprint[fp.URL.String()] = append(s.basicURLWithFingerprint[fp.URL.String()], result...)
			s.basicURLWithFingerprint[fp.URL.String()] = append(s.basicURLWithFingerprint[fp.URL.String()], highRiskResult...)
			s.mutex.Unlock()

			retChan <- Result{
				URL:                  fullURL,
				StatusCode:           ti.StatusCode,
				Length:               ti.ContentLength,
				Title:                title,
				Fingerprints:         result,         // 主动扫描时合并显示（已去重）
				HighRiskFingerprints: highRiskResult, // 高危指纹（单独存储）
				VulnFingerprints:     vulnResult,     // ⚠️ 漏洞指纹（单独存储）
				Detect:               "Active",
				Port:                 ti.Port,
				Scheme:               fp.URL.Scheme,
				Host:                 fp.URL.Host,
				Screenshot:           screenshotPath,
			}
		}
	})
	defer threadPool.Release()

	count := s.ActiveCounts()

	activePathMap := groupActiveFingerprintsByPath(s.fingerprintRepo.GetActiveFingerprintDB())
	for _, target := range s.aliveURLs {
		// 在外层循环检查 context
		if ctx.Err() != nil {
			if s.shouldPrintDefaultOutput() {
				logger.Default.Info("主动指纹扫描已取消，停止提交新任务")
			}
			break
		}

		for path, fingers := range activePathMap {
			// 在内层循环也检查 context
			if ctx.Err() != nil {
				break
			}

			base := target.String()
			if val, ok := timeoutCounter.Load(base); ok && val.(int) >= s.activeTimeoutLimit {
				s.IncreaseActiveProgress(&id, count)
				continue
			}

			wg.Add(1)
			s.IncreaseActiveProgress(&id, count)
			activeTarget := target
			if s.rootPath {
				activeTarget, _ = url.Parse(httputil.GetBasicURL(target.String()))
			}

			threadPool.Invoke(ActiveFingerDetect{
				URL:  activeTarget,
				Fpe:  fingers,
				Path: path,
			})
		}
	}

	wg.Wait()
	close(retChan)
	<-single
}

// 统计主动指纹总共要扫描的目标
func (s *FingerScanner) ActiveCounts() int {
	activePathMap := groupActiveFingerprintsByPath(s.fingerprintRepo.GetActiveFingerprintDB())
	count := len(s.aliveURLs) * len(activePathMap)
	return count
}

func (s *FingerScanner) IncreaseActiveProgress(id *int32, total int) {
	if !s.shouldPrintDefaultOutput() {
		return
	}
	current := atomic.AddInt32(id, 1)
	logger.Default.PrintRaw("\r[%d / %d]", current, total)
	if current == int32(total) {
		logger.Default.PrintRaw("\n")
	}
}

func (s *FingerScanner) URLWithFingerprintMap() map[string][]string {
	return s.basicURLWithFingerprint
}

// Scan 扫描指纹，返回：普通指纹、高危指纹、漏洞指纹（带指纹详情）
func Scan(web *WebInfo, targetDB []FingerEntity) ([]string, []string, []VulnFingerprint) {
	var fingerPrintResults []string
	var highRiskFingerPrintResults []string
	// 用 map 去重漏洞指纹
	vulnMap := make(map[string]VulnFingerprint)

	for _, finger := range targetDB {
		expr := finger.AllString
		for _, rule := range finger.Rule {
			var result bool
			switch rule.Key {
			case "header":
				result = dataCheckString(rule.Op, web.HeadeString, rule.ValueLC)
			case "body":
				result = dataCheckString(rule.Op, web.BodyString, rule.ValueLC)
			case "server":
				result = dataCheckString(rule.Op, web.Server, rule.ValueLC)
			case "title":
				result = dataCheckString(rule.Op, web.Title, rule.ValueLC)
			case "cert":
				result = dataCheckString(rule.Op, web.Cert, rule.ValueLC)
			case "port":
				value, err := strconv.Atoi(rule.Value)
				if err == nil {
					result = dataCheckInt(rule.Op, web.Port, value)
				}
			case "protocol":
				result = (rule.Op == 0 && web.Protocol == rule.ValueLC) || (rule.Op == 1 && web.Protocol != rule.ValueLC)
			case "path":
				result = dataCheckString(rule.Op, web.Path, rule.ValueLC)
			case "icon_hash":
				value, err := strconv.Atoi(rule.Value)
				hashIcon, errHash := strconv.Atoi(web.IconHash)
				if err == nil && errHash == nil {
					result = dataCheckInt(rule.Op, hashIcon, value)
				}
			case "icon_mdhash":
				result = dataCheckString(rule.Op, web.IconMd5, rule.ValueLC)
			case "status":
				value, err := strconv.Atoi(rule.Value)
				if err == nil {
					result = dataCheckInt(rule.Op, web.StatusCode, value)
				}
			case "content_type":
				result = dataCheckString(rule.Op, web.ContentType, rule.ValueLC)
			case "banner":
				result = dataCheckString(rule.Op, web.Banner, rule.ValueLC)
			}

			if result {
				expr = expr[:rule.Start] + "T" + expr[rule.End:]
			} else {
				expr = expr[:rule.Start] + "F" + expr[rule.End:]
			}
		}

		r, err := boolEval(expr)
		if err != nil {
			logger.Default.Warning("[fingerprint] 错误指纹: %v", finger.AllString)
			continue
		}
		if r {
			// ⚠️ 新增：如果指纹标记为 Vuln，记录到漏洞指纹列表
			if finger.Vuln {
				if _, exists := vulnMap[finger.ProductName]; !exists {
					vulnMap[finger.ProductName] = VulnFingerprint{
						Name:        finger.ProductName,
						Description: finger.Description,
						MatchedRule: finger.AllString,
					}
				}
			}

			// 原有逻辑：分类到普通指纹或高危指纹
			if finger.HighRisk {
				highRiskFingerPrintResults = append(highRiskFingerPrintResults, finger.ProductName)
			} else {
				fingerPrintResults = append(fingerPrintResults, finger.ProductName)
			}
		}
	}

	// map → slice
	vulnFingerprintResults := make([]VulnFingerprint, 0, len(vulnMap))
	for _, v := range vulnMap {
		vulnFingerprintResults = append(vulnFingerprintResults, v)
	}

	return arrayutil.RemoveDuplicates(fingerPrintResults), arrayutil.RemoveDuplicates(highRiskFingerPrintResults), vulnFingerprintResults
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

// 探测shiro并返回响应头中的Set-Cookie值
func (s *FingerScanner) ShiroScan(u *url.URL) string {
	shiroHeader := map[string]string{
		"Cookie": fmt.Sprintf("JSESSIONID=%s;rememberMe=123", randutil.RandomStr(16)),
	}
	resp, err := clients.DoRequest("GET", u.String(), shiroHeader, nil, 10, s.client)
	if err != nil {
		return ""
	}
	return resp.Header().Get("Set-Cookie")
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
