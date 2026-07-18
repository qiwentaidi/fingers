package fingers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/qiwentaidi/fingers/internal/logger"
)

const (
	screenshotTimeout          = 30 * time.Second
	screenshotRetryTime        = 1
	defaultScreenshotMaxTabs   = 10
	screenshotInitTimeout      = 60 * time.Second
	dynamicCaptureInitialWait  = 4 * time.Second
	dynamicCaptureTimeout      = 20 * time.Second
	maxCapturedAPIResponses    = 12
	maxCapturedAPIResponseSize = 512 * 1024
)

type capturedAPIResponse struct {
	URL  string
	Body []byte
}

// pageLoadCapture records data produced by one automatic page load. The
// capture never clicks, types, scrolls, submits forms, or invokes page code.
type pageLoadCapture struct {
	RequestURLs  []string
	DOMURLs      []string
	APIResponses []capturedAPIResponse
}

type screenshotBrowser struct {
	allocCancel   context.CancelFunc
	browserCancel context.CancelFunc
	browserCtx    context.Context
	tempDir       string
	tabSlots      chan struct{}
}

func newScreenshotBrowser(parent context.Context, maxTabs int, proxy string) (*screenshotBrowser, error) {
	if maxTabs <= 0 {
		maxTabs = 1
	}

	tempDir, err := os.MkdirTemp("", "chromedp-runner-*")
	if err != nil {
		return nil, fmt.Errorf("创建 chromedp 临时目录失败: %w", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(tempDir),
		chromedp.WSURLReadTimeout(screenshotInitTimeout),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),

		// HTTPS / 扫描目标必备
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-insecure-localhost", true),
		chromedp.Flag("disable-web-security", true),

		// 减少后台资源占用
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
	)
	// Windows requires a process creation attribute to prevent the Chrome
	// subprocess from briefly showing an empty window during startup.
	opts = append(opts, screenshotBrowserPlatformOptions()...)
	if strings.TrimSpace(proxy) != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}

	allocCtx, cancelAllocator := chromedp.NewExecAllocator(parent, opts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)

	if err := chromedp.Run(browserCtx); err != nil {
		cancelBrowser()
		cancelAllocator()
		_ = os.RemoveAll(tempDir)
		return nil, enrichChromedpStartError(err)
	}

	return &screenshotBrowser{
		allocCancel:   cancelAllocator,
		browserCancel: cancelBrowser,
		browserCtx:    browserCtx,
		tempDir:       tempDir,
		tabSlots:      make(chan struct{}, maxTabs),
	}, nil
}

func (b *screenshotBrowser) CaptureNetworkURLs(ctx context.Context, targetURL string) ([]string, error) {
	capture, err := b.CapturePageLoad(ctx, targetURL)
	return capture.RequestURLs, err
}

// CapturePageLoad collects requests, rendered links, and bounded JSON response
// bodies emitted during the initial navigation of targetURL.
func (b *screenshotBrowser) CapturePageLoad(ctx context.Context, targetURL string) (pageLoadCapture, error) {
	result := pageLoadCapture{}
	pageURL, pageURLErr := url.Parse(targetURL)
	if pageURLErr != nil {
		return result, pageURLErr
	}
	if b == nil || b.browserCtx == nil {
		return result, fmt.Errorf("headless browser is not initialized")
	}
	select {
	case b.tabSlots <- struct{}{}:
	case <-ctx.Done():
		return result, ctx.Err()
	}
	defer func() { <-b.tabSlots }()

	tabCtx, cancelTab := chromedp.NewContext(b.browserCtx)
	defer cancelTab()
	captureCtx, cancelCapture := context.WithTimeout(tabCtx, dynamicCaptureTimeout)
	defer cancelCapture()

	seen := make(map[string]struct{})
	responseRequests := make(map[network.RequestID]string)
	finishedResponses := make(map[network.RequestID]struct{})
	var mu sync.Mutex
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch event := ev.(type) {
		case *network.EventRequestWillBeSent:
			if event == nil || event.Request == nil || !isHTTPURL(event.Request.URL) {
				return
			}
			mu.Lock()
			if _, exists := seen[event.Request.URL]; !exists {
				seen[event.Request.URL] = struct{}{}
				result.RequestURLs = append(result.RequestURLs, event.Request.URL)
			}
			mu.Unlock()
		case *network.EventResponseReceived:
			if event == nil || event.Response == nil || !isHTTPURL(event.Response.URL) || !isLikelyAPIResponse(event.Response.URL, event.Response.MimeType) {
				return
			}
			responseURL, parseErr := url.Parse(event.Response.URL)
			if parseErr != nil || !sameContextURL(pageURL, responseURL) {
				return
			}
			mu.Lock()
			if len(responseRequests) < maxCapturedAPIResponses {
				responseRequests[event.RequestID] = event.Response.URL
			}
			mu.Unlock()
		case *network.EventLoadingFinished:
			if event == nil {
				return
			}
			mu.Lock()
			if _, tracked := responseRequests[event.RequestID]; tracked {
				finishedResponses[event.RequestID] = struct{}{}
			}
			mu.Unlock()
		}
	})

	var domURLs []string
	err := chromedp.Run(captureCtx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(dynamicCaptureInitialWait),
		chromedp.Evaluate(`(() => {
			const values = [];
			document.querySelectorAll('a[href],area[href],iframe[src],frame[src],link[rel="canonical"][href]').forEach((node) => {
				values.push(node.href || node.src);
			});
			document.querySelectorAll('meta[http-equiv="refresh" i]').forEach((node) => {
				const match = (node.content || '').match(/(?:^|;)\s*url\s*=\s*(.+)$/i);
				if (match) values.push(match[1].trim().replace(/^['"]|['"]$/g, ''));
			});
			return values.filter(Boolean);
		})()`, &domURLs),
	)
	mu.Lock()
	requestIDs := make([]network.RequestID, 0, len(finishedResponses))
	for requestID := range finishedResponses {
		requestIDs = append(requestIDs, requestID)
	}
	mu.Unlock()
	for _, requestID := range requestIDs {
		var body []byte
		bodyErr := chromedp.Run(captureCtx, chromedp.ActionFunc(func(actionCtx context.Context) error {
			var err error
			body, err = network.GetResponseBody(requestID).Do(actionCtx)
			return err
		}))
		if bodyErr != nil || len(body) == 0 || len(body) > maxCapturedAPIResponseSize {
			continue
		}
		mu.Lock()
		responseURL := responseRequests[requestID]
		mu.Unlock()
		result.APIResponses = append(result.APIResponses, capturedAPIResponse{URL: responseURL, Body: body})
	}
	result.DOMURLs = domURLs
	return result, err
}

func isJSONMIMEType(mimeType string) bool {
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	return strings.Contains(mimeType, "json") || strings.HasSuffix(mimeType, "+json")
}

func isLikelyAPIResponse(rawURL string, mimeType string) bool {
	if isJSONMIMEType(mimeType) {
		return true
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	return strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/rest/") || strings.HasPrefix(path, "/service/")
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
}

func (b *screenshotBrowser) Close() error {
	if b == nil {
		return nil
	}
	if b.browserCancel != nil {
		b.browserCancel()
	}
	if b.allocCancel != nil {
		b.allocCancel()
	}
	if b.tempDir == "" {
		return nil
	}
	return os.RemoveAll(b.tempDir)
}

func enrichChromedpStartError(err error) error {
	base := fmt.Errorf("启动 chromedp 失败: %w", err)
	if !isChromeExecutableMissing(err) {
		return base
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w；未找到 Chrome/Chromium 浏览器，请安装后重试", base)
	}
	return fmt.Errorf(
		"%w；Linux 环境未找到 Chrome/Chromium 浏览器，请先安装后重试，例如 Debian/Ubuntu: `sudo apt-get install -y chromium`，CentOS/RHEL/Fedora: `sudo yum install -y chromium`，Alpine: `sudo apk add chromium`；如果已安装到自定义位置，请将其加入 PATH 或创建软链接",
		base,
	)
}

func isChromeExecutableMissing(err error) bool {
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
		return true
	}
	return strings.Contains(err.Error(), "executable file not found")
}

// GetScreenshot 对指定 URL 截图并保存
func (s *FingerScanner) captureScreenshot(ctx context.Context, targetURL string) (string, error) {
	if s.screenshotBrowser == nil {
		return "", fmt.Errorf("screenshot browser is not initialized")
	}
	return s.screenshotBrowser.Capture(ctx, targetURL, s.screenshotStore, s.shouldReportScreenshotDiagnostics())
}

func (b *screenshotBrowser) Capture(ctx context.Context, targetURL string, store assetStore, enableLog bool) (string, error) {
	baseName := renameOutput(targetURL)
	objectName := baseName + ".webp"

	var buf []byte
	var lastErr error

	for attempt := 1; attempt <= screenshotRetryTime; attempt++ {
		select {
		case b.tabSlots <- struct{}{}:
		case <-ctx.Done():
			return "", ctx.Err()
		}

		tabCtx, cancelTab := chromedp.NewContext(b.browserCtx)
		tabCtx, cancelTimeout := context.WithTimeout(tabCtx, screenshotTimeout)

		lastErr = chromedp.Run(tabCtx,
			chromedp.EmulateViewport(1366, 768),
			chromedp.Navigate(targetURL),
			chromedp.WaitReady("body", chromedp.ByQuery),
			chromedp.Sleep(2*time.Second),
			chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				buf, err = page.CaptureScreenshot().
					WithFormat(page.CaptureScreenshotFormatWebp).
					Do(ctx)
				return err
			}),
		)

		cancelTimeout()
		cancelTab()
		<-b.tabSlots

		if lastErr == nil {
			location, err := store.Save(ctx, objectName, buf)
			if err != nil {
				return "", err
			}
			// gologger.Info().Msgf("[screenshot] captured %s -> %s", targetURL, location)
			return location, nil
		}

		if enableLog {
			logger.Default.Warning("[screenshot] attempt %d failed for %s: %v", attempt, targetURL, lastErr)
		}
		time.Sleep(1 * time.Second)
	}

	return "", fmt.Errorf("截图失败: %v", lastErr)
}

// sanitizeFilename 清理 URL 生成安全文件名
func renameOutput(name string) string {
	// 先对链接进行URL解码，避免%2D等字符导致前端解析出错
	if decoded, err := url.QueryUnescape(name); err == nil {
		name = decoded
	}
	name = strings.ReplaceAll(name, "https://", "")
	name = strings.ReplaceAll(name, "http://", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "?", "_")
	name = strings.ReplaceAll(name, "&", "_")
	return name
}
