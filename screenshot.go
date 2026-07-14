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
	screenshotTimeout         = 30 * time.Second
	screenshotRetryTime       = 1
	defaultScreenshotMaxTabs  = 10
	screenshotInitTimeout     = 60 * time.Second
	dynamicCaptureInitialWait = 4 * time.Second
	dynamicCaptureTimeout     = 20 * time.Second
)

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
	if b == nil || b.browserCtx == nil {
		return nil, fmt.Errorf("headless browser is not initialized")
	}
	select {
	case b.tabSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-b.tabSlots }()

	tabCtx, cancelTab := chromedp.NewContext(b.browserCtx)
	defer cancelTab()
	captureCtx, cancelCapture := context.WithTimeout(tabCtx, dynamicCaptureTimeout)
	defer cancelCapture()

	seen := make(map[string]struct{})
	urls := make([]string, 0)
	var mu sync.Mutex
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		request, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || request == nil || request.Request == nil || !isHTTPURL(request.Request.URL) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := seen[request.Request.URL]; exists {
			return
		}
		seen[request.Request.URL] = struct{}{}
		urls = append(urls, request.Request.URL)
	})

	if err := chromedp.Run(captureCtx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(dynamicCaptureInitialWait),
	); err != nil {
		return urls, err
	}
	return urls, nil
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
