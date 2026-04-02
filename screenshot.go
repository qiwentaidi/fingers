package fingers

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/projectdiscovery/gologger"
)

const (
	screenshotTimeout   = 30 * time.Second
	screenshotRetryTime = 2
)

func newScreenshotAllocator(parent context.Context) (context.Context, context.CancelFunc, string, error) {
	tempDir, err := os.MkdirTemp("", "chromedp-runner-*")
	if err != nil {
		return nil, nil, "", fmt.Errorf("创建 chromedp 临时目录失败: %w", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(tempDir),
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

	allocCtx, cancelAllocator := chromedp.NewExecAllocator(parent, opts...)
	return allocCtx, cancelAllocator, tempDir, nil
}

// GetScreenshot 对指定 URL 截图并保存
func captureScreenshot(ctx context.Context, targetURL string, store assetStore) (string, error) {
	baseName := renameOutput(targetURL)
	objectName := baseName + ".webp"

	var buf []byte
	var lastErr error

	for attempt := 1; attempt <= screenshotRetryTime; attempt++ {
		allocCtx, cancelAllocator, tempDir, err := newScreenshotAllocator(context.Background())
		if err != nil {
			return "", err
		}

		browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
		browserCtx, cancelTimeout := context.WithTimeout(browserCtx, screenshotTimeout)

		lastErr = chromedp.Run(browserCtx,
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
		cancelBrowser()
		cancelAllocator()
		if err := os.RemoveAll(tempDir); err != nil {
			gologger.Warning().Msgf("[screenshot] cleanup temp dir failed %s: %v", tempDir, err)
		}

		if lastErr == nil {
			location, err := store.Save(ctx, objectName, buf)
			if err != nil {
				return "", err
			}
			gologger.Info().Msgf("[screenshot] captured %s -> %s", targetURL, location)
			return location, nil
		}

		gologger.Warning().Msgf("[screenshot] attempt %d failed for %s: %v", attempt, targetURL, lastErr)
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
