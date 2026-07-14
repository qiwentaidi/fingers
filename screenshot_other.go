//go:build !windows

package fingers

import "github.com/chromedp/chromedp"

func screenshotBrowserPlatformOptions() []chromedp.ExecAllocatorOption {
	return nil
}
