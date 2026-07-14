//go:build windows

package fingers

import (
	"os/exec"
	"syscall"

	"github.com/chromedp/chromedp"
)

// screenshotBrowserPlatformOptions prevents the Chrome child process from
// creating a visible window while it is running in headless mode.
func screenshotBrowserPlatformOptions() []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{
		chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		}),
	}
}
