package fingers

import (
	"context"
	"io"
	"io/fs"
	"path"
	"strings"

	root "github.com/qiwentaidi/fingers"
)

// FingerEngine is the public SDK engine type.
type FingerEngine = root.FingerScanner

// FingersSDKOptions contains options for fingers SDK.
type FingersSDKOptions func(*root.Options) error

// ResultCallback is the result callback signature exported by the SDK entry package.
type ResultCallback = root.ResultCallback

// Re-export core configuration and result types for SDK users.
type (
	Options               = root.Options
	Result                = root.Result
	FingerprintMatch      = root.FingerprintMatch
	FingerprintExtraction = root.FingerprintExtraction
	Tag                   = root.Tag
	VulnFingerprint       = root.VulnFingerprint
	StorageMode           = root.StorageMode
	LocalStorageConfig    = root.LocalStorageConfig
	AliyunOSSConfig       = root.AliyunOSSConfig
	AssetStorageConfig    = root.AssetStorageConfig
)

const (
	StorageModeLocal     = root.StorageModeLocal
	StorageModeAliyunOSS = root.StorageModeAliyunOSS
)

// NewFingersEngineCtx creates a new fingers engine with SDK-style option funcs.
func NewFingersEngineCtx(ctx context.Context, options ...FingersSDKOptions) (*FingerEngine, error) {
	_ = ctx

	opts := root.Options{}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&opts); err != nil {
			return nil, err
		}
	}

	return root.NewScanner(opts)
}

// NewFingersEngine creates a new fingers engine using background context.
func NewFingersEngine(options ...FingersSDKOptions) (*FingerEngine, error) {
	return NewFingersEngineCtx(context.Background(), options...)
}

func WithTargets(targets ...string) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.Targets = append(opts.Targets, targets...)
		return nil
	}
}

func WithThread(thread int) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.Thread = thread
		return nil
	}
}

func WithHeaders(headers ...string) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.Headers = append(opts.Headers, headers...)
		return nil
	}
}

func WithCustomHeaders(headers string) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.CustomHeaders = headers
		return nil
	}
}

func WithProxy(proxy string) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.Proxy = proxy
		return nil
	}
}

func WithDeepScan(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.DeepScan = enabled
		return nil
	}
}

func WithRootPath(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.RootPath = enabled
		return nil
	}
}

func WithActiveTimeoutLimit(limit int) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.ActiveTimeoutLimit = limit
		return nil
	}
}

func WithScreenshot(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.EnableScreenshot = enabled
		return nil
	}
}

// WithScreenshotDiagnostics enables browser startup and screenshot failure logs
// without enabling the scanner's normal result output.
func WithScreenshotDiagnostics(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.ScreenshotDiagnostics = enabled
		return nil
	}
}

func WithAssetTagProbe(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.EnableAssetTagProbe = enabled
		return nil
	}
}

func WithRawResponse(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.EnableRawResponse = enabled
		return nil
	}
}

func WithDefaultOutput(enabled bool) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.DisableDefaultOutput = !enabled
		return nil
	}
}

func WithLogOutput(w io.Writer) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.LogOutput = w
		return nil
	}
}

func WithFingerprintBytes(data []byte) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.FingerprintData = append([]byte(nil), data...)
		opts.FingerprintPath = ""
		opts.FingerprintFS = nil
		opts.FingerprintFSName = ""
		return nil
	}
}

func WithFingerprintFile(path string) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.FingerprintData = nil
		opts.FingerprintPath = path
		opts.FingerprintFS = nil
		opts.FingerprintFSName = ""
		return nil
	}
}

func WithFingerprintFS(fsys fs.FS, name string) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.FingerprintData = nil
		opts.FingerprintPath = ""
		opts.FingerprintFS = fsys
		opts.FingerprintFSName = name
		return nil
	}
}

func WithAssetStorage(storage root.AssetStorageConfig) FingersSDKOptions {
	return func(opts *root.Options) error {
		opts.FaviconStorage = appendAssetStorageSuffix(storage, "favicon")
		opts.ScreenshotStorage = appendAssetStorageSuffix(storage, "screenshot")
		return nil
	}
}

func appendAssetStorageSuffix(storage root.AssetStorageConfig, suffix string) root.AssetStorageConfig {
	next := storage

	if storage.Local != nil {
		local := *storage.Local
		local.BaseDir = joinStoragePath(local.BaseDir, suffix)
		local.PublicBaseURL = joinStorageURL(local.PublicBaseURL, suffix)
		next.Local = &local
	}

	if storage.AliyunOSS != nil {
		oss := *storage.AliyunOSS
		oss.Prefix = joinStoragePath(oss.Prefix, suffix)
		oss.PublicBaseURL = joinStorageURL(oss.PublicBaseURL, suffix)
		next.AliyunOSS = &oss
	}

	return next
}

func joinStoragePath(base string, suffix string) string {
	if base == "" {
		return suffix
	}
	return path.Join(base, suffix)
}

func joinStorageURL(base string, suffix string) string {
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(suffix, "/")
}
