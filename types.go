package fingers

import "io/fs"

type Tag struct {
	ProductName string
	AssetType   string
	Source      string
}

type VulnFingerprint struct {
	Name        string
	Description string
	MatchedRule string
}

type Result struct {
	URL                  string
	Scheme               string
	Host                 string
	Port                 int
	StatusCode           int
	Length               int
	Title                string
	Fingerprints         []string
	HighRiskFingerprints []string
	VulnFingerprints     []VulnFingerprint
	AssetTags            Tag
	IsWAF                bool
	WAF                  string
	Detect               string
	Screenshot           string
	Favicon              string
}

type ResultCallback func(Result)

type StorageMode string

const (
	StorageModeLocal     StorageMode = "local"
	StorageModeAliyunOSS StorageMode = "aliyun_oss"
)

type LocalStorageConfig struct {
	BaseDir       string
	PublicBaseURL string
}

type AliyunOSSConfig struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	AccessKeySecret string
	Prefix          string
	PublicBaseURL   string
}

type AssetStorageConfig struct {
	Mode      StorageMode
	Local     *LocalStorageConfig
	AliyunOSS *AliyunOSSConfig
}

type Options struct {
	Targets              []string
	Thread               int
	TimeoutSeconds       int
	Headers              []string
	CustomHeaders        string
	Proxy                string
	DeepScan             bool
	RootPath             bool
	ActiveTimeoutLimit   int
	EnableScreenshot     bool
	EnableAssetTagProbe  bool
	DisableDefaultOutput bool
	FingerprintData      []byte
	FingerprintPath      string
	FingerprintFS        fs.FS
	FingerprintFSName    string
	FaviconStorage       AssetStorageConfig
	ScreenshotStorage    AssetStorageConfig
}
