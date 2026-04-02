# Fingerprint SDK

`fingers` 是一个独立的 Web 指纹识别 SDK，适合通过远程 GitHub 模块直接引入。SDK 本身不应绑定某个业务项目自己的 `finger.yaml` 文件。

主要能力：

- 被动指纹识别
- 主动路径指纹识别
- favicon 哈希计算与存储
- screenshot 截图与存储
- TLS 证书特征识别
- 本地目录 / 阿里云 OSS 统一资源存储
- 指纹规则从 `bytes`、文件路径、`fs.FS` 三种方式加载
- 由调用方决定规则来源，SDK 不强绑定业务规则文件

## 安装

```bash
go get github.com/qiwentaidi/fingers
```

业务项目推荐通过正常的 Go module 方式引用：

```go
import fingers "github.com/qiwentaidi/fingers/lib"
```

## 加载规则

SDK 的规则加载入口统一为三种：

1. 从字节加载

```go
rules, err := fingers.LoadFingerprintFromBytes(data)
```

2. 从文件路径加载

```go
rules, err := fingers.LoadFingerprintFromFile("/path/to/finger.yaml")
```

3. 从 `fs.FS` 加载

```go
//go:embed myfinger.yaml
var myFS embed.FS

rules, err := fingers.LoadFingerprintFromFS(myFS, "myfinger.yaml")
```

## 创建扫描引擎

最常见的用法是直接创建 SDK 引擎，不手动处理规则对象：

```go
engine, err := fingers.NewFingersEngine(
    fingers.WithTargets("https://example.com"),
    fingers.WithFingerprintFile("/path/to/finger.yaml"),
    fingers.WithThread(30),
    fingers.WithDeepScan(true),
    fingers.WithAssetStorage(fingers.AssetStorageConfig{
        Mode: fingers.StorageModeLocal,
        Local: &fingers.LocalStorageConfig{
            BaseDir: "data",
        },
    }),
)
```

然后执行扫描：

```go
err = engine.Scan(ctx, func(result fingers.Result) {
    fmt.Println(result.URL, result.Fingerprints)
})
```

## 规则来源配置

SDK 支持三种配置形式：

- `WithFingerprintBytes(data []byte)`
- `WithFingerprintFile(path string)`
- `WithFingerprintFS(fsys fs.FS, name string)`

这意味着：

- SDK 仓库可以独立发布到 GitHub
- 业务项目不需要依赖 SDK 仓库内部路径
- 调用方可以自己决定规则是来自本地配置、远端下载后内存加载，还是编译进二进制

## 资源存储

favicon 和 screenshot 使用统一入口：

```go
fingers.WithAssetStorage(...)
```

SDK 会自动派生出：

- `.../favicon`
- `.../screenshot`

本地存储示例：

```go
fingers.WithAssetStorage(fingers.AssetStorageConfig{
    Mode: fingers.StorageModeLocal,
    Local: &fingers.LocalStorageConfig{
        BaseDir:       "data",
        PublicBaseURL: "https://static.example.com/assets",
    },
})
```

阿里云 OSS 示例：

```go
fingers.WithAssetStorage(fingers.AssetStorageConfig{
    Mode: fingers.StorageModeAliyunOSS,
    AliyunOSS: &fingers.AliyunOSSConfig{
        Endpoint:        "oss-cn-hangzhou.aliyuncs.com",
        Bucket:          "your-bucket",
        AccessKeyID:     "xxx",
        AccessKeySecret: "xxx",
        Prefix:          "hephaestus/assets",
        PublicBaseURL:   "https://cdn.example.com/waswo",
    },
})
```

## 对业务项目的建议

如果 SDK 后续通过远程 GitHub 模块引入，业务项目自己的可编辑指纹文件不要再放在 SDK 仓库目录下读取，而应该放在业务自己的配置目录，例如：

- `config/finger.yaml`
- `/etc/your-app/finger.yaml`
- Docker 挂载目录
- 配置中心下发后写入本地文件

然后由业务项目自己选择：

- 用 `WithFingerprintFile(...)` 指向业务配置文件
- 用 `WithFingerprintBytes(...)` 加载远端拉取后的内容
- 用 `WithFingerprintFS(...)` 把规则编译进业务二进制

对于 Hephaestus 主项目，默认规则文件现在建议放在业务仓库自己的路径中，例如：

- `backend/pkg/webscan/static/finger.yaml`

然后由主项目自己通过 `WithFingerprintFS(...)` 或 `WithFingerprintFile(...)` 传给 SDK，而不是由 SDK 仓库内置。
