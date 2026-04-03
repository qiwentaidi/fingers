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
    fingers.WithDefaultOutput(false),
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

// 保留 callback，自行处理输出时，建议关闭 SDK 默认扫描日志。
```

## 提取命中内容

指纹规则除了 `rule` 命中判断外，还支持 `extract` 提取匹配内容。提取只会在该指纹命中后执行。

```yaml
- name: 发现供应链
  description: 提取页面中的供应链标识
  rule:
    - body="技术支持"
  extract:
    - name: support_text
      from: body
      regex: "(技术支持[^<\\n]{0,80})"
```

说明：

- `from` 目前支持：`body`、`header`、`title`、`server`、`cert`、`path`、`content_type`、`banner`
- `regex` 如果带捕获组，优先返回第一个捕获组
- `regex` 如果不带捕获组，则返回整个命中字符串
- 提取使用扫描阶段已经转为小写的内容源，行为与规则匹配保持一致

提取结果会出现在 `result.Fingerprints[i].Extractions` 中。

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
