# Fingerprint SDK

`fingers` 是一个独立的 Web 指纹识别 SDK，适合通过远程 GitHub 模块直接引入。SDK 本身不应绑定某个业务项目自己的 `finger.yaml` 文件。

主要能力：

- 被动指纹识别
- 主动路径指纹识别
- 主机名 token 派生路径探测
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

如果启用了 `screenshot` 截图能力，运行环境还需要安装 Chrome/Chromium，并确保浏览器可执行文件在 `PATH` 中。SDK 会尝试查找：

- `google-chrome`
- `google-chrome-stable`
- `chromium`
- `chromium-browser`
- `chrome`

Linux 常见安装方式示例：

```bash
# Debian / Ubuntu
sudo apt-get install -y chromium

# CentOS / RHEL / Fedora
sudo dnf install -y chromium

# Alpine
sudo apk add chromium
```

业务项目推荐通过正常的 Go module 方式引用：

```go
import fingers "github.com/qiwentaidi/fingers/lib"
```

## 命令行使用

仓库内置了 `cmd/fingerprint` 命令行程序，默认使用编译进二进制的 `cmd/fingerprint/static/finger.yaml` 指纹库。

直接运行：

```bash
go run ./cmd/fingerprint -u http://example.com
```

构建后运行：

```bash
go build -o fingerprint ./cmd/fingerprint
./fingerprint -u http://example.com
```

批量扫描目标文件：

```bash
go run ./cmd/fingerprint -l targets.txt
```

`targets.txt` 每行一个目标，空行和 `#` 开头的注释行会被忽略。

使用自定义指纹库：

```bash
go run ./cmd/fingerprint -u http://example.com -f /path/to/finger.yaml
```

### Verbose 响应包输出

加 `-v` 或 `--verbose` 后，命令会额外打印可用于指纹识别的字段，以及捕获到的完整 HTTP 响应包：

```bash
go run ./cmd/fingerprint -u 'https://example.com' -v
```

输出示例：

```text
[Default] https://example.com [200] [1256] [Example Domain] [Nginx]
===== FINGERPRINT FIELDS https://example.com =====
  status: 200
  server: nginx
  title: Example Domain
  content_type: text/html
  protocol: https
  host: example.com
  port: 443
  path: /
  length: 1256
  icon_hash: 0
  icon_md5:
  favicon_url: https://example.com/favicon.ico
===== END FINGERPRINT FIELDS https://example.com =====
===== RAW RESPONSE https://example.com =====
HTTP/1.1 200 OK
Content-Length: 1256
Content-Type: text/html
Server: nginx

<!DOCTYPE html>
...
===== END RAW RESPONSE https://example.com =====
```

说明：

- `FINGERPRINT FIELDS` 是程序当前支持识别和调试的字段摘要。
- `RAW RESPONSE` 是本次请求捕获到的完整响应头和响应体。
- CLI 不输出本地 `favicon_path`，只输出 `favicon_url` 和 hash 字段。
- favicon 和截图仍会按 `--storage-dir` 保存到本地，默认目录是 `data`；未开启 `--screenshot` 时只会跳过截图保存，favicon 仍会独立保存。

### 常用参数

| 参数 | 说明 |
| --- | --- |
| `-u, --url` | 目标 URL 或 host，可重复，也可用英文逗号分隔 |
| `-l, --list` | 目标文件路径，每行一个目标 |
| `-f, --fingerprint` | 自定义指纹 YAML 文件路径 |
| `-t, --thread` | 扫描并发数，默认 `50` |
| `-H, --header` | 自定义请求头，格式为 `Key: Value`，可重复 |
| `--headers` | 多行自定义请求头 |
| `--proxy` | HTTP/SOCKS 代理地址 |
| `--deep` | 开启主动路径指纹扫描、主机名 token 派生路径探测和 JS 上下文路径探测 |
| `--root-path` | 主动路径扫描时从站点根路径发起 |
| `--screenshot` | 开启截图 |
| `--asset-tag` | 开启 CDN/资产标签探测，默认开启 |
| `--active-timeout` | 主动扫描中单目标最大失败次数，默认 `10` |
| `--storage-dir` | favicon 和 screenshot 的本地保存目录，默认 `data` |
| `-v, --verbose` | 输出识别字段和完整 HTTP 响应包 |

主机名 token 派生路径探测仅在 `--deep` 深度扫描模式下开启，例如会从 `https://szzs.invest.beijing.gov.cn/` 自动探测 `/szzs/`。派生前缀本身即使未命中，也会继续组合主动指纹路径探测，例如 `/app/` + `/webroot/decision/login`。

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

截图开关只控制 screenshot 采集与保存，不影响 favicon。即使 SDK 中通过 `fingers.WithScreenshot(false)` 关闭截图，只要目标站点 favicon 请求成功，图标文件仍会按 favicon 存储配置落地，例如本地模式下保存到 `.../favicon`。

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
