package main

import (
	"context"
	"embed"
	"fmt"

	rootfingers "github.com/qiwentaidi/fingers"
	fingerssdk "github.com/qiwentaidi/fingers/lib"
)

const builtinFingerprintName = "static/finger.yaml"

//go:embed static/finger.yaml
var builtinFingerprintFS embed.FS

func BuiltinFingerprintOption() fingerssdk.FingersSDKOptions {
	return fingerssdk.WithFingerprintFS(builtinFingerprintFS, builtinFingerprintName)
}

func LoadBuiltinFingerprints() ([]rootfingers.FingerEntity, error) {
	return rootfingers.LoadFingerprintFromFS(builtinFingerprintFS, builtinFingerprintName)
}

func main() {
	ctx := context.Background()

	// 指纹扫描结果回调
	fingerprintCallback := func(result fingerssdk.Result) {
		// 检查 context 是否被取消
		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	options := []fingerssdk.FingersSDKOptions{
		// 设置指纹文件加载模式
		BuiltinFingerprintOption(),
		// 设置扫描线程
		fingerssdk.WithThread(50),
		fingerssdk.WithTargets("http://47.250.130.96/"),
		// 开启深度扫描
		fingerssdk.WithDeepScan(true),
		// 关闭网站截图
		fingerssdk.WithScreenshot(false),
		// 设置截图模式
		fingerssdk.WithAssetStorage(rootfingers.AssetStorageConfig{
			// 选择本地存储模式
			Mode: rootfingers.StorageModeLocal,
			// 设置存储路径
			Local: &rootfingers.LocalStorageConfig{
				BaseDir: "data",
			},
		}),
		// 开启资产标签探测
		fingerssdk.WithAssetTagProbe(true),
		// 设置主动次数最大失败次数
		fingerssdk.WithActiveTimeoutLimit(10),
		// 使用自定义 callback 时可设置关闭 SDK 默认输出
		// fingerssdk.WithDefaultOutput(false),
	}

	engine, err := fingerssdk.NewFingersEngineCtx(ctx, options...)

	if err != nil {
		fmt.Printf("Error creating fingers engine: %v\n", err)
		return
	}

	engine.Scan(ctx, fingerprintCallback)
}
