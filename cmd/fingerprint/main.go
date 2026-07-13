package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	rootfingers "github.com/qiwentaidi/fingers"
	fingerssdk "github.com/qiwentaidi/fingers/lib"
	"github.com/urfave/cli/v3"
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

type cliOptions struct {
	targets            []string
	targetFile         string
	fingerprintPath    string
	thread             int
	headers            []string
	customHeaders      string
	proxy              string
	deepScan           bool
	rootPath           bool
	screenshot         bool
	assetTag           bool
	rawResponse        bool
	activeTimeoutLimit int
	storageDir         string
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := newCLICommand()
	if err := cmd.Run(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code := cliExitCode(err); code != 0 {
			return code
		}
		return 1
	}
	return 0
}

func newCLICommand() *cli.Command {
	return &cli.Command{
		Name:      "fingerprint",
		Usage:     "scan web fingerprints",
		UsageText: "fingerprint --url https://example.com [--verbose]\n   fingerprint --list targets.txt --fingerprint finger.yaml",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "url",
				Aliases: []string{"u"},
				Usage:   "target URL or host; may be repeated or comma-separated",
			},
			&cli.StringFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "file containing targets, one per line",
			},
			&cli.StringFlag{
				Name:    "fingerprint",
				Aliases: []string{"f"},
				Usage:   "fingerprint YAML path; defaults to embedded static/finger.yaml",
			},
			&cli.IntFlag{
				Name:    "thread",
				Aliases: []string{"t"},
				Value:   50,
				Usage:   "scan concurrency",
			},
			&cli.StringSliceFlag{
				Name:    "header",
				Aliases: []string{"H"},
				Usage:   "custom header in 'Key: Value' format; may be repeated",
			},
			&cli.StringFlag{
				Name:  "headers",
				Usage: "multi-line custom headers in 'Key: Value' format",
			},
			&cli.StringFlag{
				Name:  "proxy",
				Usage: "HTTP/SOCKS proxy URL",
			},
			&cli.BoolFlag{
				Name:  "deep",
				Usage: "enable active path fingerprint scan",
			},
			&cli.BoolFlag{
				Name:  "root-path",
				Usage: "run active path scan from site root",
			},
			&cli.BoolFlag{
				Name:  "screenshot",
				Usage: "capture screenshots",
			},
			&cli.BoolFlag{
				Name:  "asset-tag",
				Value: true,
				Usage: "enable CDN/asset tag probing",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "print captured full HTTP response packet",
			},
			&cli.IntFlag{
				Name:  "active-timeout",
				Value: 10,
				Usage: "max active scan failures per target",
			},
			&cli.StringFlag{
				Name:  "storage-dir",
				Value: "data",
				Usage: "local directory for favicon and screenshot assets",
			},
		},
		Action: runScanCommand,
	}
}

func runScanCommand(ctx context.Context, cmd *cli.Command) error {
	opts := cliOptions{
		targets:            cmd.StringSlice("url"),
		targetFile:         cmd.String("list"),
		fingerprintPath:    cmd.String("fingerprint"),
		thread:             cmd.Int("thread"),
		headers:            cmd.StringSlice("header"),
		customHeaders:      cmd.String("headers"),
		proxy:              cmd.String("proxy"),
		deepScan:           cmd.Bool("deep"),
		rootPath:           cmd.Bool("root-path"),
		screenshot:         cmd.Bool("screenshot"),
		assetTag:           cmd.Bool("asset-tag"),
		rawResponse:        cmd.Bool("verbose"),
		activeTimeoutLimit: cmd.Int("active-timeout"),
		storageDir:         cmd.String("storage-dir"),
	}

	targets, err := loadTargets(opts.targets, opts.targetFile)
	if err != nil {
		return fmt.Errorf("load targets: %w", err)
	}
	if len(targets) == 0 {
		return cli.Exit("target is required: use --url/-u or --list/-l", 2)
	}

	if opts.storageDir != "" {
		absStorageDir, err := filepath.Abs(opts.storageDir)
		if err != nil {
			return fmt.Errorf("resolve storage dir: %w", err)
		}
		opts.storageDir = absStorageDir
	}

	engine, err := fingerssdk.NewFingersEngineCtx(ctx, buildSDKOptions(opts, targets)...)
	if err != nil {
		return fmt.Errorf("create scanner: %w", err)
	}

	if err := engine.Scan(ctx, func(result fingerssdk.Result) {
		printResult(result, opts.rawResponse)
	}); err != nil && ctx.Err() == nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	return nil
}

type exitCoder interface {
	ExitCode() int
}

func cliExitCode(err error) int {
	if coder, ok := err.(exitCoder); ok {
		return coder.ExitCode()
	}
	return 0
}

func loadTargets(inlineTargets []string, targetFile string) ([]string, error) {
	targets := normalizeInlineTargets(inlineTargets)
	if targetFile == "" {
		return targets, nil
	}

	data, err := os.ReadFile(targetFile)
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, nil
}

func normalizeInlineTargets(inlineTargets []string) []string {
	targets := make([]string, 0, len(inlineTargets))
	for _, raw := range inlineTargets {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				targets = append(targets, item)
			}
		}
	}
	return targets
}

func buildSDKOptions(opts cliOptions, targets []string) []fingerssdk.FingersSDKOptions {
	sdkOptions := []fingerssdk.FingersSDKOptions{
		fingerssdk.WithTargets(targets...),
		fingerssdk.WithThread(opts.thread),
		fingerssdk.WithHeaders(opts.headers...),
		fingerssdk.WithCustomHeaders(opts.customHeaders),
		fingerssdk.WithProxy(opts.proxy),
		fingerssdk.WithDeepScan(opts.deepScan),
		fingerssdk.WithRootPath(opts.rootPath),
		fingerssdk.WithScreenshot(opts.screenshot),
		fingerssdk.WithAssetTagProbe(opts.assetTag),
		fingerssdk.WithRawResponse(opts.rawResponse),
		fingerssdk.WithActiveTimeoutLimit(opts.activeTimeoutLimit),
		fingerssdk.WithDefaultOutput(false),
		fingerssdk.WithAssetStorage(rootfingers.AssetStorageConfig{
			Mode: rootfingers.StorageModeLocal,
			Local: &rootfingers.LocalStorageConfig{
				BaseDir: opts.storageDir,
			},
		}),
	}

	if opts.fingerprintPath != "" {
		sdkOptions = append(sdkOptions, fingerssdk.WithFingerprintFile(opts.fingerprintPath))
	} else {
		sdkOptions = append(sdkOptions, BuiltinFingerprintOption())
	}

	return sdkOptions
}

func printResult(result fingerssdk.Result, verbose bool) {
	fmt.Printf("[%s] %s [%d] [%d] [%s] [%s]\n",
		result.Detect,
		result.URL,
		result.StatusCode,
		result.Length,
		result.Title,
		formatFingerprints(result),
	)

	if result.Screenshot != "" {
		fmt.Printf("  screenshot: %s\n", result.Screenshot)
	}
	if result.AssetTags.AssetType != "" || result.AssetTags.ProductName != "" {
		fmt.Printf("  asset_tag: %s %s\n", strings.TrimSpace(result.AssetTags.AssetType), strings.TrimSpace(result.AssetTags.ProductName))
	}

	if verbose {
		printFingerprintFields(result)
		fmt.Printf("===== RAW RESPONSE %s =====\n", result.URL)
		if result.RawResponse != "" {
			fmt.Print(result.RawResponse)
			if !strings.HasSuffix(result.RawResponse, "\n") {
				fmt.Println()
			}
		}
		fmt.Printf("===== END RAW RESPONSE %s =====\n", result.URL)
	}
}

func printFingerprintFields(result fingerssdk.Result) {
	fmt.Printf("===== FINGERPRINT FIELDS %s =====\n", result.URL)
	fmt.Printf("  status: %d\n", result.StatusCode)
	fmt.Printf("  server: %s\n", result.Server)
	fmt.Printf("  title: %s\n", result.Title)
	fmt.Printf("  content_type: %s\n", result.ContentType)
	fmt.Printf("  protocol: %s\n", result.Scheme)
	fmt.Printf("  host: %s\n", result.Host)
	fmt.Printf("  port: %d\n", result.Port)
	fmt.Printf("  path: %s\n", displayPath(result.Path))
	fmt.Printf("  length: %d\n", result.Length)
	fmt.Printf("  icon_hash: %s\n", result.IconHash)
	fmt.Printf("  icon_md5: %s\n", result.IconMd5)
	fmt.Printf("  favicon_url: %s\n", result.FaviconURL)
	fmt.Printf("===== END FINGERPRINT FIELDS %s =====\n", result.URL)
}

func displayPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func formatFingerprints(result fingerssdk.Result) string {
	if len(result.Fingerprints) == 0 {
		return "no fingerprint"
	}

	names := make([]string, 0, len(result.Fingerprints))
	for _, fp := range result.Fingerprints {
		name := fp.Name
		extractions := make([]string, 0, len(fp.Extractions))
		for _, extraction := range fp.Extractions {
			if strings.TrimSpace(extraction.Value) != "" {
				extractions = append(extractions, extraction.Value)
			}
		}
		if len(extractions) > 0 {
			name += " " + strings.Join(extractions, " ")
		}
		names = append(names, name)
	}
	return strings.Join(names, " | ")
}
