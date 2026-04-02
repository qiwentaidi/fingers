package fingers

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
)

type assetStore interface {
	Save(ctx context.Context, objectName string, data []byte) (string, error)
}

type noopStore struct{}

func (noopStore) Save(context.Context, string, []byte) (string, error) { return "", nil }

type localStore struct {
	baseDir       string
	publicBaseURL string
}

func (s *localStore) Save(_ context.Context, objectName string, data []byte) (string, error) {
	targetPath := filepath.Join(s.baseDir, filepath.FromSlash(objectName))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", err
	}
	if _, err := os.Stat(targetPath); err == nil {
		return s.location(objectName), nil
	}
	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return "", err
	}
	return s.location(objectName), nil
}

func (s *localStore) location(objectName string) string {
	if s.publicBaseURL != "" {
		return strings.TrimRight(s.publicBaseURL, "/") + "/" + strings.TrimLeft(filepath.ToSlash(objectName), "/")
	}
	return filepath.Join(s.baseDir, filepath.FromSlash(objectName))
}

type aliyunOSSStore struct {
	bucket        *oss.Bucket
	prefix        string
	publicBaseURL string
}

func (s *aliyunOSSStore) Save(ctx context.Context, objectName string, data []byte) (string, error) {
	key := strings.TrimLeft(path.Join(s.prefix, filepath.ToSlash(objectName)), "/")
	opts := []oss.Option{}
	if contentType := mime.TypeByExtension(filepath.Ext(objectName)); contentType != "" {
		opts = append(opts, oss.ContentType(contentType))
	}
	if err := s.bucket.PutObject(key, bytes.NewReader(data), opts...); err != nil {
		return "", err
	}
	if s.publicBaseURL != "" {
		return strings.TrimRight(s.publicBaseURL, "/") + "/" + key, nil
	}
	return key, nil
}

func newAssetStore(cfg AssetStorageConfig, fallbackDir string) (assetStore, error) {
	switch cfg.Mode {
	case "", StorageModeLocal:
		baseDir := fallbackDir
		publicBaseURL := ""
		if cfg.Local != nil {
			if cfg.Local.BaseDir != "" {
				baseDir = cfg.Local.BaseDir
			}
			publicBaseURL = cfg.Local.PublicBaseURL
		}
		if baseDir == "" {
			return noopStore{}, nil
		}
		return &localStore{baseDir: baseDir, publicBaseURL: publicBaseURL}, nil
	case StorageModeAliyunOSS:
		if cfg.AliyunOSS == nil {
			return nil, fmt.Errorf("aliyun oss storage config is required")
		}
		client, err := oss.New(cfg.AliyunOSS.Endpoint, cfg.AliyunOSS.AccessKeyID, cfg.AliyunOSS.AccessKeySecret)
		if err != nil {
			return nil, err
		}
		bucket, err := client.Bucket(cfg.AliyunOSS.Bucket)
		if err != nil {
			return nil, err
		}
		return &aliyunOSSStore{
			bucket:        bucket,
			prefix:        cfg.AliyunOSS.Prefix,
			publicBaseURL: cfg.AliyunOSS.PublicBaseURL,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported storage mode: %s", cfg.Mode)
	}
}
