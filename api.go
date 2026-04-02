package fingers

import (
	"context"
	"fmt"
)

func NewScanner(options Options) (*FingerScanner, error) {
	if options.Thread <= 0 {
		options.Thread = 30
	}
	if options.ActiveTimeoutLimit <= 0 {
		options.ActiveTimeoutLimit = 5
	}

	fingerprintRepo, err := loadFingerprintRepository(options)
	if err != nil {
		return nil, fmt.Errorf("load fingerprints: %w", err)
	}

	faviconStore, err := newAssetStore(options.FaviconStorage, "data/favicon")
	if err != nil {
		return nil, fmt.Errorf("init favicon storage: %w", err)
	}
	screenshotStore, err := newAssetStore(options.ScreenshotStorage, "data/screenshot")
	if err != nil {
		return nil, fmt.Errorf("init screenshot storage: %w", err)
	}

	scanner := newFingerScanner(options, fingerprintRepo, faviconStore, screenshotStore)
	if scanner == nil {
		return nil, fmt.Errorf("no valid targets configured")
	}
	return scanner, nil
}

func loadFingerprintRepository(options Options) (*FingerprintRepository, error) {
	switch {
	case len(options.FingerprintData) > 0:
		fingers, err := LoadFingerprintFromBytes(options.FingerprintData)
		if err != nil {
			return nil, err
		}
		return BuildFingerprintRepository(fingers), nil
	case options.FingerprintPath != "":
		fingers, err := LoadFingerprintFromFile(options.FingerprintPath)
		if err != nil {
			return nil, err
		}
		return BuildFingerprintRepository(fingers), nil
	case options.FingerprintFS != nil && options.FingerprintFSName != "":
		fingers, err := LoadFingerprintFromFS(options.FingerprintFS, options.FingerprintFSName)
		if err != nil {
			return nil, err
		}
		return BuildFingerprintRepository(fingers), nil
	default:
		return nil, fmt.Errorf("no fingerprint source configured")
	}
}

func (s *FingerScanner) Scan(ctx context.Context, callback ResultCallback) error {
	s.FingerScan(ctx, callback)
	if s.deepScan {
		s.ActiveFingerScan(ctx, callback)
	}
	return ctx.Err()
}
