package fingers

import (
	"context"
	"net/url"

	"github.com/qiwentaidi/fingers/internal/logger"
)

// storeJSContextPage keeps the response body for a possible static fallback.
// Dynamic browser capture is preferred, so this body is only parsed when the
// browser cannot start or does not observe any API roots.
func (s *FingerScanner) storeJSContextPage(pageURL *url.URL, body []byte) {
	if s == nil || pageURL == nil || len(body) == 0 {
		return
	}
	if len(body) > maxInfoReponseSize {
		body = body[:maxInfoReponseSize]
	}
	copyBody := append([]byte(nil), body...)
	s.jsContextMutex.Lock()
	defer s.jsContextMutex.Unlock()
	if s.pageContextBodies == nil {
		s.pageContextBodies = make(map[string][]byte)
	}
	s.pageContextBodies[contextOriginKey(pageURL)] = copyBody
}

func (s *FingerScanner) pageContextBody(pageURL *url.URL) []byte {
	if s == nil || pageURL == nil {
		return nil
	}
	s.jsContextMutex.Lock()
	defer s.jsContextMutex.Unlock()
	return append([]byte(nil), s.pageContextBodies[contextOriginKey(pageURL)]...)
}

// discoverDynamicContextPaths uses only the initial page load. It deliberately
// does not click forms or invoke arbitrary actions, keeping this discovery
// phase bounded and side-effect free. Static HTML/JS parsing is a fallback.
func (s *FingerScanner) discoverDynamicContextPaths(ctx context.Context) {
	if s == nil || ctx.Err() != nil || len(s.aliveURLs) == 0 {
		return
	}
	seenOrigins := make(map[string]struct{})
	for _, target := range s.aliveURLs {
		if ctx.Err() != nil {
			return
		}
		if target == nil || (target.Scheme != "http" && target.Scheme != "https") {
			continue
		}
		origin := contextOriginKey(target)
		if _, seen := seenOrigins[origin]; seen {
			continue
		}
		seenOrigins[origin] = struct{}{}

		var dynamicRoots []string
		if s.screenshotBrowser != nil {
			requests, err := s.screenshotBrowser.CaptureNetworkURLs(ctx, target.String())
			dynamicPaths := make([]string, 0, len(requests))
			for _, raw := range requests {
				requestURL, parseErr := url.Parse(raw)
				if parseErr != nil || !sameContextURL(target, requestURL) {
					continue
				}
				dynamicPaths = append(dynamicPaths, requestURL.Path)
			}
			dynamicRoots = deriveAPIContextPaths(dynamicPaths)
			if err != nil && s.shouldPrintDefaultOutput() {
				logger.Default.Debug("[headless] capture API roots for %s partially failed: %v", target, err)
			}
		}
		if len(dynamicRoots) > 0 {
			s.storeJSContextPaths(target, dynamicRoots)
			continue
		}

		// Browser startup/network capture can fail on hosts without Chromium;
		// retain the previous static parser as a bounded compatibility fallback.
		if body := s.pageContextBody(target); len(body) > 0 {
			s.discoverJSContextPaths(ctx, target, body)
		}
	}
}
