package fingers

import (
	"context"
	"net/url"
)

const maxPageDiscoveryHTMLBytes = 512 * 1024

// storeJSContextPage keeps the response body for a possible static fallback.
// Dynamic browser capture is preferred, so this body is only parsed when the
// browser cannot start or does not observe any API roots.
func (s *FingerScanner) storeJSContextPage(pageURL *url.URL, body []byte) {
	if s == nil || pageURL == nil || len(body) == 0 {
		return
	}
	if len(body) > maxPageDiscoveryHTMLBytes {
		body = body[:maxPageDiscoveryHTMLBytes]
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

// discoverDynamicContextPaths keeps its historical name because it is the
// dynamic-discovery entry point. It now also records first-level page
// candidates, while preserving the original no-click/no-form-submit policy.
func (s *FingerScanner) discoverDynamicContextPaths(ctx context.Context) {
	s.discoverPageCandidates(ctx)
}
