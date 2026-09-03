package fingers

import (
	"context"
	"net/url"
)

const maxPageDiscoveryHTMLBytes = 512 * 1024

// storeJSContextPage keeps the initial page response for discovery decisions.
func (s *FingerScanner) storeJSContextPage(pageURL *url.URL, body []byte, statusCode int) {
	if s == nil || pageURL == nil {
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
	if s.pageContextStatusCodes == nil {
		s.pageContextStatusCodes = make(map[string]int)
	}
	key := contextOriginKey(pageURL)
	s.pageContextBodies[key] = copyBody
	s.pageContextStatusCodes[key] = statusCode
}

func (s *FingerScanner) pageContext(pageURL *url.URL) ([]byte, int, bool) {
	if s == nil || pageURL == nil {
		return nil, 0, false
	}
	s.jsContextMutex.Lock()
	defer s.jsContextMutex.Unlock()
	key := contextOriginKey(pageURL)
	body, bodyOK := s.pageContextBodies[key]
	statusCode, statusOK := s.pageContextStatusCodes[key]
	return append([]byte(nil), body...), statusCode, bodyOK || statusOK
}

func (s *FingerScanner) pageContextBody(pageURL *url.URL) []byte {
	body, _, _ := s.pageContext(pageURL)
	return body
}

func (s *FingerScanner) discoverPageContextPaths(ctx context.Context) {
	s.discoverPageCandidates(ctx)
}
