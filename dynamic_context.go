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

func (s *FingerScanner) storeDiscoveredRequests(pageURL *url.URL, requests []DiscoveredRequest) {
	if s == nil || pageURL == nil || len(requests) == 0 {
		return
	}
	key := contextOriginKey(pageURL)
	s.discoveredRequestMutex.Lock()
	defer s.discoveredRequestMutex.Unlock()
	if s.discoveredRequests == nil {
		s.discoveredRequests = make(map[string][]DiscoveredRequest)
	}
	s.discoveredRequests[key] = append(s.discoveredRequests[key], cloneDiscoveredRequests(requests)...)
}

func (s *FingerScanner) discoveredRequestsForTarget(pageURL *url.URL) []DiscoveredRequest {
	if s == nil || pageURL == nil {
		return nil
	}
	s.discoveredRequestMutex.Lock()
	defer s.discoveredRequestMutex.Unlock()
	return cloneDiscoveredRequests(s.discoveredRequests[contextOriginKey(pageURL)])
}

func cloneDiscoveredRequests(requests []DiscoveredRequest) []DiscoveredRequest {
	if len(requests) == 0 {
		return nil
	}
	result := make([]DiscoveredRequest, 0, len(requests))
	for _, request := range requests {
		next := request
		next.Headers = cloneStringMap(request.Headers)
		next.ResponseHeaders = cloneStringMap(request.ResponseHeaders)
		result = append(result, next)
	}
	return result
}

func cloneStringMap(items map[string]string) map[string]string {
	if len(items) == 0 {
		return nil
	}
	result := make(map[string]string, len(items))
	for key, value := range items {
		result[key] = value
	}
	return result
}

// discoverDynamicContextPaths keeps its historical name because it is the
// dynamic-discovery entry point. It now also records first-level page
// candidates, while preserving the original no-click/no-form-submit policy.
func (s *FingerScanner) discoverDynamicContextPaths(ctx context.Context) {
	s.discoverPageCandidates(ctx)
}
