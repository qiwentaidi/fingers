package fingers

import (
	"net/http"
	"testing"
)

func TestNewDiscoveredRequestBuilderIsExportedFromSDKPackage(t *testing.T) {
	builder := NewDiscoveredRequestBuilder("https://example.com").
		AddJSONRequest(http.MethodPost, "https://example.com/api/orders", `{"id":1}`)

	requests := builder.Requests()
	if len(requests) != 1 || requests[0].ContentType != "application/json" {
		t.Fatalf("unexpected SDK builder requests: %#v", requests)
	}
}
