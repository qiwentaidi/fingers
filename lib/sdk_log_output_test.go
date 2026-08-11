package fingers

import (
	"bytes"
	"strings"
	"testing"
)

func TestWithLogOutputRoutesSDKLogs(t *testing.T) {
	var buf bytes.Buffer

	_, err := NewFingersEngine(
		WithTargets("http://example.com"),
		WithLogOutput(&buf),
		WithFingerprintBytes([]byte(`
Web:
  - name: Example
    rule:
      - body="example"
`)),
	)
	if err != nil {
		t.Fatalf("NewFingersEngine() error = %v", err)
	}

	if got := buf.String(); !strings.Contains(got, "[INF] fingerprint repository fingersized") {
		t.Fatalf("expected configured SDK log output to receive init log, got %q", got)
	}
}
