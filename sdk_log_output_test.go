package fingers

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewScannerRoutesLogsToConfiguredOutput(t *testing.T) {
	var buf bytes.Buffer

	_, err := NewScanner(Options{
		Targets:   []string{"http://example.com"},
		LogOutput: &buf,
		FingerprintData: []byte(`
Web:
  - name: Example
    rule:
      - body="example"
`),
	})
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}

	if got := buf.String(); !strings.Contains(got, "[INF] fingerprint repository fingersized") {
		t.Fatalf("expected configured log output to receive init log, got %q", got)
	}
}
