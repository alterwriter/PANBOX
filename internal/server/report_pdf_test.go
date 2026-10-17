package server

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"testing"
)

func TestTechnicalPDF(t *testing.T) {
	data, err := technicalPDF([]findingRow{{Repository: "sample", Branch: "main", Module: "vaccin", RuleID: "PAN-001", Path: "src/main.go", Line: 12, Raw: "high", Effective: "medium"}}, url.Values{"module": {"vaccin"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) || len(data) < 1000 {
		t.Fatalf("invalid PDF (%d bytes)", len(data))
	}
	if path := os.Getenv("PANBOX_PDF_PREVIEW"); path != "" {
		preview := make([]findingRow, 120)
		for i := range preview {
			preview[i] = findingRow{Repository: "sample", Branch: "main", Module: "vaccin", RuleID: fmt.Sprintf("PAN-%03d", i), Path: "src/main.go", Line: i + 1, Raw: "high", Effective: "medium"}
		}
		bulk, err := technicalPDF(preview, url.Values{"module": {"vaccin"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bulk, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
