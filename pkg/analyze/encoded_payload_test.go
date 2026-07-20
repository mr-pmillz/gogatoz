package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestEncodedPayload_Base64DecodeToShell(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{`echo "ZWNobyAiaGVsbG8i" | base64 -d | sh`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding for base64 decode to shell", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_Base64DecodeToShell_Long(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "deploy",
			Script: []string{`encoded=$(cat payload.b64); echo "$encoded" | base64 --decode | bash`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_ELFMagicBase64(t *testing.T) {
	elfBase64 := "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAUEBAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx"
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "inject",
			Script: []string{"echo '" + elfBase64 + "' > /tmp/payload"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding for ELF magic in base64", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_HexBlob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "payload",
			Script: []string{`echo -e '\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0a\x48\x45\x4c\x4c\x4f' > /tmp/bin`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding for hex blob", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_XxdDecode(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "exec",
			Script: []string{`echo "48656c6c6f" | xxd -r -p | sh`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding for xxd decode to shell", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_ChmodExec(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "drop",
			Script: []string{"chmod +x /tmp/payload; ./tmp/payload"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding for chmod+exec pattern", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_NoFalsePositive_NormalBase64(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "decode",
			Script: []string{`echo "$CI_VARIABLE" | base64 -d > config.json`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("did not expect %s finding for normal base64 decode to file", ScriptEncodedPayloadID)
	}
}

func TestEncodedPayload_GzipMagicBase64(t *testing.T) {
	gzipBase64 := "H4sIAAAAAAAAA" + // gzip magic
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "extract",
			Script: []string{"echo '" + gzipBase64 + "' > /tmp/archive.gz"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, ScriptEncodedPayloadID) {
		t.Fatalf("expected %s finding for gzip magic", ScriptEncodedPayloadID)
	}
}
