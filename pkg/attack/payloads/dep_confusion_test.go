package payloads

import (
	"strings"
	"testing"
)

func TestGenerateDepConfusionYAML_RegistryOverride(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		registry  string
		want      string
	}{
		{name: "npm", ecosystem: "npm", registry: "https://npm.invalid", want: `--registry "https://npm.invalid"`},
		{name: "pip", ecosystem: "pip", registry: "https://pypi.invalid", want: `--repository-url "https://pypi.invalid"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered := GenerateDepConfusionYAML(DepConfusionOptions{
				PackageName: "internal-package",
				Version:     "99.0.0",
				Ecosystem:   tt.ecosystem,
				Registry:    tt.registry,
			})
			if !strings.Contains(rendered, "stages: [attack]") {
				t.Fatalf("generated payload missing stages declaration:\n%s", rendered)
			}
			if !strings.Contains(rendered, tt.want) {
				t.Fatalf("generated payload missing %q:\n%s", tt.want, rendered)
			}
		})
	}
}
