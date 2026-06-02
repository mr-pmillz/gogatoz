package attack

import (
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// --- GenerateWebShellCI -----------------------------------------------------

func TestGenerateWebShellCI(t *testing.T) {
	tests := []struct {
		name         string
		jobName      string
		runnerTags   []string
		shell        string
		downloadPath string
		wantContains []string
	}{
		{
			name:         "defaults",
			jobName:      "",
			runnerTags:   nil,
			shell:        "",
			downloadPath: "",
			wantContains: []string{"webshell:", "stages:", "shell", "CMD", "bash .cmd.sh", "when: manual"},
		},
		{
			name:         "custom job and tags",
			jobName:      "my-shell",
			runnerTags:   []string{"self-hosted", "docker"},
			shell:        "",
			downloadPath: "",
			wantContains: []string{"my-shell:", "tags:", `"self-hosted"`, `"docker"`},
		},
		{
			name:         "with shell",
			jobName:      "sh-job",
			runnerTags:   nil,
			shell:        "zsh",
			downloadPath: "",
			wantContains: []string{"sh-job:", "before_script:", "Using shell zsh"},
		},
		{
			name:         "with downloadPath",
			jobName:      "dl-job",
			runnerTags:   nil,
			shell:        "",
			downloadPath: "/etc/passwd",
			wantContains: []string{"dl-job:", "artifacts:", "/etc/passwd", "expire_in"},
		},
		{
			name:         "all combined",
			jobName:      "full",
			runnerTags:   []string{"linux"},
			shell:        "bash",
			downloadPath: "/tmp/out",
			wantContains: []string{"full:", "tags:", `"linux"`, "before_script:", "Using shell bash", "artifacts:", "/tmp/out"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			att := NewAttacker(nil, "https://gitlab.com", "Test", "t@t.com", 0)
			w := NewWebShell(att)
			yaml := w.GenerateWebShellCI(tt.jobName, tt.runnerTags, tt.shell, tt.downloadPath)
			for _, substr := range tt.wantContains {
				if !strings.Contains(yaml, substr) {
					t.Errorf("expected %q in output:\n%s", substr, yaml)
				}
			}
			// Validate as parseable YAML
			doc, err := pipeline.Parse(strings.NewReader(yaml))
			if err != nil {
				t.Fatalf("generated YAML did not parse: %v\n---\n%s\n---", err, yaml)
			}
			if len(doc.Jobs) == 0 {
				t.Fatal("expected at least one job in parsed document")
			}
		})
	}
}
