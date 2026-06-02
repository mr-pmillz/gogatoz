package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func BenchmarkAnalyze(b *testing.B) {
	doc := &pipeline.Document{
		Stages:    []string{"build", "test", "deploy", "security"},
		Variables: map[string]any{"SECRET_KEY": "glpat-xxxxxxxxxxxxxxxxxxxx", "APP_NAME": "myapp"},
		Includes: []pipeline.Include{
			{Type: pipeline.IncludeRemote, Remote: "https://evil.example.com/ci.yml"},
			{Type: pipeline.IncludeProject, Project: "devops/templates", File: []string{"/ci.yml"}},
			{Type: pipeline.IncludeComponent, Component: "example.com/my-component@1.0"},
		},
		Workflow: pipeline.Workflow{
			Rules: []any{
				map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event"`, "when": "always"},
				map[string]any{"if": "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", "when": "always"},
			},
		},
		Jobs: []pipeline.Job{
			{
				Name:  "build",
				Stage: "build",
				Tags:  []string{"self-hosted", "production"},
				Script: []string{
					"docker build -t $APP_NAME .",
				},
				Rules: []any{
					map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event"`},
					map[string]any{"when": "always"},
				},
				Artifacts: map[string]any{"paths": []string{"dist/"}},
				Services:  []string{"docker:24.0-dind"},
				Image:     "docker:24.0",
			},
			{
				Name:  "test_inject",
				Stage: "test",
				Script: []string{
					"make test COMMIT_MSG=$CI_COMMIT_MESSAGE",
					"echo $CI_MERGE_REQUEST_TITLE",
				},
				Rules: []any{
					map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event"`},
				},
			},
			{
				Name:  "risky_remote",
				Stage: "security",
				Script: []string{
					"curl https://scanner.example.com/run.sh | bash",
				},
				AllowFailure: true,
			},
			{
				Name:  "deploy_staging",
				Stage: "deploy",
				Tags:  []string{"self-hosted", "production"},
				Script: []string{
					"kubectl apply -f k8s/",
				},
				Rules: []any{
					map[string]any{"if": `$CI_PIPELINE_SOURCE == "merge_request_event"`},
				},
				Needs:       []string{"build"},
				Environment: "staging",
			},
			{
				Name:  "deploy_prod",
				Stage: "deploy",
				Tags:  []string{"self-hosted"},
				Script: []string{
					"kubectl apply -f k8s/",
				},
				When:        "manual",
				Environment: "production",
				Needs:       []string{"deploy_staging"},
			},
			{
				Name:  "artifact_consumer",
				Stage: "deploy",
				Needs: []string{"build"},
				Tags:  []string{"self-hosted"},
				Script: []string{
					"./deploy.sh",
				},
			},
			{
				Name:  "broad_only",
				Stage: "test",
				Tags:  []string{"runner-x"},
				Only:  []any{"branches"},
				Script: []string{
					"echo testing",
				},
			},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		findings, err := Run(doc)
		if err != nil {
			b.Fatal(err)
		}
		if len(findings) == 0 {
			b.Fatal("expected findings")
		}
	}
}
