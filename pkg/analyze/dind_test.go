package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

func TestIsDinDService(t *testing.T) {
	tests := []struct {
		service string
		want    bool
	}{
		{"docker:dind", true},
		{"docker:24-dind", true},
		{"docker:25.0-dind", true},
		{"docker:latest", true},
		{"docker:DIND", true},                           // case-insensitive
		{"Docker:dind", true},                           // case-insensitive name
		{"registry.example.com/docker:dind", true},      // with registry prefix
		{"registry.example.com:5000/docker:dind", true}, // registry with port
		{"my-org/docker:24-dind", true},                 // namespaced image
		{"docker:24.0", false},                          // version tag without dind
		{"docker:stable", false},                        // non-dind tag
		{"docker", false},                               // bare docker, no tag
		{"postgres:15", false},                          // unrelated service
		{"redis:7", false},                              // unrelated service
		{"mysql:8.0", false},                            // unrelated service
		{"my-docker:dind", false},                       // name is not exactly "docker"
		{"dockerhub:dind", false},                       // name is not exactly "docker"
		{"", false},                                     // empty string
		{"  ", false},                                   // whitespace only
	}
	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			got := isDinDService(tt.service)
			if got != tt.want {
				t.Errorf("isDinDService(%q) = %v, want %v", tt.service, got, tt.want)
			}
		})
	}
}

func TestDetectDinD_DinDDetected(t *testing.T) {
	tests := []struct {
		name     string
		doc      *pipeline.Document
		wantDinD bool
	}{
		{
			name: "docker:dind service triggers DIND_DETECTED",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
				}},
			},
			wantDinD: true,
		},
		{
			name: "docker:24-dind service triggers DIND_DETECTED",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:24-dind"},
				}},
			},
			wantDinD: true,
		},
		{
			name: "docker:latest service triggers DIND_DETECTED",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:latest"},
				}},
			},
			wantDinD: true,
		},
		{
			name: "docker:24.0 service does not trigger DIND_DETECTED",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:24.0"},
				}},
			},
			wantDinD: false,
		},
		{
			name: "postgres:15 service does not trigger DIND_DETECTED",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "test",
					Script:   []string{"go test ./..."},
					Services: []string{"postgres:15"},
				}},
			},
			wantDinD: false,
		},
		{
			name: "no services does not trigger DIND_DETECTED",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:   "test",
					Script: []string{"echo hello"},
				}},
			},
			wantDinD: false,
		},
		{
			name: "multiple services, one is dind",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "integration",
					Script:   []string{"docker compose up"},
					Services: []string{"postgres:15", "docker:dind", "redis:7"},
				}},
			},
			wantDinD: true,
		},
		{
			name:     "nil document returns no findings",
			doc:      nil,
			wantDinD: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectDinD(tt.doc)
			got := hasFindingID(findings, DinDDetectedID)
			if got != tt.wantDinD {
				t.Errorf("hasFindingID(%q) = %v, want %v; findings: %+v", DinDDetectedID, got, tt.wantDinD, findings)
			}
		})
	}
}

func TestDetectDinD_DinDInsecure(t *testing.T) {
	tests := []struct {
		name         string
		doc          *pipeline.Document
		wantInsecure bool
	}{
		{
			name: "docker:dind + DOCKER_TLS_CERTDIR empty triggers DIND_INSECURE",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
					Variables: map[string]any{
						"DOCKER_TLS_CERTDIR": "",
					},
				}},
			},
			wantInsecure: true,
		},
		{
			name: "docker:dind + DOCKER_HOST tcp 2375 triggers DIND_INSECURE",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
					Variables: map[string]any{
						"DOCKER_HOST":        "tcp://docker:2375",
						"DOCKER_TLS_CERTDIR": "/certs",
					},
				}},
			},
			wantInsecure: true,
		},
		{
			name: "docker:dind + DOCKER_TLS_CERTDIR=/certs no DIND_INSECURE",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
					Variables: map[string]any{
						"DOCKER_TLS_CERTDIR": "/certs",
					},
				}},
			},
			wantInsecure: false,
		},
		{
			name: "no dind service, empty DOCKER_TLS_CERTDIR, no DIND_INSECURE",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "test",
					Script:   []string{"go test ./..."},
					Services: []string{"postgres:15"},
					Variables: map[string]any{
						"DOCKER_TLS_CERTDIR": "",
					},
				}},
			},
			wantInsecure: false,
		},
		{
			name: "docker:dind + DOCKER_TLS_CERTDIR empty at global level triggers DIND_INSECURE",
			doc: &pipeline.Document{
				Variables: map[string]any{
					"DOCKER_TLS_CERTDIR": "",
				},
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
				}},
			},
			wantInsecure: true,
		},
		{
			name: "docker:dind + DOCKER_HOST 2375 at global level triggers DIND_INSECURE",
			doc: &pipeline.Document{
				Variables: map[string]any{
					"DOCKER_HOST":        "tcp://docker:2375",
					"DOCKER_TLS_CERTDIR": "/certs",
				},
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
				}},
			},
			wantInsecure: true,
		},
		{
			name: "docker:dind + job overrides global DOCKER_TLS_CERTDIR to /certs, no DIND_INSECURE",
			doc: &pipeline.Document{
				Variables: map[string]any{
					"DOCKER_TLS_CERTDIR": "",
				},
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
					Variables: map[string]any{
						"DOCKER_TLS_CERTDIR": "/certs",
					},
				}},
			},
			wantInsecure: false,
		},
		{
			name: "docker:dind + no DOCKER_TLS_CERTDIR set anywhere triggers DIND_INSECURE",
			doc: &pipeline.Document{
				Jobs: []pipeline.Job{{
					Name:     "build",
					Script:   []string{"docker build ."},
					Services: []string{"docker:dind"},
				}},
			},
			wantInsecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectDinD(tt.doc)
			got := hasFindingID(findings, DinDInsecureID)
			if got != tt.wantInsecure {
				t.Errorf("hasFindingID(%q) = %v, want %v; findings: %+v", DinDInsecureID, got, tt.wantInsecure, findings)
			}
		})
	}
}

func TestDetectDinD_OneFindingPerJob(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:     "build",
			Script:   []string{"docker build ."},
			Services: []string{"docker:dind", "docker:24-dind"},
			Variables: map[string]any{
				"DOCKER_TLS_CERTDIR": "/certs",
			},
		}},
	}
	findings := detectDinD(doc)

	count := 0
	for _, f := range findings {
		if f.ID == DinDDetectedID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 DIND_DETECTED finding per job with multiple dind services, got %d", count)
	}
}

func TestDetectDinD_MultipleJobs(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{
			{
				Name:     "build",
				Script:   []string{"docker build ."},
				Services: []string{"docker:dind"},
				Variables: map[string]any{
					"DOCKER_TLS_CERTDIR": "/certs",
				},
			},
			{
				Name:     "test",
				Script:   []string{"go test ./..."},
				Services: []string{"postgres:15"},
			},
			{
				Name:     "integration",
				Script:   []string{"docker compose up"},
				Services: []string{"docker:24-dind"},
				Variables: map[string]any{
					"DOCKER_TLS_CERTDIR": "",
				},
			},
		},
	}
	findings := detectDinD(doc)

	// Two jobs have dind services
	dindCount := 0
	for _, f := range findings {
		if f.ID == DinDDetectedID {
			dindCount++
		}
	}
	if dindCount != 2 {
		t.Errorf("expected 2 DIND_DETECTED findings, got %d", dindCount)
	}

	// Only the integration job has insecure config
	insecureCount := 0
	for _, f := range findings {
		if f.ID == DinDInsecureID {
			insecureCount++
			if f.JobName != "integration" {
				t.Errorf("expected DIND_INSECURE for job 'integration', got job %q", f.JobName)
			}
		}
	}
	if insecureCount != 1 {
		t.Errorf("expected 1 DIND_INSECURE finding, got %d", insecureCount)
	}
}

func TestDetectDinD_FindingSeverity(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:     "build",
			Script:   []string{"docker build ."},
			Services: []string{"docker:dind"},
			Variables: map[string]any{
				"DOCKER_TLS_CERTDIR": "",
			},
		}},
	}
	findings := detectDinD(doc)

	for _, f := range findings {
		if f.ID == DinDDetectedID && f.Severity != SeverityHigh {
			t.Errorf("DIND_DETECTED severity = %v, want %v", f.Severity, SeverityHigh)
		}
		if f.ID == DinDInsecureID && f.Severity != SeverityHigh {
			t.Errorf("DIND_INSECURE severity = %v, want %v", f.Severity, SeverityHigh)
		}
	}
}
