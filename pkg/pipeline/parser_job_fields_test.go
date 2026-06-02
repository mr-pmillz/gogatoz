package pipeline

import (
	"os"
	"strings"
	"testing"
)

func TestParse_JobFields_ImageServicesArtifactsCache(t *testing.T) {
	path := "testdata_job_fields.yml"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading fixture: %v", err)
	}
	doc, err := Parse(strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Jobs) < 2 {
		t.Fatalf("expected at least 2 jobs, got %d", len(doc.Jobs))
	}
	find := func(name string) *Job {
		for i := range doc.Jobs {
			if doc.Jobs[i].Name == name {
				return &doc.Jobs[i]
			}
		}
		return nil
	}
	j1 := find("job_img_services")
	if j1 == nil {
		t.Fatalf("missing job_img_services")
	}
	if want, got := "alpine:3.20", j1.Image; want != got {
		t.Fatalf("job1 image want %s got %s", want, got)
	}
	if len(j1.Services) != 2 || j1.Services[0] != "postgres:13" || j1.Services[1] != "docker:24.0-dind" {
		t.Fatalf("unexpected services: %#v", j1.Services)
	}
	if j1.Artifacts == nil || j1.Cache == nil {
		t.Fatalf("expected artifacts and cache to be parsed")
	}

	j2 := find("job_img_map")
	if j2 == nil {
		t.Fatalf("missing job_img_map")
	}
	if want, got := "golang:1.22", j2.Image; want != got {
		t.Fatalf("job2 image want %s got %s", want, got)
	}
}
