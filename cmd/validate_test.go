package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/validate"
)

func TestValidate_TargetFlagMapsToReadOnlyProbe(t *testing.T) {
	originalProbe := probeTokenFunc
	originalProject := validateProject
	originalToken := token
	originalGitLabURL := gitlabURL
	originalJSON := outputJSON
	defer func() {
		probeTokenFunc = originalProbe
		validateProject = originalProject
		token = originalToken
		gitlabURL = originalGitLabURL
		outputJSON = originalJSON
	}()

	var captured validate.ProbeOptions
	probeTokenFunc = func(
		_ context.Context,
		_ *gitlabx.Client,
		opts validate.ProbeOptions,
	) (*validate.TokenProfile, error) {
		captured = opts
		return &validate.TokenProfile{
			Username: "developer", ProbeMode: "read-only", ReadOnly: true,
			Project: &validate.ProjectAccess{ID: 42, Path: "group/demo", AccessLevel: 30},
		}, nil
	}
	validateProject = "  group/demo  "
	token = testTok
	gitlabURL = testGitlabURL
	outputJSON = true

	var output bytes.Buffer
	validateCmd.SetOut(&output)
	defer validateCmd.SetOut(nil)
	if err := validateCmd.RunE(validateCmd, nil); err != nil {
		t.Fatalf("validate RunE: %v", err)
	}
	if captured.Project != "group/demo" {
		t.Fatalf("probe target = %q, want group/demo", captured.Project)
	}
	var profile validate.TokenProfile
	if err := json.Unmarshal(output.Bytes(), &profile); err != nil {
		t.Fatalf("decode JSON output: %v\n%s", err, output.String())
	}
	if !profile.ReadOnly || profile.Project == nil || profile.Project.ID != 42 {
		t.Fatalf("profile output = %+v", profile)
	}
}

func TestValidate_TargetFlagRegistered(t *testing.T) {
	flag := validateCmd.Flags().Lookup("target")
	if flag == nil {
		t.Fatal("validate --target flag is not registered")
	}
	if flag.DefValue != "" {
		t.Fatalf("validate --target default = %q, want empty", flag.DefValue)
	}
}
