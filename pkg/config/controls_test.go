package config

import (
	"strings"
	"testing"
)

func TestIsRuleDisabled_Match(t *testing.T) {
	c := &ControlsConfig{
		DisabledRules: []string{"IMAGE_NOT_PINNED", "UNPINNED_PACKAGE_INSTALL"},
	}
	if !c.IsRuleDisabled("IMAGE_NOT_PINNED") {
		t.Fatal("expected IMAGE_NOT_PINNED to be disabled")
	}
	if !c.IsRuleDisabled("UNPINNED_PACKAGE_INSTALL") {
		t.Fatal("expected UNPINNED_PACKAGE_INSTALL to be disabled")
	}
}

func TestIsRuleDisabled_CaseInsensitive(t *testing.T) {
	c := &ControlsConfig{
		DisabledRules: []string{"image_not_pinned"},
	}
	if !c.IsRuleDisabled("IMAGE_NOT_PINNED") {
		t.Fatal("expected case-insensitive match")
	}
	if !c.IsRuleDisabled("Image_Not_Pinned") {
		t.Fatal("expected case-insensitive match for mixed case")
	}
}

func TestIsRuleDisabled_NoMatch(t *testing.T) {
	c := &ControlsConfig{
		DisabledRules: []string{"IMAGE_NOT_PINNED"},
	}
	if c.IsRuleDisabled("SELF_HOSTED_EXPOSED") {
		t.Fatal("did not expect SELF_HOSTED_EXPOSED to be disabled")
	}
}

func TestIsRuleDisabled_EmptyList(t *testing.T) {
	c := &ControlsConfig{}
	if c.IsRuleDisabled("IMAGE_NOT_PINNED") {
		t.Fatal("empty disabled list should not disable any rule")
	}
}

func TestIsRuleDisabled_NilConfig(t *testing.T) {
	var c *ControlsConfig
	if c.IsRuleDisabled("IMAGE_NOT_PINNED") {
		t.Fatal("nil config should not disable any rule")
	}
}

func TestDefaultControls_ForbiddenImageTags(t *testing.T) {
	d := DefaultControls()
	if len(d.ForbiddenImageTags) == 0 {
		t.Fatal("expected non-empty ForbiddenImageTags")
	}
	found := false
	for _, tag := range d.ForbiddenImageTags {
		if tag == "latest" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected 'latest' in default ForbiddenImageTags")
	}
}

func TestDefaultControls_SecurityJobPatterns(t *testing.T) {
	d := DefaultControls()
	if len(d.SecurityJobPatterns) == 0 {
		t.Fatal("expected non-empty SecurityJobPatterns")
	}
	found := false
	for _, p := range d.SecurityJobPatterns {
		if p == "sast" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected 'sast' in default SecurityJobPatterns")
	}
}

func TestDefaultControls_DebugTraceVariables(t *testing.T) {
	d := DefaultControls()
	if len(d.DebugTraceVariables) == 0 {
		t.Fatal("expected non-empty DebugTraceVariables")
	}
	found := false
	for _, v := range d.DebugTraceVariables {
		if v == "CI_DEBUG_TRACE" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected 'CI_DEBUG_TRACE' in default DebugTraceVariables")
	}
}

func TestDefaultControls_EmptyOptionalFields(t *testing.T) {
	d := DefaultControls()
	if len(d.AuthorizedRegistries) != 0 {
		t.Fatalf("expected empty AuthorizedRegistries, got %v", d.AuthorizedRegistries)
	}
	if len(d.ControlledVariables) != 0 {
		t.Fatalf("expected empty ControlledVariables, got %v", d.ControlledVariables)
	}
	if len(d.TrustedScriptURLs) != 0 {
		t.Fatalf("expected empty TrustedScriptURLs, got %v", d.TrustedScriptURLs)
	}
	if len(d.DisabledRules) != 0 {
		t.Fatalf("expected empty DisabledRules, got %v", d.DisabledRules)
	}
}

func TestGenerateDefaultYAML_ContainsExpectedKeys(t *testing.T) {
	yaml := GenerateDefaultYAML()
	keys := []string{
		"controls:",
		"forbiddenImageTags:",
		"securityJobPatterns:",
		"debugTraceVariables:",
		"authorizedRegistries:",
		"controlledVariables:",
		"trustedScriptURLs:",
		"disabledRules:",
	}
	for _, key := range keys {
		if !strings.Contains(yaml, key) {
			t.Errorf("expected GenerateDefaultYAML output to contain %q", key)
		}
	}
}

func TestGenerateDefaultYAML_ContainsDefaultValues(t *testing.T) {
	yaml := GenerateDefaultYAML()
	values := []string{
		"latest",
		"sast",
		"CI_DEBUG_TRACE",
		"CI_DEBUG_SERVICES",
		"IMAGE_NOT_PINNED",
	}
	for _, val := range values {
		if !strings.Contains(yaml, val) {
			t.Errorf("expected GenerateDefaultYAML output to contain %q", val)
		}
	}
}
