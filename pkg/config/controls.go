package config

import "strings"

// ControlsConfig holds per-detection configuration for the analysis engine.
// All slices override the corresponding hardcoded defaults when non-empty.
// A nil *ControlsConfig is safe to pass everywhere and means "use defaults".
type ControlsConfig struct {
	ForbiddenImageTags   []string `yaml:"forbiddenImageTags" mapstructure:"forbiddenImageTags"`
	AuthorizedRegistries []string `yaml:"authorizedRegistries" mapstructure:"authorizedRegistries"`
	SecurityJobPatterns  []string `yaml:"securityJobPatterns" mapstructure:"securityJobPatterns"`
	ControlledVariables  []string `yaml:"controlledVariables" mapstructure:"controlledVariables"`
	DebugTraceVariables  []string `yaml:"debugTraceVariables" mapstructure:"debugTraceVariables"`
	TrustedScriptURLs    []string `yaml:"trustedScriptURLs" mapstructure:"trustedScriptURLs"`
	DisabledRules        []string `yaml:"disabledRules" mapstructure:"disabledRules"`
}

// IsRuleDisabled returns true if the given finding ID is in the disabled list.
// Safe to call on a nil receiver.
func (c *ControlsConfig) IsRuleDisabled(id string) bool {
	if c == nil {
		return false
	}
	for _, d := range c.DisabledRules {
		if strings.EqualFold(d, id) {
			return true
		}
	}
	return false
}
