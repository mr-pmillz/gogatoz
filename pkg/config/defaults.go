package config

// DefaultControls returns a ControlsConfig populated with the same defaults
// that the analysis engine uses when no configuration is provided. Callers can
// use this as a starting point and override individual fields.
func DefaultControls() ControlsConfig {
	return ControlsConfig{
		ForbiddenImageTags: []string{
			"latest",
			"dev",
			"master",
			"main",
			"nightly",
			"edge",
			"canary",
			"unstable",
			"beta",
			"alpha",
			"rc",
			"staging",
		},
		SecurityJobPatterns: []string{
			"sast",
			"secret",
			"dast",
			"container_scanning",
			"dependency_scanning",
			"license_scanning",
			"code_quality",
			"security",
		},
		DebugTraceVariables: []string{
			"CI_DEBUG_TRACE",
			"CI_DEBUG_SERVICES",
		},
		// AuthorizedRegistries, ControlledVariables, TrustedScriptURLs,
		// and DisabledRules are intentionally empty by default.
	}
}

// GenerateDefaultYAML returns a commented .gogatoz.yaml template showing all
// available controls options with their default values. This is intended for
// the `gogatoz config init` command.
func GenerateDefaultYAML() string {
	return `# GoGatoZ configuration file
# See: gogatoz config show

# GitLab connection settings (can also be set via flags/env)
# gitlab-url: https://gitlab.com
# token: ""

# Analysis controls — override detection defaults
controls:
  # Container image tags considered mutable (IMAGE_MUTABLE_TAG detection)
  forbiddenImageTags:
    - latest
    - dev
    - master
    - main
    - nightly
    - edge
    - canary
    - unstable
    - beta
    - alpha
    - rc
    - staging

  # Registries that are trusted (future: suppress IMAGE_NOT_PINNED for these)
  # authorizedRegistries: []

  # Job name patterns that identify security jobs (SECURITY_JOB_WEAKENED detection)
  securityJobPatterns:
    - sast
    - secret
    - dast
    - container_scanning
    - dependency_scanning
    - license_scanning
    - code_quality
    - security

  # CI variables that expose secrets when enabled (DEBUG_TRACE_ENABLED detection)
  debugTraceVariables:
    - CI_DEBUG_TRACE
    - CI_DEBUG_SERVICES

  # Additional controlled CI variables (future: variable governance)
  # controlledVariables: []

  # URLs considered safe for remote script execution (future: suppress RISKY_REMOTE_SCRIPT)
  # trustedScriptURLs: []

  # Finding IDs to suppress (case-insensitive)
  # disabledRules: []
  #   - IMAGE_NOT_PINNED
  #   - UNPINNED_PACKAGE_INSTALL
`
}
