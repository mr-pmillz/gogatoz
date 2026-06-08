package analyze

import "strings"

// LOTPTool describes a "Living off the Pipeline" tool — a legitimate CI/CD tool that can be
// weaponized if an attacker modifies its configuration file or input via a merge request.
// Source: https://boostsecurityio.github.io/lotp/
type LOTPTool struct {
	// Name is the canonical display name of the tool.
	Name string
	// Commands are the command-line prefixes to match in script lines (lowercase).
	Commands []string
	// Vector describes the attack surface: "config-file", "input-file", or "env-var".
	Vector string
	// ConfigFiles lists the files in the repository that can weaponize the tool.
	ConfigFiles []string
	// EvalType is the execution language: "sh", "js", "py", "groovy", "go", "bin".
	EvalType string
}

// lotpCatalog is the complete LOTP tool catalog.
// Every entry represents a tool whose CI invocation can be exploited if an attacker
// can modify its configuration or input file in a merge request.
//
//nolint:gochecknoglobals
var lotpCatalog = []LOTPTool{
	// Build / package managers
	{Name: "npm", Commands: []string{"npm"}, Vector: "config-file", ConfigFiles: []string{"package.json"}, EvalType: "js"},
	{Name: "npx", Commands: []string{"npx"}, Vector: "input-file", ConfigFiles: []string{"package.json"}, EvalType: "js"},
	{Name: "yarn", Commands: []string{"yarn"}, Vector: "config-file", ConfigFiles: []string{".yarnrc", ".yarnrc.yml", "package.json"}, EvalType: "js"},
	{Name: "pnpm", Commands: []string{"pnpm"}, Vector: "config-file", ConfigFiles: []string{".npmrc", "package.json"}, EvalType: "js"},
	{Name: "bun", Commands: []string{"bun"}, Vector: "config-file", ConfigFiles: []string{"bunfig.toml", "package.json"}, EvalType: "js"},
	{Name: "pip", Commands: []string{"pip", "pip3"}, Vector: "input-file", ConfigFiles: []string{"requirements.txt", "setup.py", "pyproject.toml"}, EvalType: "py"},
	{Name: "uv", Commands: []string{"uv"}, Vector: "input-file", ConfigFiles: []string{"pyproject.toml", "requirements.txt"}, EvalType: "py"},
	{Name: "poetry", Commands: []string{"poetry"}, Vector: "input-file", ConfigFiles: []string{"pyproject.toml"}, EvalType: "py"},
	{Name: "tox", Commands: []string{"tox"}, Vector: "config-file", ConfigFiles: []string{"tox.ini", "setup.cfg", "pyproject.toml"}, EvalType: "py"},
	{Name: "cargo", Commands: []string{"cargo"}, Vector: "config-file", ConfigFiles: []string{"Cargo.toml", "build.rs"}, EvalType: "sh"},
	{Name: "bundler", Commands: []string{"bundle", "bundler"}, Vector: "config-file", ConfigFiles: []string{"Gemfile", "Gemfile.lock"}, EvalType: "sh"},
	{Name: "gradle", Commands: []string{"gradle", "gradlew", "./gradlew"}, Vector: "config-file", ConfigFiles: []string{"build.gradle", "settings.gradle", "build.gradle.kts"}, EvalType: "groovy"},
	{Name: "maven", Commands: []string{"mvn", "mvnw", "./mvnw"}, Vector: "config-file", ConfigFiles: []string{"pom.xml", ".mvn/extensions.xml"}, EvalType: "sh"},
	{Name: "ant", Commands: []string{"ant"}, Vector: "config-file", ConfigFiles: []string{"build.xml"}, EvalType: "sh"},
	{Name: "msbuild", Commands: []string{"msbuild", "dotnet build", "dotnet test", "dotnet run"}, Vector: "config-file", ConfigFiles: []string{"*.csproj", "*.fsproj", "Directory.Build.props"}, EvalType: "sh"},

	// Code quality / linting
	{Name: "eslint", Commands: []string{"eslint"}, Vector: "config-file", ConfigFiles: []string{".eslintrc", ".eslintrc.js", ".eslintrc.json", "eslint.config.js"}, EvalType: "js"},
	{Name: "stylelint", Commands: []string{"stylelint"}, Vector: "config-file", ConfigFiles: []string{".stylelintrc", "stylelint.config.js"}, EvalType: "js"},
	{Name: "prettier", Commands: []string{"prettier"}, Vector: "config-file", ConfigFiles: []string{".prettierrc", ".prettierrc.js", "prettier.config.js"}, EvalType: "js"},
	{Name: "pylint", Commands: []string{"pylint"}, Vector: "config-file", ConfigFiles: []string{".pylintrc", "pyproject.toml", "setup.cfg"}, EvalType: "py"},
	{Name: "flake8", Commands: []string{"flake8"}, Vector: "config-file", ConfigFiles: []string{".flake8", "setup.cfg", "tox.ini"}, EvalType: "py"},
	{Name: "mypy", Commands: []string{"mypy"}, Vector: "config-file", ConfigFiles: []string{"mypy.ini", ".mypy.ini", "setup.cfg", "pyproject.toml"}, EvalType: "py"},
	{Name: "rubocop", Commands: []string{"rubocop"}, Vector: "config-file", ConfigFiles: []string{".rubocop.yml"}, EvalType: "sh"},
	{Name: "phpstan", Commands: []string{"phpstan"}, Vector: "config-file", ConfigFiles: []string{"phpstan.neon", "phpstan.neon.dist"}, EvalType: "sh"},
	{Name: "checkov", Commands: []string{"checkov"}, Vector: "config-file", ConfigFiles: []string{".checkov.yaml", ".checkov.yml"}, EvalType: "py"},
	{Name: "sonar-scanner", Commands: []string{"sonar-scanner", "sonarqube"}, Vector: "config-file", ConfigFiles: []string{"sonar-project.properties"}, EvalType: "sh"},
	{Name: "vale", Commands: []string{"vale"}, Vector: "config-file", ConfigFiles: []string{".vale.ini"}, EvalType: "bin"},
	{Name: "golangci-lint", Commands: []string{"golangci-lint"}, Vector: "config-file", ConfigFiles: []string{".golangci.yml", ".golangci.yaml", ".golangci-lint.yml"}, EvalType: "go"},
	{Name: "trivy", Commands: []string{"trivy"}, Vector: "config-file", ConfigFiles: []string{"trivy.yaml", "trivy.yml"}, EvalType: "bin"},

	// Build automation / task runners
	{Name: "make", Commands: []string{"make"}, Vector: "config-file", ConfigFiles: []string{"Makefile", "GNUmakefile", "makefile"}, EvalType: "sh"},
	{Name: "rake", Commands: []string{"rake"}, Vector: "config-file", ConfigFiles: []string{"Rakefile", "Rakefile.rb"}, EvalType: "sh"},
	{Name: "just", Commands: []string{"just"}, Vector: "config-file", ConfigFiles: []string{"justfile", "Justfile", ".justfile"}, EvalType: "sh"},
	{Name: "earthly", Commands: []string{"earthly"}, Vector: "config-file", ConfigFiles: []string{"Earthfile"}, EvalType: "sh"},
	{Name: "gauge", Commands: []string{"gauge"}, Vector: "config-file", ConfigFiles: []string{"manifest.json"}, EvalType: "sh"},
	{Name: "goreleaser", Commands: []string{"goreleaser"}, Vector: "config-file", ConfigFiles: []string{".goreleaser.yml", ".goreleaser.yaml"}, EvalType: "sh"},
	{Name: "danger", Commands: []string{"danger"}, Vector: "config-file", ConfigFiles: []string{"Dangerfile", ".dangerfile.rb"}, EvalType: "sh"},
	{Name: "pre-commit", Commands: []string{"pre-commit"}, Vector: "config-file", ConfigFiles: []string{".pre-commit-config.yaml"}, EvalType: "sh"},
	{Name: "webpack", Commands: []string{"webpack"}, Vector: "config-file", ConfigFiles: []string{"webpack.config.js", "webpack.config.ts"}, EvalType: "js"},
	{Name: "deno", Commands: []string{"deno"}, Vector: "config-file", ConfigFiles: []string{"deno.json", "deno.jsonc"}, EvalType: "js"},
	{Name: "mage", Commands: []string{"mage"}, Vector: "config-file", ConfigFiles: []string{"magefile.go", "Magefile.go"}, EvalType: "go"},
	{Name: "gomplate", Commands: []string{"gomplate"}, Vector: "config-file", ConfigFiles: []string{".gomplate/", "gomplate.yaml"}, EvalType: "sh"},

	// Infrastructure / deployment
	{Name: "terraform", Commands: []string{"terraform"}, Vector: "input-file", ConfigFiles: []string{"*.tf", "*.tfvars"}, EvalType: "sh"},
	{Name: "tflint", Commands: []string{"tflint"}, Vector: "config-file", ConfigFiles: []string{".tflint.hcl"}, EvalType: "sh"},
	{Name: "docker", Commands: []string{"docker build", "docker buildx"}, Vector: "config-file", ConfigFiles: []string{"Dockerfile", ".dockerignore"}, EvalType: "sh"},
	{Name: "gcloud", Commands: []string{"gcloud"}, Vector: "config-file", ConfigFiles: []string{".gcloudignore", "app.yaml"}, EvalType: "sh"},
	{Name: "wrangler", Commands: []string{"wrangler"}, Vector: "config-file", ConfigFiles: []string{"wrangler.toml"}, EvalType: "sh"},

	// Testing
	{Name: "pytest", Commands: []string{"pytest"}, Vector: "config-file", ConfigFiles: []string{"pytest.ini", "pyproject.toml", "conftest.py", "setup.cfg"}, EvalType: "py"},

	// Documentation
	{Name: "mkdocs", Commands: []string{"mkdocs"}, Vector: "config-file", ConfigFiles: []string{"mkdocs.yml"}, EvalType: "py"},

	// Go tools
	{Name: "go generate", Commands: []string{"go generate"}, Vector: "input-file", ConfigFiles: []string{"*.go (//go:generate directives)"}, EvalType: "sh"},

	// Scripting / processing (env-var attack vector)
	{Name: "wget", Commands: []string{"wget"}, Vector: "env-var", ConfigFiles: []string{".wgetrc"}, EvalType: "sh"},
}

// DetectLOTPTools scans a set of script lines and returns all LOTP tools detected.
// A tool is detected when its command appears at the start of a script line.
func DetectLOTPTools(scripts []string) []LOTPTool {
	var found []LOTPTool
	seen := map[string]bool{}
	for _, line := range scripts {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, tool := range lotpCatalog {
			if seen[tool.Name] {
				continue
			}
			for _, cmd := range tool.Commands {
				if lotpCommandMatches(cmd, lower) {
					found = append(found, tool)
					seen[tool.Name] = true
					break
				}
			}
		}
	}
	return found
}

// lotpCommandMatches returns true if cmd appears at the start of line, followed by
// a word boundary (space, tab) or end of string. Both cmd and line must be lowercase.
func lotpCommandMatches(cmd, line string) bool {
	if !strings.HasPrefix(line, cmd) {
		return false
	}
	if len(line) == len(cmd) {
		return true // exact match
	}
	next := line[len(cmd)]
	return next == ' ' || next == '\t'
}
