package artifactverify

import "testing"

func TestAnalyzeFilesRecognizesDeveloperToolPersistencePaths(t *testing.T) {
	t.Parallel()

	paths := []string{
		"package/.claude/setup.mjs",
		"package/.codex/config.toml",
		"package/AGENTS.md",
		"package/.gemini/settings.json",
		"package/.kiro/steering/project.md",
		"package/.vscode/tasks.json",
		"package/node_modules/@vscode/deviceid/dist/index.js",
		"package/GitHub Desktop/resources/app/main.js",
		"package/lib/node_modules/npm/bin/npm-cli.js",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			findings := analyzeFiles([]FileRecord{{Path: path, content: []byte("synthetic fixture")}})
			found := false
			for _, finding := range findings {
				if finding.ID == "PACKAGE_PERSISTENCE_INDICATOR" {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing persistence finding for %s: %+v", path, findings)
			}
		})
	}
}
