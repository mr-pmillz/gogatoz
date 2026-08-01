//go:build !e2e

package payloads

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePackageTamperYAMLPreviewOnly(t *testing.T) {
	tests := []struct {
		name     string
		opts     PackageTamperOptions
		contains []string
	}{
		{
			name: "npm postinstall",
			opts: PackageTamperOptions{
				Ecosystem: "npm",
				Trigger:   "postinstall",
			},
			contains: []string{"node:lts-alpine", "postinstall", "package.json"},
		},
		{
			name: "npm preinstall",
			opts: PackageTamperOptions{
				Ecosystem: "npm",
				Trigger:   "preinstall",
			},
			contains: []string{"node:lts-alpine", "preinstall", "package.json"},
		},
		{
			name: "npm import entry",
			opts: PackageTamperOptions{
				Ecosystem: "npm",
				Trigger:   "import",
				EntryFile: "src/index.js",
			},
			contains: []string{"src/index.js", "trigger=import", "base64 -d"},
		},
		{
			name: "Python import entry",
			opts: PackageTamperOptions{
				Ecosystem: "pypi",
				Trigger:   "import",
				EntryFile: "src/acme_fixture/__init__.py",
			},
			contains: []string{"python:3.13-alpine", "src/acme_fixture/__init__.py", "trigger=import"},
		},
		{
			name: "Ruby import entry",
			opts: PackageTamperOptions{
				Ecosystem: "rubygems",
				Trigger:   "import",
				EntryFile: "lib/acme_fixture.rb",
			},
			contains: []string{"ruby:3.4-alpine", "lib/acme_fixture.rb", "trigger=import"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml, err := GeneratePackageTamperYAML(tt.opts)
			if err != nil {
				t.Fatalf("GeneratePackageTamperYAML() error = %v", err)
			}
			_ = mustParse(t, yaml)
			for _, want := range append([]string{
				"Authorized Package Tamper Preview",
				"mode=preview",
				"package-tamper-preview.tar.gz",
				"printenv | sort > env.txt",
				"when: manual",
			}, tt.contains...) {
				if !strings.Contains(yaml, want) {
					t.Errorf("expected %q in output:\n%s", want, yaml)
				}
			}
			for _, forbidden := range []string{
				"npm publish", "twine upload", "gem push", "npm install",
				"npm run", "pip install", "gem install", "npm access list",
			} {
				if strings.Contains(yaml, forbidden) {
					t.Errorf("preview contains executable/publishing command %q:\n%s", forbidden, yaml)
				}
			}
		})
	}
}

func TestGeneratePackageTamperYAMLLivePublishGates(t *testing.T) {
	tests := []struct {
		name     string
		opts     PackageTamperOptions
		contains []string
	}{
		{
			name: "npm",
			opts: PackageTamperOptions{
				Ecosystem:            "npm",
				Trigger:              "preinstall",
				PackageName:          "acme-owned-fixture",
				RegistryURL:          "https://registry.npmjs.org",
				LivePublish:          true,
				AllowPublicRegistry:  true,
				PublishAuthorization: "publish:npm:acme-owned-fixture",
			},
			contains: []string{"npm publish", "--ignore-scripts", "publish:npm:acme-owned-fixture"},
		},
		{
			name: "PyPI",
			opts: PackageTamperOptions{
				Ecosystem:            "pypi",
				Trigger:              "import",
				EntryFile:            "src/acme_fixture/__init__.py",
				PackageName:          "acme-owned-fixture",
				RegistryURL:          "https://packages.example.test/pypi",
				LivePublish:          true,
				PublishAuthorization: "publish:pypi:acme-owned-fixture",
			},
			contains: []string{"python -m build", "python -m twine upload", "publish:pypi:acme-owned-fixture"},
		},
		{
			name: "RubyGems",
			opts: PackageTamperOptions{
				Ecosystem:            "rubygems",
				Trigger:              "import",
				EntryFile:            "lib/acme_fixture.rb",
				PackageName:          "acme-owned-fixture",
				RegistryURL:          "https://gems.example.test",
				LivePublish:          true,
				PublishAuthorization: "publish:rubygems:acme-owned-fixture",
			},
			contains: []string{"gem build", "gem push", "publish:rubygems:acme-owned-fixture"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml, err := GeneratePackageTamperYAML(tt.opts)
			if err != nil {
				t.Fatalf("GeneratePackageTamperYAML() error = %v", err)
			}
			_ = mustParse(t, yaml)
			for _, want := range append([]string{
				"GOGATOZ_PACKAGE_TAMPER_APPROVED",
				"GOGATOZ_EXPECTED_PACKAGE",
				"package identity mismatch",
				"mode=live-publish",
				"when: manual",
			}, tt.contains...) {
				if !strings.Contains(yaml, want) {
					t.Errorf("expected %q in output:\n%s", want, yaml)
				}
			}
			for _, forbidden := range []string{"npm access list", "NPM_CONFIG_TOKEN", "NODE_AUTH_TOKEN"} {
				if strings.Contains(yaml, forbidden) {
					t.Errorf("live payload contains credential discovery %q:\n%s", forbidden, yaml)
				}
			}
		})
	}
}

func TestPackageTamperPreviewMutatesOnlyAnIsolatedCopy(t *testing.T) {
	projectDir := t.TempDir()
	entryPath := filepath.Join(projectDir, "src", "acme_fixture", "__init__.py")
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("VALUE = 1\n")
	if err := os.WriteFile(entryPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	yaml, err := GeneratePackageTamperYAML(PackageTamperOptions{
		Ecosystem:      "pypi",
		Trigger:        "import",
		EntryFile:      "src/acme_fixture/__init__.py",
		InjectedScript: `open("SHOULD_NOT_EXIST", "w").write("executed")`,
	})
	if err != nil {
		t.Fatalf("GeneratePackageTamperYAML() error = %v", err)
	}
	document := mustParse(t, yaml)
	if len(document.Jobs) != 1 || len(document.Jobs[0].Script) != 1 {
		t.Fatalf("unexpected generated jobs: %+v", document.Jobs)
	}
	command := exec.Command("sh", "-c", document.Jobs[0].Script[0]) //nolint:gosec // Executes only locally generated preview shell in an isolated test directory.
	command.Dir = projectDir
	command.Env = append(os.Environ(), "CI_PROJECT_DIR="+projectDir)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("preview command failed: %v\n%s", runErr, output)
	}
	if _, statErr := os.Stat(filepath.Join(projectDir, "SHOULD_NOT_EXIST")); !os.IsNotExist(statErr) {
		t.Fatalf("injected Python unexpectedly executed: %v", statErr)
	}
	gotOriginal, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotOriginal) != string(original) {
		t.Fatalf("source checkout was modified: %q", gotOriginal)
	}
	previewEntry := readTarGzipMember(t, filepath.Join(projectDir, "package-tamper-preview.tar.gz"), "./src/acme_fixture/__init__.py")
	if !strings.Contains(previewEntry, "SHOULD_NOT_EXIST") {
		t.Fatalf("preview archive does not contain inert injected content: %q", previewEntry)
	}
}

func TestPackageTamperPreviewRejectsSymlinkEntry(t *testing.T) {
	projectDir := t.TempDir()
	targetPath := filepath.Join(projectDir, "outside.py")
	if err := os.WriteFile(targetPath, []byte("SAFE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entryPath := filepath.Join(projectDir, "src", "acme_fixture", "__init__.py")
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, entryPath); err != nil {
		t.Fatal(err)
	}

	yaml, err := GeneratePackageTamperYAML(PackageTamperOptions{
		Ecosystem: "pypi", Trigger: "import", EntryFile: "src/acme_fixture/__init__.py",
	})
	if err != nil {
		t.Fatalf("GeneratePackageTamperYAML() error = %v", err)
	}
	document := mustParse(t, yaml)
	command := exec.Command("sh", "-c", document.Jobs[0].Script[0]) //nolint:gosec // Executes only locally generated preview shell in an isolated test directory.
	command.Dir = projectDir
	command.Env = append(os.Environ(), "CI_PROJECT_DIR="+projectDir)
	if output, runErr := command.CombinedOutput(); runErr == nil {
		t.Fatalf("preview accepted symlink entry:\n%s", output)
	}
	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "SAFE\n" {
		t.Fatalf("symlink target was modified: %q", content)
	}
}

func readTarGzipMember(t *testing.T, archivePath, memberPath string) string {
	t.Helper()
	file, err := os.Open(archivePath) //nolint:gosec // Test-controlled temporary path.
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		if header.Name != memberPath {
			continue
		}
		content, readErr := io.ReadAll(tarReader)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return string(content)
	}
	t.Fatalf("archive member %q not found", memberPath)
	return ""
}

func TestGeneratePackageTamperYAMLRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name string
		opts PackageTamperOptions
		want string
	}{
		{name: "ecosystem", opts: PackageTamperOptions{Ecosystem: "cargo"}, want: "ecosystem"},
		{name: "Python lifecycle", opts: PackageTamperOptions{Ecosystem: "pypi", Trigger: "postinstall"}, want: "trigger"},
		{name: "import needs entry", opts: PackageTamperOptions{Ecosystem: "npm", Trigger: "import"}, want: "entry file"},
		{name: "entry traversal", opts: PackageTamperOptions{Ecosystem: "pypi", Trigger: "import", EntryFile: "../setup.py"}, want: "entry file"},
		{name: "live package", opts: PackageTamperOptions{Ecosystem: "npm", LivePublish: true}, want: "package name"},
		{
			name: "live registry",
			opts: PackageTamperOptions{
				Ecosystem: "npm", LivePublish: true, PackageName: "owned",
				PublishAuthorization: "publish:npm:owned",
			},
			want: "registry",
		},
		{
			name: "wrong authorization",
			opts: PackageTamperOptions{
				Ecosystem: "npm", LivePublish: true, PackageName: "owned",
				RegistryURL: "https://packages.example.test", PublishAuthorization: "yes",
			},
			want: "publish authorization",
		},
		{
			name: "public registry",
			opts: PackageTamperOptions{
				Ecosystem: "npm", LivePublish: true, PackageName: "owned",
				RegistryURL: "https://registry.npmjs.org", PublishAuthorization: "publish:npm:owned",
			},
			want: "public registry",
		},
		{
			name: "remote HTTP",
			opts: PackageTamperOptions{
				Ecosystem: "npm", LivePublish: true, PackageName: "owned",
				RegistryURL: "http://packages.example.test", PublishAuthorization: "publish:npm:owned",
			},
			want: "HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GeneratePackageTamperYAML(tt.opts)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.want)) {
				t.Fatalf("GeneratePackageTamperYAML() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLegacyNpmTamperWrapperIsPreviewOnly(t *testing.T) {
	yaml := GenerateNpmTamperYAML(NpmTamperOptions{})
	_ = mustParse(t, yaml)
	if strings.Contains(yaml, "npm publish") || strings.Contains(yaml, "npm run") {
		t.Fatalf("legacy npm wrapper must be preview-only:\n%s", yaml)
	}
}
