package analyze

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

// --- DEBUG_TRACE_ENABLED tests ---

func TestDebugTrace_GlobalVarTrue(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"CI_DEBUG_TRACE": "true",
		},
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"echo hello"},
		}},
	}
	findings := detectDebugTrace(doc, nil)
	if !hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("expected %s finding for global CI_DEBUG_TRACE=true, got: %+v", DebugTraceEnabledID, findings)
	}
	// Verify severity is critical
	for _, f := range findings {
		if f.ID == DebugTraceEnabledID && f.Severity != SeverityCritical {
			t.Fatalf("expected CRITICAL severity, got %s", f.Severity)
		}
	}
}

func TestDebugTrace_GlobalVarOne(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"CI_DEBUG_TRACE": "1",
		},
	}
	findings := detectDebugTrace(doc, nil)
	if !hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("expected %s finding for CI_DEBUG_TRACE=1, got: %+v", DebugTraceEnabledID, findings)
	}
}

func TestDebugTrace_GlobalVarYes(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"CI_DEBUG_TRACE": "YES",
		},
	}
	findings := detectDebugTrace(doc, nil)
	if !hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("expected %s finding for CI_DEBUG_TRACE=YES (case-insensitive), got: %+v", DebugTraceEnabledID, findings)
	}
}

func TestDebugTrace_JobVarTrue(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "debug-job",
			Script: []string{"echo test"},
			Variables: map[string]any{
				"CI_DEBUG_TRACE": "true",
			},
		}},
	}
	findings := detectDebugTrace(doc, nil)
	if !hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("expected %s finding for job-level CI_DEBUG_TRACE=true, got: %+v", DebugTraceEnabledID, findings)
	}
	// Verify job name is captured
	for _, f := range findings {
		if f.ID == DebugTraceEnabledID && f.JobName != "debug-job" {
			t.Fatalf("expected JobName=debug-job, got %q", f.JobName)
		}
	}
}

func TestDebugTrace_DebugServices(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"CI_DEBUG_SERVICES": "true",
		},
	}
	findings := detectDebugTrace(doc, nil)
	if !hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("expected %s finding for CI_DEBUG_SERVICES=true, got: %+v", DebugTraceEnabledID, findings)
	}
}

func TestDebugTrace_VarFalse_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"CI_DEBUG_TRACE": "false",
		},
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"echo hello"},
			Variables: map[string]any{
				"CI_DEBUG_SERVICES": "0",
			},
		}},
	}
	findings := detectDebugTrace(doc, nil)
	if hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("did not expect %s finding for false/0 values, got: %+v", DebugTraceEnabledID, findings)
	}
}

func TestDebugTrace_VarMissing_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"OTHER_VAR": "true",
		},
		Jobs: []pipeline.Job{{
			Name:   "build",
			Script: []string{"echo hello"},
		}},
	}
	findings := detectDebugTrace(doc, nil)
	if hasFindingID(findings, DebugTraceEnabledID) {
		t.Fatalf("did not expect %s finding when debug vars are absent, got: %+v", DebugTraceEnabledID, findings)
	}
}

func TestDebugTrace_NilDoc(t *testing.T) {
	findings := detectDebugTrace(nil, nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for nil doc, got: %+v", findings)
	}
}

// --- UNVERIFIED_SCRIPT_EXEC tests ---

func TestUnverifiedScript_Base64Bash(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "sneaky",
			Script: []string{"echo $PAYLOAD | base64 -d | bash"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("expected %s finding for base64|bash, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_Base64DecodeSh(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "decode",
			Script: []string{"base64 --decode payload.b64 | sh"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("expected %s finding for base64 --decode|sh, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_CurlDownloadThenExec(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"curl -o setup.sh https://example.com/setup.sh && bash setup.sh"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("expected %s finding for curl -o then exec, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_WgetDownloadThenExec(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"wget -O installer.sh https://example.com/install.sh && chmod +x installer.sh && ./installer.sh"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("expected %s finding for wget -O then exec, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_CurlRedirectExec(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install",
			Script: []string{"curl https://example.com/script > run.sh; chmod +x run.sh; ./run.sh"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("expected %s finding for curl redirect then exec, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_WithVerification_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "verified",
			Script: []string{"curl -o setup.sh https://example.com/setup.sh && sha256sum -c checksums.txt && bash setup.sh"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("did not expect %s finding when sha256sum verification is present, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_WithGPGVerify_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "gpg-verified",
			Script: []string{"curl -o setup.sh https://example.com/setup.sh && gpg --verify setup.sh.sig setup.sh && bash setup.sh"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("did not expect %s finding when gpg --verify is present, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_WithCosignVerify_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "cosign-verified",
			Script: []string{"curl -o binary https://example.com/bin && cosign verify binary && ./binary"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("did not expect %s finding when cosign verify is present, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_SafeDownload_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "download-only",
			Script: []string{"curl -o artifact.tar.gz https://example.com/artifact.tar.gz"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("did not expect %s finding for download without execution, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_BeforeScript(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:         "job-with-before",
			BeforeScript: []string{"echo $ENCODED | base64 -d | bash"},
			Script:       []string{"echo safe"},
		}},
	}
	findings := detectUnverifiedScriptExec(doc)
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Fatalf("expected %s finding in before_script, got: %+v", UnverifiedScriptExecID, findings)
	}
}

func TestUnverifiedScript_NilDoc(t *testing.T) {
	findings := detectUnverifiedScriptExec(nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for nil doc, got: %+v", findings)
	}
}

// --- UNPINNED_PACKAGE_INSTALL tests ---

func TestUnpinnedPackage_PipInstallNaked(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install-deps",
			Script: []string{"pip install requests"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("expected %s finding for pip install without version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_PipInstallPinned_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install-deps",
			Script: []string{"pip install requests==2.31.0"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding for pip install with ==version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_PipRequirements_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "install-deps",
			Script: []string{"pip install -r requirements.txt"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding for pip install -r, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_NpmInstallNaked(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "setup",
			Script: []string{"npm install lodash"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("expected %s finding for npm install without @version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_NpmInstallPinned_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "setup",
			Script: []string{"npm install lodash@4.17.21"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding for npm install with @version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_NpmCi_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "setup",
			Script: []string{"npm ci"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding for npm ci (uses lockfile), got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_GemInstallNaked(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "ruby-setup",
			Script: []string{"gem install bundler"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("expected %s finding for gem install without --version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_GemInstallPinned_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "ruby-setup",
			Script: []string{"gem install bundler --version 2.4.0"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding for gem install with --version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_GoInstallNaked(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "tools",
			Script: []string{"go install golang.org/x/tools/cmd/goimports"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("expected %s finding for go install without @version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_GoInstallPinned_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "tools",
			Script: []string{"go install golang.org/x/tools/cmd/goimports@latest"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding for go install with @version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_ApkAddNaked(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "alpine-setup",
			Script: []string{"apk add curl git"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("expected %s finding for apk add without =version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_AptGetInstallNaked(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "debian-setup",
			Script: []string{"apt-get install -y curl"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("expected %s finding for apt-get install without =version, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_PackageLockPresent_NoFinding(t *testing.T) {
	doc := &pipeline.Document{
		Jobs: []pipeline.Job{{
			Name:   "setup",
			Script: []string{"npm install --prefer-offline package-lock.json"},
		}},
	}
	findings := detectUnpinnedPackageInstall(doc)
	if hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Fatalf("did not expect %s finding when package-lock.json is referenced, got: %+v", UnpinnedPackageInstallID, findings)
	}
}

func TestUnpinnedPackage_NilDoc(t *testing.T) {
	findings := detectUnpinnedPackageInstall(nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for nil doc, got: %+v", findings)
	}
}

// --- Integration: verify findings appear via Run() ---

func TestCompliance_RunIntegration(t *testing.T) {
	doc := &pipeline.Document{
		Variables: map[string]any{
			"CI_DEBUG_TRACE": "true",
		},
		Jobs: []pipeline.Job{
			{
				Name:   "sneaky-build",
				Script: []string{"echo $PAYLOAD | base64 -d | bash"},
			},
			{
				Name:   "deps",
				Script: []string{"pip install requests"},
			},
		},
	}
	findings, err := Run(doc)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !hasFindingID(findings, DebugTraceEnabledID) {
		t.Errorf("expected %s finding via Run()", DebugTraceEnabledID)
	}
	if !hasFindingID(findings, UnverifiedScriptExecID) {
		t.Errorf("expected %s finding via Run()", UnverifiedScriptExecID)
	}
	if !hasFindingID(findings, UnpinnedPackageInstallID) {
		t.Errorf("expected %s finding via Run()", UnpinnedPackageInstallID)
	}
}
