package cmd

import (
	"strings"
	"testing"
)

func TestRenderPackageTamperPayloadDefaultsToPreview(t *testing.T) {
	atkPayload = "package-tamper"
	atkTamperEcosystem = "pypi"
	atkTamperTrigger = "import"
	atkTamperEntryFile = "src/acme_fixture/__init__.py"
	defer resetPackageTamperTestFlags()

	yaml, err := renderPayload()
	if err != nil {
		t.Fatalf("renderPayload() error = %v", err)
	}
	if !strings.Contains(yaml, "mode=preview") {
		t.Fatalf("renderPayload() missing preview marker:\n%s", yaml)
	}
	for _, forbidden := range []string{"twine upload", "python -m build"} {
		if strings.Contains(yaml, forbidden) {
			t.Fatalf("preview contains live command %q:\n%s", forbidden, yaml)
		}
	}
}

func TestRenderPackageTamperPayloadRequiresExplicitLiveAuthorization(t *testing.T) {
	atkPayload = "package-tamper"
	atkTamperEcosystem = "npm"
	atkTamperPackageName = "acme-owned-fixture"
	atkTamperRegistry = "https://packages.example.test/npm"
	atkTamperLivePublish = true
	defer resetPackageTamperTestFlags()

	_, err := renderPayload()
	if err == nil || !strings.Contains(err.Error(), "publish authorization") {
		t.Fatalf("renderPayload() error = %v, want publish authorization", err)
	}
}

func TestLegacyNpmPayloadUsesSafeGenericPreview(t *testing.T) {
	atkPayload = "npm-tamper"
	defer resetPackageTamperTestFlags()

	yaml, err := renderPayload()
	if err != nil {
		t.Fatalf("renderPayload() error = %v", err)
	}
	if !strings.Contains(yaml, "mode=preview") || strings.Contains(yaml, "npm publish") {
		t.Fatalf("legacy npm payload is not preview-only:\n%s", yaml)
	}
}

func resetPackageTamperTestFlags() {
	atkPayload = ""
	atkPackageTamper = false
	atkNpmTamper = false
	atkTamperEcosystem = ""
	atkTamperRegistry = ""
	atkTamperPackageName = ""
	atkTamperTrigger = ""
	atkTamperEntryFile = ""
	atkTamperInjectScript = ""
	atkTamperLivePublish = false
	atkTamperPublishAuthorization = ""
	atkTamperAllowPublicRegistry = false
	atkNpmRegistry = ""
	atkNpmPackage = ""
	atkNpmInjectScript = ""
}
