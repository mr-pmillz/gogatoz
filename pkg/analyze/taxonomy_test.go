package analyze

import (
	"fmt"
	"regexp"
	"testing"
)

func TestLookupTaxonomy_KnownID(t *testing.T) {
	tax := LookupTaxonomy("VARIABLE_INJECTION")
	if tax == nil {
		t.Fatal("expected taxonomy for VARIABLE_INJECTION, got nil")
	}
	if len(tax.CWEs) == 0 {
		t.Error("VARIABLE_INJECTION should have at least one CWE")
	}
	if len(tax.OWASPCICDRefs) == 0 {
		t.Error("VARIABLE_INJECTION should have at least one OWASP CI/CD ref")
	}
}

func TestLookupTaxonomy_UnknownID(t *testing.T) {
	tax := LookupTaxonomy("NONEXISTENT_FINDING_ID")
	if tax != nil {
		t.Errorf("expected nil for unknown finding, got %+v", tax)
	}
}

func TestAllRegisteredFindingsHaveTaxonomy(t *testing.T) {
	for id := range findingCodeRegistry {
		tax := LookupTaxonomy(id)
		if tax == nil {
			t.Errorf("finding %q has no taxonomy mapping", id)
			continue
		}
		if len(tax.CWEs) == 0 {
			t.Errorf("finding %q has empty CWEs", id)
		}
		if len(tax.OWASPCICDRefs) == 0 {
			t.Errorf("finding %q has empty OWASPCICDRefs", id)
		}
	}
}

func TestTaxonomyCWEIDsArePositive(t *testing.T) {
	for id, tax := range taxonomyRegistry {
		for _, cwe := range tax.CWEs {
			if cwe.ID <= 0 {
				t.Errorf("finding %q has invalid CWE ID %d", id, cwe.ID)
			}
			if cwe.Name == "" {
				t.Errorf("finding %q has CWE-%d with empty name", id, cwe.ID)
			}
		}
	}
}

var attackIDPattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func TestTaxonomyATTACKIDsAreValid(t *testing.T) {
	for id, tax := range taxonomyRegistry {
		for _, ref := range tax.ATTACKRefs {
			if !attackIDPattern.MatchString(ref.ID) {
				t.Errorf("finding %q has invalid ATT&CK ID %q (want T####[.###])", id, ref.ID)
			}
			if ref.Name == "" {
				t.Errorf("finding %q has ATT&CK %q with empty name", id, ref.ID)
			}
		}
	}
}

var owaspCICDPattern = regexp.MustCompile(`^CICD-SEC-([1-9]|10)$`)

func TestTaxonomyOWASPCICDIDsAreValid(t *testing.T) {
	for id, tax := range taxonomyRegistry {
		for _, ref := range tax.OWASPCICDRefs {
			if !owaspCICDPattern.MatchString(ref.ID) {
				t.Errorf("finding %q has invalid OWASP CI/CD ID %q (want CICD-SEC-[1-10])", id, ref.ID)
			}
			if ref.Name == "" {
				t.Errorf("finding %q has OWASP %q with empty name", id, ref.ID)
			}
		}
	}
}

func TestTaxonomyMergedIntoFindingCodeInfo(t *testing.T) {
	info := LookupFinding("VARIABLE_INJECTION")
	if info == nil {
		t.Fatal("VARIABLE_INJECTION not in finding registry")
	}
	if len(info.Taxonomy.CWEs) == 0 {
		t.Error("FindingCodeInfo.Taxonomy.CWEs should be populated after init")
	}
	if len(info.Taxonomy.ATTACKRefs) == 0 {
		t.Error("FindingCodeInfo.Taxonomy.ATTACKRefs should be populated after init")
	}
	if len(info.Taxonomy.OWASPCICDRefs) == 0 {
		t.Error("FindingCodeInfo.Taxonomy.OWASPCICDRefs should be populated after init")
	}
}

func TestAllTaxonomies_ReturnsCopy(t *testing.T) {
	all := AllTaxonomies()
	if len(all) == 0 {
		t.Fatal("AllTaxonomies returned empty map")
	}
	if len(all) != len(taxonomyRegistry) {
		t.Errorf("AllTaxonomies returned %d entries, registry has %d", len(all), len(taxonomyRegistry))
	}

	// Mutating the returned map should not affect the registry.
	delete(all, "VARIABLE_INJECTION")
	if LookupTaxonomy("VARIABLE_INJECTION") == nil {
		t.Error("deleting from AllTaxonomies result should not affect registry")
	}
}

func TestTaxonomyRegistryCoversAllFindingCodes(t *testing.T) {
	for id := range findingCodeRegistry {
		if _, ok := taxonomyRegistry[id]; !ok {
			t.Errorf("finding code %q is in findingCodeRegistry but not in taxonomyRegistry", id)
		}
	}
}

func TestTaxonomyRegistryHasNoOrphanEntries(t *testing.T) {
	for id := range taxonomyRegistry {
		if _, ok := findingCodeRegistry[id]; !ok {
			t.Errorf("taxonomy entry %q has no corresponding finding code in findingCodeRegistry", id)
		}
	}
}

func taxonomyHasCWE(tax *Taxonomy, id int) bool {
	for _, c := range tax.CWEs {
		if c.ID == id {
			return true
		}
	}
	return false
}

func taxonomyHasATTACK(tax *Taxonomy, id string) bool {
	for _, a := range tax.ATTACKRefs {
		if a.ID == id {
			return true
		}
	}
	return false
}

func taxonomyHasOWASPCICD(tax *Taxonomy, id string) bool {
	for _, o := range tax.OWASPCICDRefs {
		if o.ID == id {
			return true
		}
	}
	return false
}

func TestTaxonomySpecificMappings(t *testing.T) {
	tests := []struct {
		findingID string
		wantCWE   int
		wantATT   string
		wantOWASP string
	}{
		{"PLAINTEXT_SECRET", 312, "T1552.001", "CICD-SEC-6"},
		{IncludeRemoteID, 829, "T1195.002", "CICD-SEC-3"},
		{"VARIABLE_INJECTION", 78, "T1059", "CICD-SEC-4"},
		{SelfMergePossibleID, 284, "T1098", "CICD-SEC-1"},
		{CachePoisoningRiskID, 345, "T1565.001", "CICD-SEC-9"},
		{"OIDC_TOKEN_MR_RISK", 284, "T1528", "CICD-SEC-6"},
		{ScriptInjectionRiskID, 94, "T1059", "CICD-SEC-4"},
		{DepConfusionRiskID, 427, "T1195.001", "CICD-SEC-3"},
		{SecretExfilHTTPID, 319, "T1567", "CICD-SEC-6"},
		{DinDDetectedID, 250, "T1611", "CICD-SEC-7"},
	}

	for _, tt := range tests {
		t.Run(tt.findingID, func(t *testing.T) {
			tax := LookupTaxonomy(tt.findingID)
			if tax == nil {
				t.Fatalf("no taxonomy for %q", tt.findingID)
			}
			if !taxonomyHasCWE(tax, tt.wantCWE) {
				t.Errorf("expected CWE-%d in taxonomy for %q, got %v", tt.wantCWE, tt.findingID, tax.CWEs)
			}
			if !taxonomyHasATTACK(tax, tt.wantATT) {
				t.Errorf("expected ATT&CK %s in taxonomy for %q, got %v", tt.wantATT, tt.findingID, tax.ATTACKRefs)
			}
			if !taxonomyHasOWASPCICD(tax, tt.wantOWASP) {
				t.Errorf("expected OWASP %s in taxonomy for %q, got %v", tt.wantOWASP, tt.findingID, tax.OWASPCICDRefs)
			}
		})
	}
}

func TestCWERefFormat(t *testing.T) {
	tax := LookupTaxonomy("PLAINTEXT_SECRET")
	if tax == nil {
		t.Fatal("no taxonomy for PLAINTEXT_SECRET")
	}
	cwe := tax.CWEs[0]
	formatted := fmt.Sprintf("CWE-%d", cwe.ID)
	if formatted != "CWE-312" {
		t.Errorf("formatted CWE = %q, want CWE-312", formatted)
	}
}
