package analyze

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const SpecInputsInjectionRiskID = "SPEC_INPUTS_INJECTION_RISK"

var yamlMetaChars = []string{":", "\n", "#", "|", ">", "\\n"}

func detectSpecInputsRisk(doc *pipeline.Document) []Finding {
	var findings []Finding

	rawIncludes, ok := doc.Raw["include"]
	if !ok {
		return nil
	}

	includes := normalizeIncludesForInputs(rawIncludes)
	for _, inc := range includes {
		m, ok := inc.(map[string]any)
		if !ok {
			continue
		}
		inputs, ok := m["inputs"].(map[string]any)
		if !ok {
			continue
		}

		for key, val := range inputs {
			strVal, ok := val.(string)
			if !ok {
				continue
			}
			if containsYAMLMetaChars(strVal) {
				findings = append(findings, Finding{
					ID:       SpecInputsInjectionRiskID,
					Severity: SeverityMedium,
					Title:    "spec:inputs value contains YAML metacharacters",
					Description: "Include input '" + key + "' contains YAML metacharacters " +
						"that could break out of the interpolation context. If an attacker controls " +
						"this input value, they can inject arbitrary CI/CD configuration.",
					Evidence: stringutil.TruncateEvidence("input."+key+"="+strVal, 200),
				})
			}
		}
	}

	return findings
}

func normalizeIncludesForInputs(raw any) []any {
	switch v := raw.(type) {
	case []any:
		return v
	case map[string]any:
		return []any{v}
	default:
		return nil
	}
}

func containsYAMLMetaChars(s string) bool {
	for _, meta := range yamlMetaChars {
		if strings.Contains(s, meta) {
			return true
		}
	}
	return false
}
