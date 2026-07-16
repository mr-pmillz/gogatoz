package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

// SARIF 2.1.0 types (minimal subset for CI/CD findings).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool       `json:"tool"`
	Results    []sarifResult   `json:"results"`
	Taxonomies []sarifTaxonomy `json:"taxonomies,omitempty"`
}

type sarifTaxonomy struct {
	Name           string     `json:"name"`
	Index          int        `json:"index"`
	Organization   string     `json:"organization"`
	ShortDesc      sarifText  `json:"shortDescription"`
	InformationURI string     `json:"informationUri,omitempty"`
	Taxa           []sarifTax `json:"taxa,omitempty"`
}

type sarifTax struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	ShortDesc   sarifText `json:"shortDescription"`
}

type sarifRelationship struct {
	Target sarifRelTarget `json:"target"`
	Kinds  []string       `json:"kinds"`
}

type sarifRelTarget struct {
	ID            string                `json:"id"`
	ToolComponent sarifToolComponentRef `json:"toolComponent"`
}

type sarifToolComponentRef struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name,omitempty"`
	ShortDescription     sarifText           `json:"shortDescription"`
	FullDescription      *sarifText          `json:"fullDescription,omitempty"`
	Help                 *sarifText          `json:"help,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig         `json:"defaultConfiguration"`
	Properties           map[string]any      `json:"properties,omitempty"`
	Relationships        []sarifRelationship `json:"relationships,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps an analyze.Severity to a SARIF result level.
func sarifLevel(sev analyze.Severity) string {
	switch sev {
	case analyze.SeverityCritical, analyze.SeverityHigh:
		return "error"
	case analyze.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifSecuritySeverity maps an analyze.Severity to a CVSS-like score string
// for GitHub Code Scanning severity bucketing.
func sarifSecuritySeverity(sev analyze.Severity) string {
	switch sev {
	case analyze.SeverityCritical:
		return "9.5"
	case analyze.SeverityHigh:
		return "8.0"
	case analyze.SeverityMedium:
		return "5.0"
	case analyze.SeverityLow:
		return "2.0"
	default:
		return "1.0"
	}
}

// buildSARIF constructs a SARIF 2.1.0 log from analyze findings.
//
// Findings with an empty ID are skipped. Each unique finding ID produces one
// rule entry; every finding produces a result. Rule metadata is sourced from
// the analyze.LookupFinding registry, falling back to the finding's own
// Title/Description when the ID is not registered.
func buildSARIF(findings []analyze.Finding, toolVersion string) sarifLog {
	type ruleState struct {
		index      int
		maxSev     analyze.Severity
		maxSevRank int
	}
	seenRules := make(map[string]*ruleState)
	var rules []sarifRule
	var results []sarifResult

	sevRank := func(s analyze.Severity) int {
		switch s {
		case analyze.SeverityCritical:
			return 4
		case analyze.SeverityHigh:
			return 3
		case analyze.SeverityMedium:
			return 2
		case analyze.SeverityLow:
			return 1
		default:
			return 0
		}
	}

	for _, f := range findings {
		if f.ID == "" {
			continue
		}

		// Build or update the rule for this finding ID.
		if st, exists := seenRules[f.ID]; exists {
			if rank := sevRank(f.Severity); rank > st.maxSevRank {
				st.maxSev = f.Severity
				st.maxSevRank = rank
				rules[st.index].DefaultConfiguration.Level = sarifLevel(f.Severity)
				rules[st.index].Properties["security-severity"] = sarifSecuritySeverity(f.Severity)
			}
		} else {
			title := f.Title
			desc := f.Description
			sev := f.Severity
			var helpText string
			var helpURI string

			if info := analyze.LookupFinding(f.ID); info != nil {
				title = info.Title
				desc = info.Description
				helpText = info.Remediation
				helpURI = info.DocURL
			}

			props := map[string]any{
				"security-severity": sarifSecuritySeverity(sev),
			}

			var tags []string
			var rels []sarifRelationship

			if tax := analyze.LookupTaxonomy(f.ID); tax != nil {
				for _, cwe := range tax.CWEs {
					tags = append(tags, fmt.Sprintf("external/cwe/cwe-%d", cwe.ID))
				}
				for _, owasp := range tax.OWASPCICDRefs {
					tags = append(tags, "external/owasp-cicd/"+owasp.ID)
				}
				for _, att := range tax.ATTACKRefs {
					tags = append(tags, "external/mitre-attack/"+att.ID)
				}
				for _, cwe := range tax.CWEs {
					rels = append(rels, sarifRelationship{
						Target: sarifRelTarget{
							ID:            fmt.Sprintf("CWE-%d", cwe.ID),
							ToolComponent: sarifToolComponentRef{Name: "CWE", Index: 0},
						},
						Kinds: []string{"superset"},
					})
				}
			}

			if len(tags) > 0 {
				props["tags"] = tags
			}

			r := sarifRule{
				ID:               f.ID,
				Name:             f.ID,
				ShortDescription: sarifText{Text: title},
				DefaultConfiguration: sarifConfig{
					Level: sarifLevel(sev),
				},
				Properties:    props,
				Relationships: rels,
			}
			if desc != "" {
				r.FullDescription = &sarifText{Text: desc}
			}
			if helpText != "" {
				r.Help = &sarifText{Text: helpText}
			}
			if helpURI != "" {
				r.HelpURI = helpURI
			}

			seenRules[f.ID] = &ruleState{index: len(rules), maxSev: sev, maxSevRank: sevRank(sev)}
			rules = append(rules, r)
		}

		// Build the result.
		msg := f.Evidence
		if msg == "" {
			msg = f.Description
		}

		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{
							URI: ".gitlab-ci.yml",
						},
					},
				},
			},
		}
		results = append(results, res)
	}

	cweTaxa := buildCWETaxa(rules)

	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:           "GoGatoZ",
				InformationURI: "https://github.com/mr-pmillz/gogatoz",
				Version:        toolVersion,
				Rules:          rules,
			},
		},
		Results: results,
	}

	if len(cweTaxa) > 0 {
		run.Taxonomies = []sarifTaxonomy{
			{
				Name:         "CWE",
				Index:        0,
				Organization: "MITRE",
				ShortDesc:    sarifText{Text: "The MITRE Common Weakness Enumeration"},
				InformationURI: "https://cwe.mitre.org/",
				Taxa:         cweTaxa,
			},
		}
	}

	return sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
}

// buildCWETaxa extracts unique CWE entries referenced by SARIF rules.
func buildCWETaxa(rules []sarifRule) []sarifTax {
	seen := map[string]bool{}
	var taxa []sarifTax

	for _, r := range rules {
		for _, rel := range r.Relationships {
			if rel.Target.ToolComponent.Name != "CWE" {
				continue
			}
			id := rel.Target.ID
			if seen[id] {
				continue
			}
			seen[id] = true
			taxa = append(taxa, sarifTax{
				ID:        id,
				ShortDesc: sarifText{Text: id},
			})
		}
	}
	return taxa
}

// WriteSARIF marshals the findings as a SARIF 2.1.0 JSON document and writes
// the result to w.
func WriteSARIF(w io.Writer, findings []analyze.Finding, toolVersion string) error {
	s := buildSARIF(findings, toolVersion)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
