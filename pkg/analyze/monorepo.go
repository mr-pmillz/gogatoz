package analyze

import (
	"fmt"
	"path"
	"strings"
)

const MonorepoCorrelationID = "MONOREPO_CORRELATION"

// MonorepoSignal represents correlation data from a single project result.
type MonorepoSignal struct {
	ProjectPath     string
	CommitMessage   string
	AuthorEmail     string
	CIConfigChanged bool
}

// DetectMonorepoCorrelation identifies coordinated suspicious activity across
// multiple projects in the same namespace — same commit message, same author,
// CI config changes in a tight cluster.
func DetectMonorepoCorrelation(signals []MonorepoSignal) []Finding {
	var findings []Finding
	if len(signals) < 3 {
		return findings
	}

	byNamespace := map[string][]MonorepoSignal{}
	for _, s := range signals {
		ns := path.Dir(s.ProjectPath)
		if ns == "." || ns == "" {
			continue
		}
		byNamespace[ns] = append(byNamespace[ns], s)
	}

	for ns, group := range byNamespace {
		if len(group) < 3 {
			continue
		}
		findings = append(findings, detectMessageCorrelation(ns, group)...)
		findings = append(findings, detectAuthorCorrelation(ns, group)...)
	}
	return findings
}

func detectMessageCorrelation(ns string, signals []MonorepoSignal) []Finding {
	var findings []Finding
	msgCount := map[string][]string{}
	for _, s := range signals {
		msg := strings.TrimSpace(s.CommitMessage)
		if msg == "" {
			continue
		}
		msgCount[msg] = append(msgCount[msg], s.ProjectPath)
	}
	for msg, projects := range msgCount {
		if len(projects) < 3 {
			continue
		}
		findings = append(findings, Finding{
			ID:       MonorepoCorrelationID,
			Severity: SeverityHigh,
			Title:    "Coordinated commits across monorepo projects",
			Description: "The same commit message appears across " +
				strings.Join(projects[:min(3, len(projects))], ", ") +
				" and more. This pattern matches supply chain attacks like Injective (18 packages in one train).",
			Evidence: truncateEvidence("ns="+ns+" msg="+msg+" count="+fmt.Sprintf("%d", len(projects)), 200),
			JobName:  ns,
		})
	}
	return findings
}

func detectAuthorCorrelation(ns string, signals []MonorepoSignal) []Finding {
	var findings []Finding
	authorCI := map[string][]string{}
	for _, s := range signals {
		if s.CIConfigChanged && s.AuthorEmail != "" {
			authorCI[s.AuthorEmail] = append(authorCI[s.AuthorEmail], s.ProjectPath)
		}
	}
	for author, projects := range authorCI {
		if len(projects) < 3 {
			continue
		}
		findings = append(findings, Finding{
			ID:       MonorepoCorrelationID,
			Severity: SeverityHigh,
			Title:    "Single author modified CI across multiple projects",
			Description: "Author " + author + " changed CI configuration in " +
				fmt.Sprintf("%d", len(projects)) + " projects within the same namespace. " +
				"Coordinated CI changes by a single author are a supply chain compromise indicator.",
			Evidence: truncateEvidence("ns="+ns+" author="+author+" projects="+strings.Join(projects, ","), 200),
			JobName:  ns,
		})
	}
	return findings
}
