package analyze

import (
	"regexp"
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/stringutil"
)

const DepConfusionRiskID = "DEP_CONFUSION_RISK"

var (
	npmScopedPkgRe  = regexp.MustCompile(`npm\s+(?:install|i|add|ci)\s+(?:[^-]\S*\s+)*(@[a-z][a-z0-9._-]*/[a-z][a-z0-9._-]*)`)
	pipInternalRe   = regexp.MustCompile(`pip[3]?\s+install\s+.*\b([a-z][a-z0-9_-]*-(?:internal|private|core|common|shared|utils|lib|sdk|api|client|proto|models)[a-z0-9_-]*)\b`)
	goInternalRe    = regexp.MustCompile(`go\s+(?:get|install)\s+.*\b([a-z][a-z0-9.-]+\.(?:internal|corp|local)\b[^\s]*)`)
	privateRegVarRe = regexp.MustCompile(`(?i)\$\{?(?:NPM_REGISTRY|PIP_INDEX_URL|GOPROXY|MAVEN_REPO|PYPI_URL)\}?`)

	wellKnownPublicScopes = map[string]bool{
		"@types": true, "@babel": true, "@angular": true, "@vue": true,
		"@react": true, "@emotion": true, "@testing-library": true,
		"@eslint": true, "@typescript-eslint": true, "@jest": true,
		"@storybook": true, "@rollup": true, "@vitejs": true,
		"@sveltejs": true, "@nuxtjs": true, "@nestjs": true,
		"@aws-sdk": true, "@azure": true, "@google-cloud": true,
		"@octokit": true, "@fortawesome": true, "@mui": true,
		"@reduxjs": true, "@tanstack": true, "@trpc": true,
		"@prisma": true, "@sentry": true, "@grpc": true,
	}
)

func detectDependencyConfusion(doc *pipeline.Document) []Finding {
	var findings []Finding
	if doc == nil {
		return findings
	}
	for _, job := range doc.Jobs {
		lines := effectiveScripts(job, doc)
		refs := extractPrivatePackageRefs(lines)
		if len(refs) == 0 {
			continue
		}
		usesPrivateReg := slices.ContainsFunc(lines, privateRegVarRe.MatchString)
		for _, ref := range refs {
			sev := SeverityMedium
			desc := "CI configuration installs a package with a private-looking name. " +
				"If no namespace is claimed on the public registry, an attacker can publish a higher-version " +
				"package to hijack the dependency resolution."
			if usesPrivateReg {
				sev = SeverityHigh
				desc += " A private registry variable is configured, confirming internal package usage."
			}
			findings = append(findings, Finding{
				ID:          DepConfusionRiskID,
				Severity:    sev,
				Title:       "Dependency confusion risk: " + ref.ecosystem + " package " + ref.name,
				Description: desc,
				Evidence:    stringutil.TruncateEvidence("pkg="+ref.name+" eco="+ref.ecosystem+" line="+ref.evidence, 200),
				JobName:     job.Name,
			})
		}
	}
	return findings
}

type depRef struct {
	name      string
	ecosystem string
	evidence  string
}

func extractPrivatePackageRefs(lines []string) []depRef {
	var refs []depRef
	seen := map[string]bool{}
	for _, line := range lines {
		if m := npmScopedPkgRe.FindStringSubmatch(line); len(m) >= 2 {
			pkg := m[1]
			parts := strings.SplitN(pkg, "/", 2)
			if len(parts) < 2 {
				continue
			}
			scope := parts[0]
			if !wellKnownPublicScopes[scope] && !seen[pkg] {
				seen[pkg] = true
				refs = append(refs, depRef{name: pkg, ecosystem: "npm", evidence: strings.TrimSpace(line)})
			}
		}
		if m := pipInternalRe.FindStringSubmatch(line); len(m) >= 2 {
			pkg := m[1]
			if !seen[pkg] {
				seen[pkg] = true
				refs = append(refs, depRef{name: pkg, ecosystem: "pip", evidence: strings.TrimSpace(line)})
			}
		}
		if m := goInternalRe.FindStringSubmatch(line); len(m) >= 2 {
			pkg := m[1]
			if !seen[pkg] {
				seen[pkg] = true
				refs = append(refs, depRef{name: pkg, ecosystem: "go", evidence: strings.TrimSpace(line)})
			}
		}
	}
	return refs
}
