package enumerate

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	ReleaseBranchWeakProtectionID = "RELEASE_BRANCH_WEAK_PROTECTION"
	ReleaseTagWeakProtectionID    = "RELEASE_TAG_WEAK_PROTECTION"
	ReleaseJobBroadTriggerID      = "RELEASE_JOB_BROAD_TRIGGER"
)

var (
	releaseCommandPattern = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)(?:npm|pnpm)\s+publish\b|(?:^|[;&|]\s*)yarn\s+npm\s+publish\b|(?:^|[;&|]\s*)twine\s+upload\b|(?:^|[;&|]\s*)gem\s+push\b|(?:^|[;&|]\s*)cargo\s+publish\b|(?:^|[;&|]\s*)(?:mvn\s+deploy|gradle\s+publish|goreleaser\b|release-cli\s+create\b|glab\s+release\b)`)
	branchLiteralPattern  = regexp.MustCompile(`\$(?:CI_COMMIT_BRANCH|CI_COMMIT_REF_NAME)\s*==\s*["']([^"']+)["']`)
	tagLiteralPattern     = regexp.MustCompile(`\$CI_COMMIT_TAG\s*==\s*["']([^"']+)["']`)
	tagPrefixPattern      = regexp.MustCompile(`\$CI_COMMIT_TAG\s*=~\s*/\^([[:alnum:]_.-]+)`)
)

type releaseProtectionSnapshot struct {
	branches []gitlabx.BranchProtectionDetail
	tags     []gitlabx.TagProtectionDetail
}

type releaseTriggers struct {
	branches    []string
	tags        bool
	tagPatterns []string
	broad       bool
}

func checkReleaseGovernance(
	ctx context.Context,
	cl *gitlabx.Client,
	projectID any,
	defaultBranch string,
	doc *pipeline.Document,
) ([]analyze.Finding, error) {
	if cl == nil || !hasReleaseJobs(doc) {
		return nil, nil
	}
	branches, err := cl.GetProtectedBranchDetails(ctx, projectID, 100)
	if err != nil {
		return nil, fmt.Errorf("get protected release branches: %w", err)
	}
	tags, err := cl.GetProtectedTagDetails(ctx, projectID, 100)
	if err != nil {
		return nil, fmt.Errorf("get protected release tags: %w", err)
	}
	return evaluateReleaseGovernance(doc, defaultBranch, releaseProtectionSnapshot{
		branches: branches,
		tags:     tags,
	}), nil
}

func evaluateReleaseGovernance(
	doc *pipeline.Document,
	defaultBranch string,
	snapshot releaseProtectionSnapshot,
) []analyze.Finding {
	if doc == nil {
		return nil
	}
	slog.Debug("evaluating release governance", "jobs", len(doc.Jobs))
	var findings []analyze.Finding
	for _, job := range doc.Jobs {
		if !isReleaseJob(job, doc) {
			continue
		}
		triggers := extractReleaseTriggers(job, doc, defaultBranch)
		if triggers.broad {
			findings = append(findings, broadReleaseFinding(job.Name))
		}
		for _, branch := range triggers.branches {
			findings = append(findings, evaluateReleaseBranch(job.Name, branch, snapshot.branches)...)
		}
		if triggers.tags {
			for _, pattern := range triggers.tagPatterns {
				findings = append(findings, evaluateReleaseTag(job.Name, pattern, snapshot.tags)...)
			}
		}
	}
	slog.Debug("release governance evaluated", "findings", len(findings))
	return findings
}

func hasReleaseJobs(doc *pipeline.Document) bool {
	if doc == nil {
		return false
	}
	for _, job := range doc.Jobs {
		if isReleaseJob(job, doc) {
			return true
		}
	}
	return false
}

func isReleaseJob(job pipeline.Job, doc *pipeline.Document) bool {
	if doc != nil {
		if rawJob, ok := doc.Raw[job.Name].(map[string]any); ok {
			if _, ok := rawJob["release"]; ok {
				return true
			}
		}
	}
	for _, command := range job.Script {
		if releaseCommandPattern.MatchString(strings.TrimSpace(command)) {
			return true
		}
	}
	return false
}

func extractReleaseTriggers(job pipeline.Job, _ *pipeline.Document, defaultBranch string) releaseTriggers {
	triggers := releaseTriggers{}
	hasRules := job.Rules != nil
	hasOnly := job.Only != nil
	if hasRules {
		extractRuleTriggers(job.Rules, defaultBranch, &triggers)
	}
	if hasOnly {
		extractOnlyTriggers(job.Only, &triggers)
	}
	if !hasRules && !hasOnly {
		triggers.broad = true
	}
	triggers.branches = sortedUnique(triggers.branches)
	triggers.tagPatterns = sortedUnique(triggers.tagPatterns)
	if triggers.tags && len(triggers.tagPatterns) == 0 {
		triggers.tagPatterns = []string{"*"}
	}
	return triggers
}

func extractRuleTriggers(value any, defaultBranch string, triggers *releaseTriggers) {
	for _, item := range anySlice(value) {
		rule, ok := item.(map[string]any)
		if !ok || strings.EqualFold(strings.TrimSpace(fmt.Sprint(rule["when"])), "never") {
			continue
		}
		condition := strings.TrimSpace(fmt.Sprint(rule["if"]))
		if condition == "" {
			triggers.broad = true
			continue
		}
		matched := false
		for _, groups := range branchLiteralPattern.FindAllStringSubmatch(condition, -1) {
			triggers.branches = append(triggers.branches, groups[1])
			matched = true
		}
		if strings.Contains(condition, "CI_DEFAULT_BRANCH") &&
			(strings.Contains(condition, "CI_COMMIT_BRANCH") || strings.Contains(condition, "CI_COMMIT_REF_NAME")) {
			if strings.TrimSpace(defaultBranch) != "" {
				triggers.branches = append(triggers.branches, defaultBranch)
			}
			matched = true
		}
		if strings.Contains(condition, "CI_COMMIT_TAG") {
			triggers.tags = true
			matched = true
			if groups := tagLiteralPattern.FindStringSubmatch(condition); len(groups) == 2 {
				triggers.tagPatterns = append(triggers.tagPatterns, groups[1])
			} else if groups := tagPrefixPattern.FindStringSubmatch(condition); len(groups) == 2 {
				triggers.tagPatterns = append(triggers.tagPatterns, groups[1]+"*")
			} else {
				triggers.tagPatterns = append(triggers.tagPatterns, "*")
			}
		}
		if !matched && (strings.Contains(condition, "CI_COMMIT_BRANCH") ||
			strings.Contains(condition, "CI_COMMIT_REF_NAME")) {
			triggers.broad = true
		}
	}
}

func extractOnlyTriggers(value any, triggers *releaseTriggers) {
	var refs []any
	switch typed := value.(type) {
	case map[string]any:
		refs = anySlice(typed["refs"])
	default:
		refs = anySlice(value)
	}
	for _, item := range refs {
		ref := strings.TrimSpace(fmt.Sprint(item))
		switch {
		case ref == "tags":
			triggers.tags = true
			triggers.tagPatterns = append(triggers.tagPatterns, "*")
		case ref == "branches" || ref == "*":
			triggers.broad = true
		case strings.HasPrefix(ref, "/") && strings.Contains(ref, "^v"):
			triggers.tags = true
			triggers.tagPatterns = append(triggers.tagPatterns, "v*")
		case ref != "":
			triggers.branches = append(triggers.branches, ref)
		}
	}
}

func evaluateReleaseBranch(jobName, branch string, details []gitlabx.BranchProtectionDetail) []analyze.Finding {
	detail, ok := bestBranchProtection(branch, details)
	if !ok {
		return []analyze.Finding{{
			ID: ReleaseBranchWeakProtectionID, Severity: analyze.SeverityHigh,
			Title: "Publishing branch is not protected", JobName: jobName,
			Description: "A branch that can publish releases has no matching protection rule, so an unreviewed commit may reach the package registry.",
			Evidence:    "job=" + jobName + " branch=" + branch + " protection=none",
		}}
	}
	var findings []analyze.Finding
	if detail.PushAccessLevel >= 30 || detail.AllowForcePush {
		findings = append(findings, analyze.Finding{
			ID: ReleaseBranchWeakProtectionID, Severity: analyze.SeverityHigh,
			Title: "Publishing branch permits unreviewed changes", JobName: jobName,
			Description: "A branch that can publish releases permits developer direct pushes or force pushes, bypassing reviewed commits.",
			Evidence: fmt.Sprintf("job=%s branch=%s push_access_level=%s allow_force_push=%t",
				jobName, branch, accessLevelName(detail.PushAccessLevel), detail.AllowForcePush),
		})
	}
	if !detail.CodeOwnerApprovalNeeded && detail.MergeAccessLevel >= 30 {
		findings = append(findings, analyze.Finding{
			ID: ReleaseBranchWeakProtectionID, Severity: analyze.SeverityMedium,
			Title: "Publishing branch lacks code-owner approval", JobName: jobName,
			Description: "Changes to a branch that can publish releases do not require code-owner approval.",
			Evidence: fmt.Sprintf("job=%s branch=%s code_owner_approval=false merge_access_level=%s",
				jobName, branch, accessLevelName(detail.MergeAccessLevel)),
		})
	}
	return findings
}

func evaluateReleaseTag(jobName, triggerPattern string, details []gitlabx.TagProtectionDetail) []analyze.Finding {
	detail, ok := bestTagProtection(triggerPattern, details)
	if !ok {
		return []analyze.Finding{{
			ID: ReleaseTagWeakProtectionID, Severity: analyze.SeverityHigh,
			Title: "Publishing tags are not protected", JobName: jobName,
			Description: "Tags that can publish releases have no matching protection rule, allowing tag creation or recreation outside the reviewed release path.",
			Evidence:    "job=" + jobName + " tag_pattern=" + triggerPattern + " protection=none",
		}}
	}
	if detail.CreateAccessLevel > 0 && detail.CreateAccessLevel <= 30 {
		return []analyze.Finding{{
			ID: ReleaseTagWeakProtectionID, Severity: analyze.SeverityHigh,
			Title: "Publishing tags permit developer creation", JobName: jobName,
			Description: "A protected release-tag rule permits Developers to create tags, so publishing is not limited to trusted maintainers.",
			Evidence: fmt.Sprintf("job=%s tag_pattern=%s protection=%s create_access_level=%s",
				jobName, triggerPattern, detail.Name, accessLevelName(detail.CreateAccessLevel)),
		}}
	}
	return nil
}

func broadReleaseFinding(jobName string) analyze.Finding {
	return analyze.Finding{
		ID: ReleaseJobBroadTriggerID, Severity: analyze.SeverityHigh,
		Title: "Publishing job accepts broad refs", JobName: jobName,
		Description: "A publishing job has no branch or tag restriction that binds releases to a reviewed commit.",
		Evidence:    "job=" + jobName + " release_trigger=broad",
	}
}

func bestBranchProtection(branch string, details []gitlabx.BranchProtectionDetail) (gitlabx.BranchProtectionDetail, bool) {
	var best gitlabx.BranchProtectionDetail
	for _, detail := range details {
		if !wildcardMatches(detail.Name, branch) {
			continue
		}
		if best.Name == "" || detail.Name == branch || len(detail.Name) > len(best.Name) {
			best = detail
		}
	}
	return best, best.Name != ""
}

func bestTagProtection(triggerPattern string, details []gitlabx.TagProtectionDetail) (gitlabx.TagProtectionDetail, bool) {
	var best gitlabx.TagProtectionDetail
	for _, detail := range details {
		if !patternCovers(detail.Name, triggerPattern) {
			continue
		}
		if best.Name == "" || detail.Name == triggerPattern || len(detail.Name) > len(best.Name) {
			best = detail
		}
	}
	return best, best.Name != ""
}

func patternCovers(protection, trigger string) bool {
	if protection == "*" || protection == trigger {
		return true
	}
	if !strings.ContainsAny(trigger, "*?") {
		return wildcardMatches(protection, trigger)
	}
	if strings.HasSuffix(protection, "*") && strings.HasSuffix(trigger, "*") {
		return strings.HasPrefix(strings.TrimSuffix(trigger, "*"), strings.TrimSuffix(protection, "*"))
	}
	return false
}

func wildcardMatches(pattern, value string) bool {
	if pattern == value || pattern == "*" {
		return true
	}
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*`)
	quoted = strings.ReplaceAll(quoted, `\?`, `.`)
	matched, err := regexp.MatchString("^"+quoted+"$", value)
	return err == nil && matched
}

func anySlice(value any) []any {
	if value == nil {
		return nil
	}
	if values, ok := value.([]any); ok {
		return values
	}
	return []any{value}
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
