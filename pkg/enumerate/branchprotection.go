package enumerate

import (
	"context"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

const WeakBranchProtectionID = "WEAK_BRANCH_PROTECTION"

func checkBranchProtection(ctx context.Context, cl *gitlabx.Client, projectID any, defaultBranch string) []analyze.Finding {
	if cl == nil || defaultBranch == "" {
		return nil
	}
	details, err := cl.GetProtectedBranchDetails(ctx, projectID, 100)
	if err != nil {
		return nil
	}

	for _, d := range details {
		if d.Name != defaultBranch {
			continue
		}
		var findings []analyze.Finding
		// Developer (30) or higher push access = risky
		if d.PushAccessLevel >= 30 {
			findings = append(findings, analyze.Finding{
				ID:       WeakBranchProtectionID,
				Severity: analyze.SeverityHigh,
				Title:    "Default branch allows direct push by developers",
				Description: "The default branch allows push access at Developer level or above without requiring a merge request. " +
					"Compromised developer credentials can push malicious code directly, bypassing code review. " +
					"This is the attack vector used in the Injective and AsyncAPI supply chain campaigns.",
				Evidence: "branch=" + d.Name + " push_access_level=" + accessLevelName(d.PushAccessLevel),
			})
		}
		if d.AllowForcePush {
			findings = append(findings, analyze.Finding{
				ID:       WeakBranchProtectionID,
				Severity: analyze.SeverityHigh,
				Title:    "Default branch allows force push",
				Description: "Force push is allowed on the default branch. Attackers can rewrite git history " +
					"to remove evidence of malicious commits or replace legitimate commits with backdoored versions.",
				Evidence: "branch=" + d.Name + " allow_force_push=true",
			})
		}
		if !d.CodeOwnerApprovalNeeded && d.MergeAccessLevel >= 30 {
			findings = append(findings, analyze.Finding{
				ID:       WeakBranchProtectionID,
				Severity: analyze.SeverityMedium,
				Title:    "Default branch does not require code owner approval",
				Description: "Merge requests to the default branch do not require code owner approval. " +
					"This reduces the barrier for merging malicious changes if a developer account is compromised.",
				Evidence: "branch=" + d.Name + " code_owner_approval=false merge_access_level=" + accessLevelName(d.MergeAccessLevel),
			})
		}
		return findings
	}

	// Default branch not in protected branches list at all
	return []analyze.Finding{{
		ID:       WeakBranchProtectionID,
		Severity: analyze.SeverityHigh,
		Title:    "Default branch is not protected",
		Description: "The default branch (" + defaultBranch + ") has no branch protection rules. " +
			"Any project member can push directly, force push, or delete the branch.",
		Evidence: "branch=" + defaultBranch + " protection=none",
	}}
}

func accessLevelName(level int) string {
	switch level {
	case 0:
		return "no_access"
	case 5:
		return "minimal_access"
	case 10:
		return "guest"
	case 20:
		return "reporter"
	case 30:
		return "developer"
	case 40:
		return "maintainer"
	case 50:
		return "owner"
	case 60:
		return "admin"
	default:
		return "unknown"
	}
}
