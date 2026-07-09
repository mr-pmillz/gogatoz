package enumerate

import (
	"context"
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// GetDefaultBranch returns the default branch name for a project or an empty string if not set.
func GetDefaultBranch(ctx context.Context, cl *gitlabx.Client, projectID any) (string, error) {
	if cl == nil {
		return "", fmt.Errorf("nil client")
	}
	p, _, err := cl.GL.Projects.GetProject(projectID, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return p.DefaultBranch, nil
}

// FileExists returns true if a given file path exists at ref in the project repository.
func FileExists(ctx context.Context, cl *gitlabx.Client, projectID any, ref, path string) (bool, error) {
	if cl == nil {
		return false, fmt.Errorf("nil client")
	}
	if path == "" {
		return false, fmt.Errorf("path is required")
	}
	_, resp, err := cl.GL.RepositoryFiles.GetFile(projectID, path, &gitlab.GetFileOptions{Ref: new(ref)}, gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListRefs lists up to limit branches for the project (names only). If limit<=0, returns up to one page (100).
func ListRefs(ctx context.Context, cl *gitlabx.Client, projectID any, limit int) ([]string, error) {
	if cl == nil {
		return nil, fmt.Errorf("nil client")
	}
	out := []string{}
	var page int64 = 1
	var per int64 = 100
	if limit > 0 && int64(limit) < per {
		per = int64(limit)
	}
	for {
		branches, resp, err := cl.GL.Branches.ListBranches(projectID, &gitlab.ListBranchesOptions{ListOptions: gitlab.ListOptions{Page: page, PerPage: per}}, gitlab.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		for _, b := range branches {
			if b == nil {
				continue
			}
			out = append(out, b.Name)
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return out, nil
}
