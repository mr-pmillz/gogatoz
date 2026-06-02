package c2

import (
	"context"
	"strings"
	"testing"
)

type fakeRepo struct {
	exist        map[string]bool
	deleted      []string
	deletedFiles []string
	commits      []struct{ branch, yaml, msg string }
}

func (f *fakeRepo) BranchExists(_ context.Context, _ any, branch string) (bool, error) {
	if f.exist == nil {
		f.exist = map[string]bool{}
	}
	return f.exist[branch], nil
}
func (f *fakeRepo) DeleteBranch(_ context.Context, _ any, branch string) error {
	f.deleted = append(f.deleted, branch)
	if f.exist != nil {
		delete(f.exist, branch)
	}
	return nil
}
func (f *fakeRepo) DeleteFile(_ context.Context, _ any, branch, path, message string) error {
	f.deletedFiles = append(f.deletedFiles, branch+":"+path+":"+message)
	return nil
}
func (f *fakeRepo) CommitCIPipeline(_ context.Context, _ any, branch, yamlContent, message string) (string, error) {
	f.commits = append(f.commits, struct{ branch, yaml, msg string }{branch: branch, yaml: yamlContent, msg: message})
	return "https://gitlab.example.com/group/proj/-/pipelines?ref=" + branch, nil
}

func TestEnsureBranchName_Suffix(t *testing.T) {
	fr := &fakeRepo{exist: map[string]bool{"gogatoz-c2": true}}
	b, err := ensureBranchName(context.Background(), fr, "proj", "gogatoz-c2", "suffix")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if b != "gogatoz-c2-1" {
		t.Fatalf("expected suffix -1, got %s", b)
	}
}

func TestController_StartAndStop(t *testing.T) {
	fr := &fakeRepo{exist: map[string]bool{"stage": true}}
	ctrl := &Controller{r: fr}
	url, branch, yaml, err := ctrl.StartSession(context.Background(), StartOptions{
		ProjectID:        "group/proj",
		Branch:           "stage",
		Deconflict:       "suffix",
		JobName:          "c2",
		KeepAliveSeconds: 5,
		Tags:             []string{"self-hosted"},
	})
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	if branch != "stage-1" {
		t.Fatalf("expected stage-1, got %s", branch)
	}
	if url == "" || !strings.Contains(url, branch) {
		t.Fatalf("unexpected url: %s", url)
	}
	if len(fr.commits) != 1 {
		t.Fatalf("expected one commit, got %d", len(fr.commits))
	}
	if strings.TrimSpace(yaml) == "" || !strings.Contains(yaml, "stages:") {
		t.Fatalf("yaml looks wrong: %q", yaml)
	}

	// Stop session should delete CI file (best-effort) and the branch
	if err := ctrl.StopSession(context.Background(), "group/proj", branch, true); err != nil {
		t.Fatalf("stop session: %v", err)
	}
	if len(fr.deleted) != 1 || fr.deleted[0] != branch {
		t.Fatalf("expected branch deleted %v", fr.deleted)
	}
	if len(fr.deletedFiles) == 0 {
		t.Fatalf("expected CI file deletion attempt")
	}
}
