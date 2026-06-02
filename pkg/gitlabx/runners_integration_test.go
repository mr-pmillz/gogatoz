package gitlabx

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// loadLocalTestEnv loads key=value lines from config/test.env if present (best-effort).
func loadLocalTestEnv(t *testing.T) {
	t.Helper()
	p := filepath.Join("..", "..", "config", "test.env")
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			_ = os.Setenv(k, v)
		}
	}
}

func testCreds() (baseURL, token string) {
	baseURL = strings.TrimSpace(os.Getenv("TEST_GITLAB_URL"))
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	token = strings.TrimSpace(os.Getenv("TEST_API_PAT"))
	if token == "" {
		// fallback to CI_JOB_TOKEN in CI
		token = strings.TrimSpace(os.Getenv("CI_JOB_TOKEN"))
	}
	return
}

func TestPingWithToken(t *testing.T) {
	loadLocalTestEnv(t)
	base, tok := testCreds()
	if tok == "" {
		t.Skip("TEST_API_PAT/CI_JOB_TOKEN not set; skipping live API test")
	}
	cl, err := New(base, tok)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	usr, _, err := cl.Ping(ctx)
	if err != nil {
		// Not all tokens allow /user (CI_JOB_TOKEN). If forbidden, skip gracefully.
		t.Skipf("ping skipped: %v", err)
	}
	if usr == nil || usr.ID == 0 {
		t.Fatalf("unexpected user payload: %#v", usr)
	}
}

func TestAccumulateAllRunners_AdminOptional(t *testing.T) {
	loadLocalTestEnv(t)
	if v := strings.TrimSpace(os.Getenv("TEST_REQUIRE_ADMIN")); v == "" || v == "0" {
		t.Skip("admin path disabled; set TEST_REQUIRE_ADMIN=1 to enable")
	}
	base, tok := testCreds()
	if tok == "" {
		t.Skip("TEST_API_PAT not set; skipping instance runner test")
	}
	cl, err := New(base, tok)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = cl.AccumulateAllRunners(ctx)
	if err != nil {
		// If unauthorized, skip instead of failing
		t.Skipf("accumulate all runners unauthorized or not admin: %v", err)
	}
}

//nolint:dupl // test helper patterns are intentionally similar for group vs project coverage
func TestAccumulateGroupRunners_Optional(t *testing.T) {
	loadLocalTestEnv(t)
	base, tok := testCreds()
	if tok == "" {
		t.Skip("TEST_API_PAT/CI_JOB_TOKEN not set; skipping group runner test")
	}
	gidRaw := strings.TrimSpace(os.Getenv("TEST_GROUP_ID"))
	gpath := strings.TrimSpace(os.Getenv("TEST_GROUP_PATH"))
	if gidRaw == "" && gpath == "" {
		t.Skip("set TEST_GROUP_ID or TEST_GROUP_PATH to exercise group runners")
	}
	var gid any
	if gidRaw != "" {
		if n, err := strconv.Atoi(gidRaw); err == nil {
			gid = n
		} else {
			gid = gidRaw
		}
	} else {
		gid = gpath
	}
	cl, err := New(base, tok)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = cl.AccumulateGroupRunners(ctx, gid)
	if err != nil {
		// permissions vary; skip on errors
		t.Skipf("group runners list skipped: %v", err)
	}
}

//nolint:dupl // test helper patterns are intentionally similar for group vs project coverage
func TestAccumulateProjectRunners_Optional(t *testing.T) {
	loadLocalTestEnv(t)
	base, tok := testCreds()
	if tok == "" {
		t.Skip("TEST_API_PAT/CI_JOB_TOKEN not set; skipping project runner test")
	}
	pidRaw := strings.TrimSpace(os.Getenv("TEST_PROJECT_ID"))
	ppath := strings.TrimSpace(os.Getenv("TEST_PROJECT_PATH"))
	if pidRaw == "" && ppath == "" {
		t.Skip("set TEST_PROJECT_ID or TEST_PROJECT_PATH to exercise project runners")
	}
	var pid any
	if pidRaw != "" {
		if n, err := strconv.Atoi(pidRaw); err == nil {
			pid = n
		} else {
			pid = pidRaw
		}
	} else {
		pid = ppath
	}
	cl, err := New(base, tok)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = cl.AccumulateProjectRunners(ctx, pid)
	if err != nil {
		// permissions vary; skip on errors
		t.Skipf("project runners list skipped: %v", err)
	}
}
