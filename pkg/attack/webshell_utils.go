package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// terminalJobStatuses is the set of GitLab CI job statuses that indicate completion.
var terminalJobStatuses = map[string]bool{
	"success":  true,
	"failed":   true,
	"canceled": true,
	"skipped":  true,
}

// ISOTimeNow returns current UTC time in RFC3339 without sub-second precision.
func ISOTimeNow() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

// PollWithTimeout polls fn every interval until it returns true or timeout elapses.
// If fn returns an error, it is surfaced and polling stops.
func PollWithTimeout(ctx context.Context, interval, timeout time.Duration, fn func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// immediate attempt
	ok, err := fn(ctx)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				return fmt.Errorf("timeout waiting for condition: %w", ctx.Err())
			}
			return fmt.Errorf("timeout waiting for condition")
		case <-t.C:
			ok, err := fn(ctx)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
	}
}

// WaitForPipelineForRef polls GitLab for the latest pipeline on a project (optionally by ref)
// and returns its ID when a pipeline with ID > minID is found, or an error on timeout.
// Pass minID=0 to accept any pipeline; pass the ID of the latest pre-existing pipeline to
// wait for a NEW pipeline (avoiding returning one created before the current commit).
func WaitForPipelineForRef(ctx context.Context, client *gitlabx.Client, projectID any, ref string, minID int64, interval, timeout time.Duration) (int64, error) {
	if client == nil {
		return 0, fmt.Errorf("nil client")
	}
	var foundID int64
	pid := fmt.Sprintf("%v", projectID)
	pidEsc := url.PathEscape(pid)
	buildReq := func() (*http.Request, error) {
		qs := "per_page=1&order_by=id&sort=desc"
		if strings.TrimSpace(ref) != "" {
			qs += "&ref=" + url.QueryEscape(ref)
		}
		u := client.APIURL(fmt.Sprintf("/api/v4/projects/%s/pipelines?%s", pidEsc, qs))
		return http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	}
	check := func(_ context.Context) (bool, error) {
		req, err := buildReq()
		if err != nil {
			return false, err
		}
		if tok := client.Token(); tok != "" {
			req.Header.Set("PRIVATE-TOKEN", tok)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.HTTPClient().Do(req) //nolint:gosec
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, fmt.Errorf("list pipelines: http %d", resp.StatusCode)
		}
		var arr []struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
			return false, err
		}
		if len(arr) == 0 {
			return false, nil
		}
		foundID = arr[0].ID
		return foundID > minID, nil
	}
	if err := PollWithTimeout(ctx, interval, timeout, check); err != nil {
		return 0, err
	}
	return foundID, nil
}

// WaitForExfilPipeline polls recent pipelines on a branch for a job with the given name
// and waits until that job reaches a terminal state. It searches across the 5 most recent
// pipelines each tick so it tolerates branch-creation pipelines appearing before the exfil
// CI commit pipeline. Returns pipelineID, jobID, and terminal status string.
//
//nolint:gocognit // network IO orchestration; intentional complexity
func WaitForExfilPipeline(ctx context.Context, client *gitlabx.Client, projectID any, ref, jobName string, interval, timeout time.Duration) (pipelineID, jobID int64, status string, err error) {
	if client == nil {
		return 0, 0, "", fmt.Errorf("nil client")
	}
	pidEsc := url.PathEscape(fmt.Sprintf("%v", projectID))
	check := func(_ context.Context) (bool, error) {
		pipes, perr := listRecentPipelines(ctx, client, pidEsc, ref, 5)
		if perr != nil {
			return false, perr
		}
		for _, pipe := range pipes {
			found, jID, jStatus, ferr := findJobInPipeline(ctx, client, pidEsc, pipe, jobName)
			if ferr != nil {
				continue
			}
			if found {
				pipelineID = pipe
				jobID = jID
				if terminalJobStatuses[jStatus] {
					status = jStatus
					return true, nil
				}
				return false, nil
			}
		}
		return false, nil
	}
	if err = PollWithTimeout(ctx, interval, timeout, check); err != nil {
		return pipelineID, jobID, status, err
	}
	return pipelineID, jobID, status, nil
}

func listRecentPipelines(ctx context.Context, client *gitlabx.Client, pidEsc, ref string, n int) ([]int64, error) {
	qs := fmt.Sprintf("per_page=%d&order_by=id&sort=desc", n)
	if strings.TrimSpace(ref) != "" {
		qs += "&ref=" + url.QueryEscape(ref)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.APIURL(fmt.Sprintf("/api/v4/projects/%s/pipelines?%s", pidEsc, qs)), nil)
	if err != nil {
		return nil, err
	}
	if tok := client.Token(); tok != "" {
		req.Header.Set("PRIVATE-TOKEN", tok)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.HTTPClient().Do(req) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list pipelines: http %d", resp.StatusCode)
	}
	var pipes []struct {
		ID int64 `json:"id"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&pipes); err != nil {
		return nil, err
	}
	ids := make([]int64, len(pipes))
	for i, p := range pipes {
		ids[i] = p.ID
	}
	return ids, nil
}

func findJobInPipeline(ctx context.Context, client *gitlabx.Client, pidEsc string, pipelineID int64, jobName string) (found bool, jobID int64, status string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.APIURL(fmt.Sprintf("/api/v4/projects/%s/pipelines/%d/jobs?per_page=100", pidEsc, pipelineID)), nil)
	if err != nil {
		return false, 0, "", err
	}
	if tok := client.Token(); tok != "" {
		req.Header.Set("PRIVATE-TOKEN", tok)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.HTTPClient().Do(req) //nolint:gosec
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	var jobs []struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		return false, 0, "", err
	}
	for _, j := range jobs {
		if j.Name == jobName {
			return true, j.ID, j.Status, nil
		}
	}
	return false, 0, "", nil
}

// WaitForJobCompletion polls until the named job in a pipeline reaches a terminal state
// (success, failed, canceled, or skipped). Returns the job ID and terminal status string,
// or an error if the timeout elapses before the job finishes.
func WaitForJobCompletion(ctx context.Context, client *gitlabx.Client, projectID any, pipelineID int64, jobName string, interval, timeout time.Duration) (jobID int64, status string, err error) {
	if client == nil {
		return 0, "", fmt.Errorf("nil client")
	}
	pidEsc := url.PathEscape(fmt.Sprintf("%v", projectID))
	buildReq := func() (*http.Request, error) {
		u := client.APIURL(fmt.Sprintf("/api/v4/projects/%s/pipelines/%d/jobs?per_page=100", pidEsc, pipelineID))
		return http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	}
	check := func(_ context.Context) (bool, error) {
		req, rerr := buildReq()
		if rerr != nil {
			return false, rerr
		}
		if tok := client.Token(); tok != "" {
			req.Header.Set("PRIVATE-TOKEN", tok)
		}
		req.Header.Set("Accept", "application/json")
		resp, rerr := client.HTTPClient().Do(req) //nolint:gosec
		if rerr != nil {
			return false, rerr
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, fmt.Errorf("list pipeline jobs: http %d", resp.StatusCode)
		}
		var jobs []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if rerr = json.NewDecoder(resp.Body).Decode(&jobs); rerr != nil {
			return false, rerr
		}
		for _, j := range jobs {
			if j.Name == jobName {
				jobID = j.ID
				if terminalJobStatuses[j.Status] {
					status = j.Status
					return true, nil
				}
				return false, nil
			}
		}
		return false, nil
	}
	if err = PollWithTimeout(ctx, interval, timeout, check); err != nil {
		return jobID, status, err
	}
	return jobID, status, nil
}
