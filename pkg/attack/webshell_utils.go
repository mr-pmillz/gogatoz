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
// and returns its ID when at least one is found, or an error on timeout.
func WaitForPipelineForRef(ctx context.Context, client *gitlabx.Client, projectID any, ref string, interval, timeout time.Duration) (int64, error) {
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
		return foundID > 0, nil
	}
	if err := PollWithTimeout(ctx, interval, timeout, check); err != nil {
		return 0, err
	}
	return foundID, nil
}
