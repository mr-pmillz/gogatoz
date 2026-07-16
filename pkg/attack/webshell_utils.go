package attack

import (
	"context"
	"fmt"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
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
func PollWithTimeout(ctx context.Context, interval, timeout time.Duration, fn func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
func WaitForPipelineForRef(ctx context.Context, client *gitlabx.Client, projectID any, ref string, minID int64, interval, timeout time.Duration) (int64, error) {
	if client == nil {
		return 0, fmt.Errorf("nil client")
	}
	var foundID int64
	check := func(ctx context.Context) (bool, error) {
		opts := &gitlab.ListProjectPipelinesOptions{
			ListOptions: gitlab.ListOptions{PerPage: 1, Page: 1},
			OrderBy:     gitlab.Ptr("id"),
			Sort:        gitlab.Ptr("desc"),
		}
		if ref != "" {
			opts.Ref = gitlab.Ptr(ref)
		}
		pipes, _, err := client.GL.Pipelines.ListProjectPipelines(projectID, opts, gitlab.WithContext(ctx))
		if err != nil {
			return false, err
		}
		if len(pipes) == 0 {
			return false, nil
		}
		foundID = pipes[0].ID
		return foundID > minID, nil
	}
	if err := PollWithTimeout(ctx, interval, timeout, check); err != nil {
		return 0, err
	}
	return foundID, nil
}

// WaitForExfilPipeline polls recent pipelines on a branch for a job with the given name
// and waits until that job reaches a terminal state.
//
//nolint:gocognit // network IO orchestration; intentional complexity
func WaitForExfilPipeline(ctx context.Context, client *gitlabx.Client, projectID any, ref, jobName string, interval, timeout time.Duration) (pipelineID, jobID int64, status string, err error) {
	if client == nil {
		return 0, 0, "", fmt.Errorf("nil client")
	}
	check := func(ctx context.Context) (bool, error) {
		pipes, perr := listRecentPipelines(ctx, client, projectID, ref, 5)
		if perr != nil {
			return false, perr
		}
		for _, pipe := range pipes {
			found, jID, jStatus, ferr := findJobInPipeline(ctx, client, projectID, pipe, jobName)
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

func listRecentPipelines(ctx context.Context, client *gitlabx.Client, projectID any, ref string, n int) ([]int64, error) {
	opts := &gitlab.ListProjectPipelinesOptions{
		ListOptions: gitlab.ListOptions{PerPage: int64(n), Page: 1},
		OrderBy:     gitlab.Ptr("id"),
		Sort:        gitlab.Ptr("desc"),
	}
	if ref != "" {
		opts.Ref = gitlab.Ptr(ref)
	}
	pipes, _, err := client.GL.Pipelines.ListProjectPipelines(projectID, opts, gitlab.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(pipes))
	for i, p := range pipes {
		ids[i] = p.ID
	}
	return ids, nil
}

func findJobInPipeline(ctx context.Context, client *gitlabx.Client, projectID any, pipelineID int64, jobName string) (found bool, jobID int64, status string, err error) {
	opts := &gitlab.ListJobsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
	}
	jobs, _, err := client.GL.Jobs.ListPipelineJobs(projectID, pipelineID, opts, gitlab.WithContext(ctx))
	if err != nil {
		return false, 0, "", err
	}
	for _, j := range jobs {
		if j.Name == jobName {
			return true, j.ID, j.Status, nil
		}
	}
	return false, 0, "", nil
}

// WaitForJobCompletion polls until the named job in a pipeline reaches a terminal state.
func WaitForJobCompletion(ctx context.Context, client *gitlabx.Client, projectID any, pipelineID int64, jobName string, interval, timeout time.Duration) (jobID int64, status string, err error) {
	if client == nil {
		return 0, "", fmt.Errorf("nil client")
	}
	check := func(ctx context.Context) (bool, error) {
		opts := &gitlab.ListJobsOptions{
			ListOptions: gitlab.ListOptions{PerPage: 100, Page: 1},
		}
		jobs, _, jerr := client.GL.Jobs.ListPipelineJobs(projectID, pipelineID, opts, gitlab.WithContext(ctx))
		if jerr != nil {
			return false, jerr
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
