package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

const (
	defaultRunnerLogPipelines = 3
	defaultRunnerLogJobs      = 10
	defaultRunnerTraceBytes   = 1 << 20
	maxRunnerLogPipelines     = 10
	maxRunnerLogJobs          = 100
	maxRunnerTraceBytes       = 4 << 20
)

// RunnerLogInfo holds runner metadata extracted from a GitLab CI job trace.
type RunnerLogInfo struct {
	RunnerID     int64    `json:"runner_id,omitempty"`
	RunnerName   string   `json:"runner_name,omitempty"`
	Description  string   `json:"description,omitempty"`
	RunnerType   string   `json:"runner_type,omitempty"`
	Executor     string   `json:"executor,omitempty"`
	SystemID     string   `json:"system_id,omitempty"`
	Version      string   `json:"version,omitempty"`
	Revision     string   `json:"revision,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	Tags         []string `json:"observed_job_tags,omitempty"`
	JobIDs       []int64  `json:"sampled_job_ids,omitempty"`
	PipelineIDs  []int64  `json:"sampled_pipeline_ids,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
}

// RunnerLogLimits bounds the amount of historical CI data inspected during
// runner discovery. Jobs is a per-pipeline limit and TraceBytes is a per-job
// response limit.
type RunnerLogLimits struct {
	Pipelines  int
	Jobs       int
	TraceBytes int64
}

var (
	// "Running on 7ff7eebb265c using shell executor..." (older format)
	runnerUsingRe = regexp.MustCompile(`Running on (\S+) using (\S+) executor`)
	// "Running on 7ff7eebb265c..." (modern format — executor on separate line)
	runnerOnRe = regexp.MustCompile(`Running on (\S+?)\.{3}`)
	// 'Preparing the "shell" executor' (modern format — executor type)
	executorRe              = regexp.MustCompile(`Preparing the "([^"]+)" executor`)
	runnerVersionRe         = regexp.MustCompile(`Running with gitlab-runner ([^\s]+)`)
	runnerVersionRevisionRe = regexp.MustCompile(`Running with gitlab-runner ([^\s]+) \(([^)]+)\)`)
	runnerSystemIDRe        = regexp.MustCompile(`system ID:\s*(\S+)`)
	runtimePlatformRe       = regexp.MustCompile(`Runtime platform\s+arch=(\S+)\s+os=(\S+)`)
)

// ExtractRunnerFromLog parses a GitLab CI job trace and extracts runner
// metadata from the standard log header lines. Returns nil if no runner
// information is found. Handles both the older "Running on X using Y
// executor" format and the modern split-line format.
func ExtractRunnerFromLog(trace string) *RunnerLogInfo {
	if strings.TrimSpace(trace) == "" {
		return nil
	}

	// Try the older combined format first
	if m := runnerUsingRe.FindStringSubmatch(trace); m != nil {
		info := &RunnerLogInfo{RunnerName: m[1], Executor: m[2]}
		enrichRunnerFromTrace(info, trace)
		return info
	}

	// Modern format: "Running on <name>..." + 'Preparing the "<executor>" executor'
	m := runnerOnRe.FindStringSubmatch(trace)
	if m == nil {
		return nil
	}
	info := &RunnerLogInfo{RunnerName: m[1]}
	if em := executorRe.FindStringSubmatch(trace); em != nil {
		info.Executor = em[1]
	}
	enrichRunnerFromTrace(info, trace)
	return info
}

func enrichRunnerFromTrace(info *RunnerLogInfo, trace string) {
	info.Sources = appendUniqueString(info.Sources, "job_trace")
	info.Confidence = "medium"
	if vm := runnerVersionRevisionRe.FindStringSubmatch(trace); vm != nil {
		info.Version = vm[1]
		info.Revision = vm[2]
	} else if vm := runnerVersionRe.FindStringSubmatch(trace); vm != nil {
		info.Version = vm[1]
	}
	if sm := runnerSystemIDRe.FindStringSubmatch(trace); sm != nil {
		info.SystemID = sm[1]
	}
	if pm := runtimePlatformRe.FindStringSubmatch(trace); pm != nil {
		info.Architecture = pm[1]
		info.Platform = pm[2]
	}
}

func normalizeRunnerLogLimits(limits RunnerLogLimits) RunnerLogLimits {
	if limits.Pipelines <= 0 {
		limits.Pipelines = defaultRunnerLogPipelines
	}
	if limits.Pipelines > maxRunnerLogPipelines {
		limits.Pipelines = maxRunnerLogPipelines
	}
	if limits.Jobs <= 0 {
		limits.Jobs = defaultRunnerLogJobs
	}
	if limits.Jobs > maxRunnerLogJobs {
		limits.Jobs = maxRunnerLogJobs
	}
	if limits.TraceBytes <= 0 {
		limits.TraceBytes = defaultRunnerTraceBytes
	}
	if limits.TraceBytes > maxRunnerTraceBytes {
		limits.TraceBytes = maxRunnerTraceBytes
	}
	return limits
}

type runnerLogPipeline struct {
	ID int64 `json:"id"`
}

type runnerLogJob struct {
	ID      int64    `json:"id"`
	TagList []string `json:"tag_list"`
	Runner  *struct {
		ID          int64  `json:"id"`
		Description string `json:"description"`
		RunnerType  string `json:"runner_type"`
	} `json:"runner"`
	RunnerManager *struct {
		SystemID     string `json:"system_id"`
		Version      string `json:"version"`
		Revision     string `json:"revision"`
		Platform     string `json:"platform"`
		Architecture string `json:"architecture"`
	} `json:"runner_manager"`
}

// DiscoverRunnersFromLogs inspects bounded recent pipeline jobs and their
// traces. It is read-only and is intended as a fallback when runner inventory
// endpoints are unavailable to the current token.
func DiscoverRunnersFromLogs(
	ctx context.Context,
	cl *gitlabx.Client,
	projectID any,
	ref string,
	limits RunnerLogLimits,
) ([]RunnerLogInfo, error) {
	if cl == nil {
		return nil, fmt.Errorf("nil client")
	}
	limits = normalizeRunnerLogLimits(limits)
	pid := url.PathEscape(fmt.Sprintf("%v", projectID))
	query := url.Values{"per_page": {fmt.Sprintf("%d", limits.Pipelines)}}
	if trimmedRef := strings.TrimSpace(ref); trimmedRef != "" {
		query.Set("ref", trimmedRef)
	}
	path := fmt.Sprintf("/api/v4/projects/%s/pipelines?%s", pid, query.Encode())
	slog.Debug("runner log discovery starting", "project_id", projectID,
		"pipelines", limits.Pipelines, "jobs_per_pipeline", limits.Jobs)
	body, status, err := runnerLogGet(ctx, cl, path, defaultRunnerTraceBytes)
	if err != nil {
		return nil, fmt.Errorf("list recent pipelines: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list recent pipelines: http %d", status)
	}
	var pipelines []runnerLogPipeline
	if err := json.Unmarshal(body, &pipelines); err != nil {
		return nil, fmt.Errorf("decode recent pipelines: %w", err)
	}
	if len(pipelines) > limits.Pipelines {
		pipelines = pipelines[:limits.Pipelines]
	}

	var discovered []RunnerLogInfo
	for _, pipeline := range pipelines {
		if err := ctx.Err(); err != nil {
			return discovered, err
		}
		jobs, jobsErr := fetchRunnerLogJobs(ctx, cl, pid, pipeline.ID, limits.Jobs)
		if jobsErr != nil {
			slog.Debug("runner log jobs unavailable", "pipeline_id", pipeline.ID, "error", jobsErr)
			continue
		}
		for _, job := range jobs {
			if err := ctx.Err(); err != nil {
				return discovered, err
			}
			info, hasAPIEvidence := runnerInfoFromJob(job, pipeline.ID)
			tracePath := fmt.Sprintf("/api/v4/projects/%s/jobs/%d/trace", pid, job.ID)
			traceBody, traceStatus, traceErr := runnerLogGet(ctx, cl, tracePath, limits.TraceBytes)
			if traceErr == nil && traceStatus == http.StatusOK {
				if traceInfo := ExtractRunnerFromLog(string(traceBody)); traceInfo != nil {
					mergeRunnerLogInfo(&info, *traceInfo)
				}
			}
			if !hasAPIEvidence && len(info.Sources) == 0 {
				continue
			}
			info.Tags = appendUniqueStrings(info.Tags, job.TagList...)
			info.JobIDs = appendUniqueInt64(info.JobIDs, job.ID)
			info.PipelineIDs = appendUniqueInt64(info.PipelineIDs, pipeline.ID)
			mergeDiscoveredRunner(&discovered, info)
		}
	}
	slog.Debug("runner log discovery completed", "project_id", projectID, "runners", len(discovered))
	return discovered, nil
}

func fetchRunnerLogJobs(
	ctx context.Context,
	cl *gitlabx.Client,
	projectID string,
	pipelineID int64,
	limit int,
) ([]runnerLogJob, error) {
	path := fmt.Sprintf("/api/v4/projects/%s/pipelines/%d/jobs?per_page=%d", projectID, pipelineID, limit)
	body, status, err := runnerLogGet(ctx, cl, path, defaultRunnerTraceBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("http %d", status)
	}
	var jobs []runnerLogJob
	if err := json.Unmarshal(body, &jobs); err != nil {
		return nil, fmt.Errorf("decode pipeline jobs: %w", err)
	}
	if len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs, nil
}

func runnerLogGet(
	ctx context.Context,
	cl *gitlabx.Client,
	relPath string,
	maxBytes int64,
) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cl.APIURL(relPath), nil)
	if err != nil {
		return nil, 0, err
	}
	if token := cl.Token(); token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := cl.HTTPClient().Do(req) //nolint:gosec // client base URL is validated by gitlabx.New
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func runnerInfoFromJob(job runnerLogJob, pipelineID int64) (RunnerLogInfo, bool) {
	info := RunnerLogInfo{JobIDs: []int64{job.ID}, PipelineIDs: []int64{pipelineID}}
	hasEvidence := job.Runner != nil || job.RunnerManager != nil
	if !hasEvidence {
		return info, false
	}
	info.Sources = []string{"job_api"}
	info.Confidence = "high"
	if job.Runner != nil {
		info.RunnerID = job.Runner.ID
		info.Description = strings.TrimSpace(job.Runner.Description)
		info.RunnerType = strings.TrimSpace(job.Runner.RunnerType)
	}
	if job.RunnerManager != nil {
		info.SystemID = strings.TrimSpace(job.RunnerManager.SystemID)
		info.Version = strings.TrimSpace(job.RunnerManager.Version)
		info.Revision = strings.TrimSpace(job.RunnerManager.Revision)
		info.Platform = strings.TrimSpace(job.RunnerManager.Platform)
		info.Architecture = strings.TrimSpace(job.RunnerManager.Architecture)
	}
	return info, true
}

func mergeDiscoveredRunner(discovered *[]RunnerLogInfo, candidate RunnerLogInfo) {
	key := runnerLogKey(candidate)
	for i := range *discovered {
		if runnerLogKey((*discovered)[i]) == key {
			mergeRunnerLogInfo(&(*discovered)[i], candidate)
			return
		}
	}
	*discovered = append(*discovered, candidate)
}

func runnerLogKey(info RunnerLogInfo) string {
	if info.RunnerID != 0 {
		return fmt.Sprintf("runner:%d", info.RunnerID)
	}
	if info.SystemID != "" {
		return "system:" + info.SystemID
	}
	if info.Description != "" {
		return "description:" + info.Description
	}
	return "trace:" + info.RunnerName + ":" + info.Executor
}

func mergeRunnerLogInfo(dst *RunnerLogInfo, src RunnerLogInfo) {
	if dst.RunnerID == 0 {
		dst.RunnerID = src.RunnerID
	}
	fillString := func(target *string, value string) {
		if *target == "" {
			*target = value
		}
	}
	fillString(&dst.RunnerName, src.RunnerName)
	fillString(&dst.Description, src.Description)
	fillString(&dst.RunnerType, src.RunnerType)
	fillString(&dst.Executor, src.Executor)
	fillString(&dst.SystemID, src.SystemID)
	fillString(&dst.Version, src.Version)
	fillString(&dst.Revision, src.Revision)
	fillString(&dst.Platform, src.Platform)
	fillString(&dst.Architecture, src.Architecture)
	dst.Tags = appendUniqueStrings(dst.Tags, src.Tags...)
	for _, id := range src.JobIDs {
		dst.JobIDs = appendUniqueInt64(dst.JobIDs, id)
	}
	for _, id := range src.PipelineIDs {
		dst.PipelineIDs = appendUniqueInt64(dst.PipelineIDs, id)
	}
	dst.Sources = appendUniqueStrings(dst.Sources, src.Sources...)
	if slices.Contains(dst.Sources, "job_api") {
		dst.Confidence = "high"
	} else if dst.Confidence == "" {
		dst.Confidence = src.Confidence
	}
}

func appendUniqueString(values []string, value string) []string {
	if value == "" || slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func appendUniqueStrings(values []string, additions ...string) []string {
	for _, value := range additions {
		values = appendUniqueString(values, strings.TrimSpace(value))
	}
	return values
}

func appendUniqueInt64(values []int64, value int64) []int64 {
	if value == 0 || slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}
