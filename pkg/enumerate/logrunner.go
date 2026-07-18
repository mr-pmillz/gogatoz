package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// RunnerLogInfo holds runner metadata extracted from a GitLab CI job trace.
type RunnerLogInfo struct {
	RunnerName string `json:"runner_name"`
	Executor   string `json:"executor"`
	Version    string `json:"version,omitempty"`
}

var (
	runnerLineRe    = regexp.MustCompile(`Running on (\S+) using (\S+) executor`)
	runnerVersionRe = regexp.MustCompile(`Running with gitlab-runner (\d+\.\d+\.\d+)`)
)

// ExtractRunnerFromLog parses a GitLab CI job trace and extracts runner
// metadata from the standard log header lines. Returns nil if no runner
// information is found.
func ExtractRunnerFromLog(trace string) *RunnerLogInfo {
	if strings.TrimSpace(trace) == "" {
		return nil
	}
	m := runnerLineRe.FindStringSubmatch(trace)
	if m == nil {
		return nil
	}
	info := &RunnerLogInfo{
		RunnerName: m[1],
		Executor:   m[2],
	}
	if vm := runnerVersionRe.FindStringSubmatch(trace); vm != nil {
		info.Version = vm[1]
	}
	return info
}

// fetchFirstJobTrace fetches the trace of the most recent job for a project
// ref. Used as fallback when --runners is not set.
func fetchFirstJobTrace(ctx context.Context, cl *gitlabx.Client, projectID any, ref string) string {
	if cl == nil {
		return ""
	}
	url := cl.APIURL(fmt.Sprintf("/api/v4/projects/%v/pipelines?per_page=1&ref=%s", projectID, ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("PRIVATE-TOKEN", cl.Token())
	resp, err := cl.HTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	var pips []struct {
		ID int64 `json:"id"`
	}
	if json.NewDecoder(resp.Body).Decode(&pips) != nil || len(pips) == 0 {
		return ""
	}

	jobsURL := cl.APIURL(fmt.Sprintf("/api/v4/projects/%v/pipelines/%d/jobs?per_page=1", projectID, pips[0].ID))
	jreq, err := http.NewRequestWithContext(ctx, http.MethodGet, jobsURL, nil)
	if err != nil {
		return ""
	}
	jreq.Header.Set("PRIVATE-TOKEN", cl.Token())
	jresp, jerr := cl.HTTPClient().Do(jreq)
	if jerr != nil || jresp.StatusCode != http.StatusOK {
		if jresp != nil {
			jresp.Body.Close()
		}
		return ""
	}
	defer jresp.Body.Close()
	var jobs []struct {
		ID int64 `json:"id"`
	}
	if json.NewDecoder(jresp.Body).Decode(&jobs) != nil || len(jobs) == 0 {
		return ""
	}

	traceURL := cl.APIURL(fmt.Sprintf("/api/v4/projects/%v/jobs/%d/trace", projectID, jobs[0].ID))
	treq, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return ""
	}
	treq.Header.Set("PRIVATE-TOKEN", cl.Token())
	tresp, terr := cl.HTTPClient().Do(treq)
	if terr != nil || tresp.StatusCode != http.StatusOK {
		if tresp != nil {
			tresp.Body.Close()
		}
		return ""
	}
	defer tresp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(tresp.Body, 1<<20))
	return string(body)
}
