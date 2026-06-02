package secretsdump

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// Finding represents a key=value discovered in CI job logs.
// NOTE: This is heuristic and may include noisy entries; consumers should treat as leads.
//
//nolint:tagliatelle // JSON keys by convention
type Finding struct {
	JobID   int64  `json:"job_id"`
	JobName string `json:"job_name"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}

var kvLineRe = regexp.MustCompile(`(?m)^([A-Z0-9_]{3,64})=(.+)$`)

// ScrapeJobLogs discovers recent pipelines for a ref and scans their job logs for key=value lines.
// Limits:
// - up to maxPipelines pipelines for the given ref (>=1)
// - up to maxJobs jobs per pipeline (>=1)
// It returns a best-effort slice of findings.
//
//nolint:gocognit // network orchestration + nested best-effort loops; kept together for performance and clarity
func ScrapeJobLogs(ctx context.Context, client *gitlabx.Client, projectID any, ref string, maxPipelines, maxJobs int) ([]Finding, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}
	if strings.TrimSpace(ref) == "" {
		ref = ""
	}
	if maxPipelines <= 0 {
		maxPipelines = 3
	}
	if maxJobs <= 0 {
		maxJobs = 20
	}

	pid := fmt.Sprintf("%v", projectID)
	pidEsc := url.PathEscape(pid)
	// List pipelines for ref (if ref empty, list latest in general)
	qs := "per_page=50"
	if ref != "" {
		qs += "&ref=" + url.QueryEscape(ref)
	}
	pipURL := client.APIURL(fmt.Sprintf("/api/v4/projects/%s/pipelines?%s", pidEsc, qs))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pipURL, nil)
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
	var pipelines []struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pipelines); err != nil {
		return nil, err
	}
	if len(pipelines) == 0 {
		return nil, nil
	}
	if len(pipelines) > maxPipelines {
		pipelines = pipelines[:maxPipelines]
	}

	var findings []Finding
	for _, p := range pipelines {
		jobsURL := client.APIURL(fmt.Sprintf("/api/v4/projects/%s/pipelines/%d/jobs?per_page=100", pidEsc, p.ID))
		reqJ, err := http.NewRequestWithContext(ctx, http.MethodGet, jobsURL, nil)
		if err != nil {
			return nil, err
		}
		if tok := client.Token(); tok != "" {
			reqJ.Header.Set("PRIVATE-TOKEN", tok)
		}
		reqJ.Header.Set("Accept", "application/json")
		respJ, err := client.HTTPClient().Do(reqJ) //nolint:gosec
		if err != nil {
			return nil, err
		}
		func() {
			defer respJ.Body.Close()
			if respJ.StatusCode < 200 || respJ.StatusCode >= 300 {
				return
			}
			var jobs []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			}
			if err := json.NewDecoder(respJ.Body).Decode(&jobs); err != nil {
				return
			}
			if len(jobs) > maxJobs {
				jobs = jobs[:maxJobs]
			}
			for _, j := range jobs {
				traceURL := client.APIURL(fmt.Sprintf("/api/v4/projects/%s/jobs/%d/trace", pidEsc, j.ID))
				reqT, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
				if err != nil {
					continue
				}
				if tok := client.Token(); tok != "" {
					reqT.Header.Set("PRIVATE-TOKEN", tok)
				}
				reqT.Header.Set("Accept", "text/plain")
				respT, err := client.HTTPClient().Do(reqT) //nolint:gosec
				if err != nil {
					continue
				}
				func() {
					defer respT.Body.Close()
					if respT.StatusCode < 200 || respT.StatusCode >= 300 {
						return
					}
					s := bufio.NewScanner(respT.Body)
					s.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
					for s.Scan() {
						line := s.Text()
						m := kvLineRe.FindStringSubmatch(line)
						if len(m) == 3 {
							k := strings.TrimSpace(m[1])
							v := strings.TrimSpace(m[2])
							if k == RedactionKeyMasked || k == RedactionKeyJobJWT || k == RedactionKeyJobToken {
								continue
							}
							if v == "" || len(v) > 4096 {
								continue
							}
							findings = append(findings, Finding{JobID: j.ID, JobName: j.Name, Key: k, Value: v})
							if len(findings) >= 500 {
								return
							} // global safety cap
						}
					}
				}()
			}
		}()
	}
	return findings, nil
}
