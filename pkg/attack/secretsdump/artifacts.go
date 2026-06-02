package secretsdump

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// ArtifactFinding represents a key=value discovered inside a job's artifacts archive.
// It includes basic context: job id/name and the file path within the archive.
//
//nolint:tagliatelle // JSON keys by convention
type ArtifactFinding struct {
	JobID   int64  `json:"job_id"`
	JobName string `json:"job_name"`
	File    string `json:"file"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}

var kvFileRe = regexp.MustCompile(`(?m)^([A-Z0-9_]{3,64})=(.+)$`)

// ScrapeArtifacts scans recent pipelines' job artifacts for potential key=value secrets.
// Limits:
//   - up to maxPipelines pipelines (>=1)
//   - up to maxJobs jobs per pipeline (>=1)
//   - each artifact archive is downloaded only if Content-Length <= maxZipBytes (>0)
//   - within archives, only files with small textual types are scanned (env/txt/log/json/cfg/ini)
//   - each file is scanned up to maxFileBytes bytes
//
// Returns best-effort findings. API/HTTP errors on specific jobs/artifacts are tolerated.
//
//nolint:gocognit // network IO orchestration intentionally inline for performance and clarity
func ScrapeArtifacts(ctx context.Context, client *gitlabx.Client, projectID any, ref string, maxPipelines, maxJobs int, maxZipBytes int64, maxFileBytes int) ([]ArtifactFinding, error) {
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
	if maxZipBytes <= 0 {
		maxZipBytes = 16 << 20
	} // 16 MiB
	if maxFileBytes <= 0 {
		maxFileBytes = 256 << 10
	} // 256 KiB

	pid := fmt.Sprintf("%v", projectID)
	pidEsc := url.PathEscape(pid)
	// List recent pipelines for ref
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
	resp, err := client.HTTPClient().Do(req) //nolint:gosec // G704: URL constructed from client's own baseURL
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

	var findings []ArtifactFinding
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
		respJ, err := client.HTTPClient().Do(reqJ) //nolint:gosec // G704: URL constructed from client's own baseURL
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
				artURL := client.APIURL(fmt.Sprintf("/api/v4/projects/%s/jobs/%d/artifacts", pidEsc, j.ID))
				reqA, err := http.NewRequestWithContext(ctx, http.MethodGet, artURL, nil)
				if err != nil {
					continue
				}
				if tok := client.Token(); tok != "" {
					reqA.Header.Set("PRIVATE-TOKEN", tok)
				}
				reqA.Header.Set("Accept", "application/zip")
				respA, err := client.HTTPClient().Do(reqA) //nolint:gosec
				if err != nil {
					continue
				}
				func() {
					defer respA.Body.Close()
					if respA.StatusCode < 200 || respA.StatusCode >= 300 {
						return
					}
					// Enforce size cap using Content-Length if provided; otherwise, read up to maxZipBytes
					var buf []byte
					if cl := respA.ContentLength; cl > 0 {
						if cl > maxZipBytes {
							return
						}
						buf = make([]byte, 0, cl)
					} else {
						buf = make([]byte, 0, maxZipBytes)
					}
					// Copy with limit
					lim := &io.LimitedReader{R: respA.Body, N: maxZipBytes}
					b, err := io.ReadAll(lim)
					if err != nil {
						return
					}
					buf = append(buf, b...)
					zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
					if err != nil {
						return
					}
					for _, f := range zr.File {
						// Only scan small textual files by extension
						ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(f.Name), "."))
						switch ext {
						case "env", "txt", "log", "json", "cfg", "ini":
							// ok
						default:
							continue
						}
						if f.FileInfo().IsDir() {
							continue
						}
						// Guard against negative values and compare as uint64 to avoid overflow
						if maxFileBytes > 0 && f.UncompressedSize64 > uint64(maxFileBytes) { //nolint:gosec // G115: overflow impossible, maxFileBytes verified positive
							continue
						}
						rc, err := f.Open()
						if err != nil {
							continue
						}
						func() {
							defer rc.Close()
							sc := bufio.NewScanner(rc)
							// Increase scanner buffer for longer lines
							sc.Buffer(make([]byte, 0, 64*1024), maxFileBytes)
							for sc.Scan() {
								line := sc.Text()
								m := kvFileRe.FindStringSubmatch(line)
								if len(m) == 3 {
									k := strings.TrimSpace(m[1])
									v := strings.TrimSpace(m[2])
									if k == RedactionKeyMasked || k == RedactionKeyJobJWT || k == RedactionKeyJobToken {
										continue
									}
									if v == "" || len(v) > 4096 {
										continue
									}
									findings = append(findings, ArtifactFinding{JobID: j.ID, JobName: j.Name, File: f.Name, Key: k, Value: v})
									if len(findings) >= 500 {
										return
									}
								}
							}
						}()
					}
				}()
			}
		}()
	}
	return findings, nil
}
