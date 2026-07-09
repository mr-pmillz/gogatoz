package bloodhound

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultMaxRetries  = 3
	defaultRetryDelay  = 2 * time.Second
	defaultHTTPTimeout = 60 * time.Second

	extensionsPath    = "/api/v2/extensions"
	uploadStartPath   = "/api/v2/file-upload/start"
	uploadFileFmt     = "/api/v2/file-upload/%s"
	uploadEndFmt      = "/api/v2/file-upload/%s/end"
	cypherPath        = "/api/v2/graphs/cypher"
	savedQueriesPath  = "/api/v2/saved-queries"
	importQueriesPath = "/api/v2/saved-queries/import"
)

// Client communicates with the BloodHound CE API.
type Client struct {
	BaseURL    string
	Auth       Authenticator
	HTTPClient *http.Client
	MaxRetries int
	RetryDelay time.Duration
}

// NewClient creates a Client for the given BloodHound CE instance.
func NewClient(baseURL string, auth Authenticator) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Auth:    auth,
		HTTPClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
		MaxRetries: defaultMaxRetries,
		RetryDelay: defaultRetryDelay,
	}
}

type startUploadResponse struct {
	Data struct {
		ID int64 `json:"id"`
	} `json:"data"`
}

// UploadSchema uploads the CICD extension schema to BloodHound CE.
// Returns nil if the extensions endpoint is not available (e.g., older CE versions).
func (c *Client) UploadSchema(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodPut, extensionsPath, SchemaJSON, "application/json")
	if err != nil {
		return fmt.Errorf("upload schema: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.readError(resp, "upload schema")
	}
	return nil
}

// UploadData uploads a ZIP file to BloodHound CE using the three-step flow:
// start job -> upload file -> end job.
func (c *Client) UploadData(ctx context.Context, zipPath string) error {
	// Start upload job
	startBody := []byte("{}")
	resp, err := c.doRequest(ctx, http.MethodPost, uploadStartPath, startBody, "application/json")
	if err != nil {
		return fmt.Errorf("start upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return c.readError(resp, "start upload")
	}

	var result startUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parse start upload response: %w", err)
	}
	if result.Data.ID == 0 {
		return fmt.Errorf("BloodHound CE returned empty job ID")
	}
	jobID := fmt.Sprintf("%d", result.Data.ID)

	// Upload the ZIP
	data, err := os.ReadFile(zipPath)
	if err != nil {
		return fmt.Errorf("read zip file: %w", err)
	}

	contentType := "application/json"
	if strings.ToLower(filepath.Ext(zipPath)) == ".zip" {
		contentType = "application/zip"
	}

	uploadPath := fmt.Sprintf(uploadFileFmt, jobID)
	resp2, err := c.doRequest(ctx, http.MethodPost, uploadPath, data, contentType)
	if err != nil {
		return fmt.Errorf("upload file: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusAccepted && resp2.StatusCode != http.StatusNoContent {
		return c.readError(resp2, "upload file")
	}

	// End upload job
	endPath := fmt.Sprintf(uploadEndFmt, jobID)
	resp3, err := c.doRequest(ctx, http.MethodPost, endPath, []byte("{}"), "application/json")
	if err != nil {
		return fmt.Errorf("end upload: %w", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK && resp3.StatusCode != http.StatusNoContent {
		return c.readError(resp3, "end upload")
	}
	return nil
}

// RunCypher executes a Cypher query against BloodHound CE.
func (c *Client) RunCypher(ctx context.Context, query string) (map[string]any, error) {
	body, err := json.Marshal(map[string]any{
		"query":              query,
		"include_properties": true,
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(ctx, http.MethodPost, cypherPath, body, "application/json")
	if err != nil {
		return nil, fmt.Errorf("run cypher: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp, "run cypher")
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode cypher response: %w", err)
	}
	return result, nil
}

// CreateSavedQuery creates or replaces a saved Cypher query.
func (c *Client) CreateSavedQuery(ctx context.Context, sq SavedQuery) error {
	body, err := json.Marshal(sq)
	if err != nil {
		return err
	}

	resp, err := c.doRequest(ctx, http.MethodPost, savedQueriesPath, body, "application/json")
	if err != nil {
		return fmt.Errorf("create saved query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return c.readError(resp, "create saved query")
	}
	return nil
}

// ImportQueries bulk-imports saved queries as a JSON array.
func (c *Client) ImportQueries(ctx context.Context, queries []SavedQuery) error {
	for _, q := range queries {
		body, err := json.Marshal(q)
		if err != nil {
			return err
		}
		resp, err := c.doRequest(ctx, http.MethodPost, importQueriesPath, body, "application/json")
		if err != nil {
			return fmt.Errorf("import query %q: %w", q.Name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return c.readError(resp, fmt.Sprintf("import query %q", q.Name))
		}
	}
	return nil
}

type savedQueryListResponse struct {
	Data []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"data"`
}

// ListSavedQueries lists all saved Cypher queries.
func (c *Client) ListSavedQueries(ctx context.Context) ([]SavedQuery, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, savedQueriesPath, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp, "list saved queries")
	}

	var result savedQueryListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	queries := make([]SavedQuery, len(result.Data))
	for i, d := range result.Data {
		queries[i] = SavedQuery{Name: d.Name}
	}
	return queries, nil
}

// doRequest performs an HTTP request with authentication and retry logic.
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte, contentType string) (*http.Response, error) {
	url := c.BaseURL + path
	maxRetries := c.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	delay := c.RetryDelay
	if delay <= 0 {
		delay = defaultRetryDelay
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				delay *= 2
			}
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		if err := c.Auth.Authenticate(req, body); err != nil {
			return nil, fmt.Errorf("authenticate: %w", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries+1, lastErr)
}

func (c *Client) readError(resp *http.Response, operation string) error {
	body, _ := io.ReadAll(resp.Body)
	msg := truncateStr(string(body), 300)
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("%s failed (HTTP %d): %s", operation, resp.StatusCode, msg)
}

func truncateStr(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
