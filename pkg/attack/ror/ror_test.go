package ror

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestDiscoverProjectRunnerTags_NilClient(t *testing.T) {
	_, _, err := DiscoverProjectRunnerTags(context.Background(), nil, 1)
	if err == nil {
		t.Fatalf("expected error for nil client, got nil")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected error containing 'nil client', got %q", err.Error())
	}
}

func TestDiscoverProjectRunnerTags_Success(t *testing.T) {
	tests := []struct {
		name        string
		response    []RunnerSummary
		wantTags    []string
		wantRunners int
	}{
		{
			name: "single_runner_two_tags",
			response: []RunnerSummary{
				{ID: 1, Description: "r1", IsShared: false, RunnerType: "project_type", Tags: []string{"docker", "ci"}},
			},
			wantTags:    []string{"ci", "docker"},
			wantRunners: 1,
		},
		{
			name: "multiple_runners_overlapping_tags",
			response: []RunnerSummary{
				{ID: 1, Description: "r1", Tags: []string{"docker", "ci"}},
				{ID: 2, Description: "r2", Tags: []string{"ci", "build"}},
			},
			wantTags:    []string{"build", "ci", "docker"},
			wantRunners: 2,
		},
		{
			name:        "no_runners",
			response:    []RunnerSummary{},
			wantTags:    []string{},
			wantRunners: 0,
		},
		{
			name: "empty_tags_trimmed",
			response: []RunnerSummary{
				{ID: 1, Description: "r1", Tags: []string{"", " "}},
			},
			wantTags:    []string{},
			wantRunners: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/runners") {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tc.response); err != nil {
					t.Fatalf("failed to encode response: %v", err)
				}
			}))
			defer srv.Close()

			client, err := gitlabx.New(srv.URL, "test-token")
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			tags, runners, err := DiscoverProjectRunnerTags(context.Background(), client, 42)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(runners) != tc.wantRunners {
				t.Fatalf("expected %d runners, got %d", tc.wantRunners, len(runners))
			}

			sort.Strings(tags)
			if len(tags) != len(tc.wantTags) {
				t.Fatalf("expected %d tags %v, got %d tags %v", len(tc.wantTags), tc.wantTags, len(tags), tags)
			}
			for i, want := range tc.wantTags {
				if tags[i] != want {
					t.Errorf("tag[%d]: expected %q, got %q", i, want, tags[i])
				}
			}
		})
	}
}

func TestDiscoverProjectRunnerTags_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, _, err = DiscoverProjectRunnerTags(context.Background(), client, 42)
	if err == nil {
		t.Fatalf("expected error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "http 403") {
		t.Fatalf("expected error containing 'http 403', got %q", err.Error())
	}
}

func TestDiscoverProjectRunnerTags_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, _, err = DiscoverProjectRunnerTags(context.Background(), client, 42)
	if err == nil {
		t.Fatalf("expected error for invalid JSON, got nil")
	}
}

func TestFilterTagsByExecutor(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		executor string
		want     []string
	}{
		{
			name:     "empty_executor_returns_all",
			tags:     []string{"ci", "build"},
			executor: "",
			want:     []string{"ci", "build"},
		},
		{
			name:     "docker_matches",
			tags:     []string{"docker-runner", "shell-runner"},
			executor: "docker",
			want:     []string{"docker-runner"},
		},
		{
			name:     "docker_matches_dind",
			tags:     []string{"dind-runner", "shell"},
			executor: "docker",
			want:     []string{"dind-runner"},
		},
		{
			name:     "docker_matches_container",
			tags:     []string{"container-build", "k8s"},
			executor: "docker",
			want:     []string{"container-build"},
		},
		{
			name:     "shell_matches",
			tags:     []string{"shell-linux", "docker"},
			executor: "shell",
			want:     []string{"shell-linux"},
		},
		{
			name:     "kubernetes_matches",
			tags:     []string{"kubernetes", "k8s-runner"},
			executor: "kubernetes",
			want:     []string{"kubernetes"},
		},
		{
			name:     "case_insensitive",
			tags:     []string{"Docker-Runner"},
			executor: "docker",
			want:     []string{"Docker-Runner"},
		},
		{
			name:     "no_matches",
			tags:     []string{"ci", "build"},
			executor: "shell",
			want:     nil,
		},
		{
			name:     "nil_tags",
			tags:     nil,
			executor: "docker",
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterTagsByExecutor(tc.tags, tc.executor)

			// Both nil or both empty are treated as equal
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
			for i, w := range tc.want {
				if got[i] != w {
					t.Errorf("result[%d]: expected %q, got %q", i, w, got[i])
				}
			}
		})
	}
}

func TestDiscoverGroupRunnerSharing_NilClient(t *testing.T) {
	_, err := DiscoverGroupRunnerSharing(context.Background(), nil, 1)
	if err == nil {
		t.Fatalf("expected error for nil client, got nil")
	}
	if !strings.Contains(err.Error(), "nil client") {
		t.Fatalf("expected error containing 'nil client', got %q", err.Error())
	}
}

// groupRunnerMockServer creates an httptest server that mocks group runner APIs.
func groupRunnerMockServer(t *testing.T) *httptest.Server { //nolint:gocognit
	t.Helper()
	type mockRunner struct {
		ID          int64  `json:"id"`
		Description string `json:"description"`
		Paused      bool   `json:"paused"`
		IsShared    bool   `json:"is_shared"`
	}
	type mockRunnerDetails struct {
		ID          int64    `json:"id"`
		Description string   `json:"description"`
		Paused      bool     `json:"paused"`
		IsShared    bool     `json:"is_shared"`
		TagList     []string `json:"tag_list"`
	}
	type mockProject struct {
		ID int64 `json:"id"`
	}
	type mockJob struct {
		ID      int64       `json:"id"`
		Project mockProject `json:"project"`
	}
	runners := []mockRunner{
		{ID: 10, Description: "shared-runner", Paused: false, IsShared: true},
		{ID: 20, Description: "single-runner", Paused: true, IsShared: false},
	}
	runnerDetails := map[int64]mockRunnerDetails{
		10: {ID: 10, Description: "shared-runner", Paused: false, IsShared: true, TagList: []string{"docker", "ci"}},
		20: {ID: 20, Description: "single-runner", Paused: true, IsShared: false, TagList: []string{"shell"}},
	}
	runnerJobs := map[int64][]mockJob{
		10: {
			{ID: 1, Project: mockProject{ID: 100}},
			{ID: 2, Project: mockProject{ID: 200}},
			{ID: 3, Project: mockProject{ID: 100}},
		},
		20: {{ID: 4, Project: mockProject{ID: 300}}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "100")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "0")
		path := r.URL.Path
		if strings.Contains(path, "/groups/") && strings.HasSuffix(path, "/runners") {
			w.Header().Set("X-Total", fmt.Sprintf("%d", len(runners)))
			json.NewEncoder(w).Encode(runners) //nolint:errcheck
			return
		}
		if strings.Contains(path, "/runners/") && strings.HasSuffix(path, "/jobs") {
			for rid, jobs := range runnerJobs {
				if strings.Contains(path, fmt.Sprintf("/runners/%d/", rid)) {
					w.Header().Set("X-Total", fmt.Sprintf("%d", len(jobs)))
					json.NewEncoder(w).Encode(jobs) //nolint:errcheck
					return
				}
			}
			json.NewEncoder(w).Encode([]mockJob{}) //nolint:errcheck
			return
		}
		if strings.Contains(path, "/runners/") {
			for rid, details := range runnerDetails {
				if strings.HasSuffix(path, fmt.Sprintf("/runners/%d", rid)) {
					json.NewEncoder(w).Encode(details) //nolint:errcheck
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestDiscoverGroupRunnerSharing_Success(t *testing.T) {
	srv := groupRunnerMockServer(t)
	defer srv.Close()

	client, err := gitlabx.New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	results, err := DiscoverGroupRunnerSharing(context.Background(), client, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only runner 10 should be returned (serves 2 projects).
	if len(results) != 1 {
		t.Fatalf("expected 1 shared runner, got %d", len(results))
	}

	r := results[0]
	if r.RunnerID != 10 {
		t.Errorf("expected runner ID 10, got %d", r.RunnerID)
	}
	if r.Description != "shared-runner" {
		t.Errorf("expected description 'shared-runner', got %q", r.Description)
	}
	if r.Paused {
		t.Errorf("expected Paused=false for runner 10")
	}

	// Tags from RunnerDetails.
	sort.Strings(r.Tags)
	expectedTags := []string{"ci", "docker"}
	if len(r.Tags) != len(expectedTags) {
		t.Fatalf("expected tags %v, got %v", expectedTags, r.Tags)
	}
	for i, want := range expectedTags {
		if r.Tags[i] != want {
			t.Errorf("tag[%d]: expected %q, got %q", i, want, r.Tags[i])
		}
	}

	// Project IDs should be sorted and deduplicated.
	expectedProjects := []int64{100, 200}
	if len(r.ProjectIDs) != len(expectedProjects) {
		t.Fatalf("expected project IDs %v, got %v", expectedProjects, r.ProjectIDs)
	}
	for i, want := range expectedProjects {
		if r.ProjectIDs[i] != want {
			t.Errorf("project_id[%d]: expected %d, got %d", i, want, r.ProjectIDs[i])
		}
	}
}
