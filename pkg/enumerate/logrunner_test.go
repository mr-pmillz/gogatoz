package enumerate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestExtractRunnerFromLog(t *testing.T) {
	tests := []struct {
		name     string
		trace    string
		wantNil  bool
		wantName string
		wantExec string
	}{
		{
			name:     "older combined format",
			trace:    "Running on 7ff7eebb265c using shell executor...\nBuilding...",
			wantName: "7ff7eebb265c",
			wantExec: "shell",
		},
		{
			name:     "older docker format",
			trace:    "Running on runner-abc123 using docker executor with image alpine:latest...",
			wantName: "runner-abc123",
			wantExec: "docker",
		},
		{
			name:     "older kubernetes format",
			trace:    "Running on runner-k8s-pod using kubernetes executor...\n$ echo hello",
			wantName: "runner-k8s-pod",
			wantExec: "kubernetes",
		},
		{
			name:     "modern split format (real GitLab 19.x trace)",
			trace:    "Running with gitlab-runner 19.1.1 (24b9b726)\n  on Lab shell runner P_ZhTrTBE\nPreparing the \"shell\" executor\nUsing Shell (bash) executor...\nRunning on 7ff7eebb265c...",
			wantName: "7ff7eebb265c",
			wantExec: "shell",
		},
		{
			name:     "modern docker split format",
			trace:    "Running with gitlab-runner 17.0.0 (abc)\n  on runner-dock XYZ\nPreparing the \"docker\" executor\nRunning on abcdef123456...",
			wantName: "abcdef123456",
			wantExec: "docker",
		},
		{
			name:     "modern format without version line",
			trace:    "Preparing the \"kubernetes\" executor\nRunning on k8s-pod-abc...",
			wantName: "k8s-pod-abc",
			wantExec: "kubernetes",
		},
		{
			name:    "no runner info",
			trace:   "Building project...\n$ echo hello\nhello",
			wantNil: true,
		},
		{
			name:    "empty trace",
			trace:   "",
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ExtractRunnerFromLog(tt.trace)
			if tt.wantNil {
				if info != nil {
					t.Fatalf("expected nil, got %+v", info)
				}
				return
			}
			if info == nil {
				t.Fatal("expected non-nil RunnerLogInfo")
			}
			if info.RunnerName != tt.wantName {
				t.Errorf("runner name: got %q, want %q", info.RunnerName, tt.wantName)
			}
			if info.Executor != tt.wantExec {
				t.Errorf("executor: got %q, want %q", info.Executor, tt.wantExec)
			}
		})
	}
}

func TestExtractRunnerVersion(t *testing.T) {
	trace := "Running with gitlab-runner 17.5.0 (deadbeef)\n  on my-runner 1234\nPreparing the \"docker\" executor\nRunning on 1234..."
	info := ExtractRunnerFromLog(trace)
	if info == nil {
		t.Fatal("expected non-nil")
	}
	if info.Version != "17.5.0" {
		t.Errorf("version: got %q, want 17.5.0", info.Version)
	}
}

func TestDiscoverRunnersFromLogs_BoundedAndMergesMetadata(t *testing.T) {
	t.Parallel()

	var pipelineJobRequests atomic.Int32
	var traceRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects/42/pipelines":
			if got := r.URL.Query().Get("per_page"); got != "2" {
				t.Errorf("pipeline per_page = %q, want 2", got)
			}
			if got := r.URL.Query().Get("ref"); got != "main" {
				t.Errorf("pipeline ref = %q, want main", got)
			}
			// Return an extra item deliberately; the client must still honor its bound.
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 101}, {"id": 102}, {"id": 103}})
		case "/api/v4/projects/42/pipelines/101/jobs":
			pipelineJobRequests.Add(1)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"id": 1001, "tag_list": []string{"shell", "linux"},
					"runner": map[string]any{"id": 7, "description": "build-shell", "runner_type": "project_type"},
					"runner_manager": map[string]any{
						"system_id": "s_shell", "version": "18.2.1", "revision": "abc123",
						"platform": "linux", "architecture": "amd64",
					},
				},
				{
					"id": 1002, "tag_list": []string{"trusted", "shell"},
					"runner":         map[string]any{"id": 7, "description": "build-shell", "runner_type": "project_type"},
					"runner_manager": map[string]any{"system_id": "s_shell", "version": "18.2.1"},
				},
			})
		case "/api/v4/projects/42/pipelines/102/jobs":
			pipelineJobRequests.Add(1)
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": 2001, "tag_list": []string{"docker"},
				"runner":         map[string]any{"id": 8, "description": "build-docker", "runner_type": "group_type"},
				"runner_manager": map[string]any{"system_id": "s_docker", "version": "17.11.0", "platform": "linux", "architecture": "arm64"},
			}})
		case "/api/v4/projects/42/pipelines/103/jobs":
			t.Error("third pipeline exceeded configured sample bound")
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/v4/projects/42/jobs/1001/trace":
			traceRequests.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Running with gitlab-runner 18.2.1 (abc123)\n  on build-shell token, system ID: s_shell\nPreparing the \"shell\" executor\nRunning on shell-host..."))
		case "/api/v4/projects/42/jobs/1002/trace":
			traceRequests.Add(1)
			w.WriteHeader(http.StatusNotFound)
		case "/api/v4/projects/42/jobs/2001/trace":
			traceRequests.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Preparing the \"docker\" executor\nRunning on docker-host..."))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := gitlabx.New(server.URL, "test-token")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	runners, err := DiscoverRunnersFromLogs(context.Background(), client, int64(42), "main", RunnerLogLimits{
		Pipelines: 2,
		Jobs:      2,
		TraceBytes: 64 << 10,
	})
	if err != nil {
		t.Fatalf("DiscoverRunnersFromLogs: %v", err)
	}
	if got := len(runners); got != 2 {
		t.Fatalf("runner count = %d, want 2: %+v", got, runners)
	}
	if got := pipelineJobRequests.Load(); got != 2 {
		t.Fatalf("pipeline job requests = %d, want 2", got)
	}
	if got := traceRequests.Load(); got != 3 {
		t.Fatalf("trace requests = %d, want 3", got)
	}

	shell := runners[0]
	if shell.RunnerID != 7 || shell.Description != "build-shell" || shell.RunnerType != "project_type" {
		t.Fatalf("shell runner identity = %+v", shell)
	}
	if shell.Executor != "shell" || shell.RunnerName != "shell-host" || shell.SystemID != "s_shell" {
		t.Fatalf("shell runner trace metadata = %+v", shell)
	}
	if shell.Version != "18.2.1" || shell.Revision != "abc123" || shell.Platform != "linux" || shell.Architecture != "amd64" {
		t.Fatalf("shell runner manager metadata = %+v", shell)
	}
	for _, want := range []string{"shell", "linux", "trusted"} {
		if !slices.Contains(shell.Tags, want) {
			t.Errorf("shell tags %v missing %q", shell.Tags, want)
		}
	}
	if !slices.Contains(shell.Sources, "job_api") || !slices.Contains(shell.Sources, "job_trace") {
		t.Errorf("shell sources = %v, want job_api and job_trace", shell.Sources)
	}
	if shell.Confidence != "high" {
		t.Errorf("shell confidence = %q, want high", shell.Confidence)
	}
	if !slices.Equal(shell.JobIDs, []int64{1001, 1002}) {
		t.Errorf("shell job IDs = %v, want [1001 1002]", shell.JobIDs)
	}

	docker := runners[1]
	if docker.RunnerID != 8 || docker.Executor != "docker" || docker.Architecture != "arm64" {
		t.Fatalf("docker runner = %+v", docker)
	}
}

func TestDiscoverRunnersFromLogs_RejectsNilClient(t *testing.T) {
	t.Parallel()

	_, err := DiscoverRunnersFromLogs(context.Background(), nil, int64(42), "main", RunnerLogLimits{})
	if err == nil {
		t.Fatal("expected nil client error")
	}
}
