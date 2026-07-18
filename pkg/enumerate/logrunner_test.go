package enumerate

import "testing"

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
