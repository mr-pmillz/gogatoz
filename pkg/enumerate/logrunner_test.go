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
			name:     "standard shell executor",
			trace:    "Running on 7ff7eebb265c using shell executor...\nBuilding...",
			wantName: "7ff7eebb265c",
			wantExec: "shell",
		},
		{
			name:     "docker executor",
			trace:    "Running on runner-abc123 using docker executor with image alpine:latest...",
			wantName: "runner-abc123",
			wantExec: "docker",
		},
		{
			name:     "kubernetes executor",
			trace:    "Running on runner-k8s-pod using kubernetes executor...\n$ echo hello",
			wantName: "runner-k8s-pod",
			wantExec: "kubernetes",
		},
		{
			name:     "with version line",
			trace:    "Running with gitlab-runner 17.5.0 (abc123)\n  on my-runner 1234abcd\nPreparing environment\nRunning on 1234abcd using shell executor...",
			wantName: "1234abcd",
			wantExec: "shell",
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
	trace := "Running with gitlab-runner 17.5.0 (deadbeef)\n  on my-runner 1234\nRunning on 1234 using docker executor..."
	info := ExtractRunnerFromLog(trace)
	if info == nil {
		t.Fatal("expected non-nil")
	}
	if info.Version != "17.5.0" {
		t.Errorf("version: got %q, want 17.5.0", info.Version)
	}
}
