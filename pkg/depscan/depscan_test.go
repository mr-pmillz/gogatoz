package depscan

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAuditor struct {
	result AuditResult
	err    error
	paths  []string
	closed bool
}

func (f *fakeAuditor) Audit(_ context.Context, paths []string) (AuditResult, error) {
	f.paths = append([]string(nil), paths...)
	return f.result, f.err
}

func (f *fakeAuditor) Close() { f.closed = true }

func TestScanner_ScanMapsDepxVerdictsToFindings(t *testing.T) {
	auditor := &fakeAuditor{result: AuditResult{
		Dependencies: 3,
		Summary: AuditSummary{
			Lockfiles:   1,
			Total:       3,
			Malicious:   1,
			Quarantined: 1,
			Clean:       1,
		},
		Lockfiles: []Lockfile{{Path: "/repo/package-lock.json", Type: "lockfile", Ecosystem: "npm", Dependencies: 3}},
		Findings: []AuditFinding{
			{
				Verdict:   "malicious",
				Ecosystem: "npm",
				Name:      "gogatoz-synthetic-malicious",
				Version:   "1.2.3",
				IDs:       []string{"MAL-2099-GOGATOZ-TEST"},
				Summary:   "synthetic test advisory",
				Source:    "/repo/package-lock.json",
			},
			{
				Verdict:   "quarantined",
				Ecosystem: "npm",
				Name:      "gogatoz-synthetic-quarantined",
				Version:   "9.9.9",
				IDs:       []string{"MAL-2099-GOGATOZ-QUARANTINE"},
				Source:    "/repo/bom.cdx.json",
			},
		},
	}}

	scanner := NewScanner(auditor)
	report, err := scanner.Scan(context.Background(), []string{"  /repo  ", ""})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(auditor.paths) != 1 || auditor.paths[0] != "/repo" {
		t.Fatalf("auditor paths = %v, want [/repo]", auditor.paths)
	}
	if report.Engine != "depx" {
		t.Fatalf("Engine = %q, want depx", report.Engine)
	}
	if report.Dependencies != 3 || len(report.Findings) != 2 {
		t.Fatalf("report = %+v", report)
	}

	malicious := report.Findings[0]
	if malicious.ID != MaliciousDependencyID {
		t.Fatalf("malicious ID = %q", malicious.ID)
	}
	if malicious.SourceFile != "/repo/package-lock.json" {
		t.Fatalf("malicious SourceFile = %q", malicious.SourceFile)
	}
	for _, want := range []string{"npm", "gogatoz-synthetic-malicious", "1.2.3", "MAL-2099-GOGATOZ-TEST"} {
		if !strings.Contains(malicious.Evidence, want) {
			t.Errorf("malicious evidence %q missing %q", malicious.Evidence, want)
		}
	}
	if malicious.Recommendation == "" {
		t.Error("malicious finding has no recommendation")
	}

	quarantined := report.Findings[1]
	if quarantined.ID != QuarantinedDependencyID {
		t.Fatalf("quarantined ID = %q", quarantined.ID)
	}
	if quarantined.SourceFile != "/repo/bom.cdx.json" {
		t.Fatalf("quarantined SourceFile = %q", quarantined.SourceFile)
	}
}

func TestScanner_ScanDefaultsToCurrentDirectory(t *testing.T) {
	auditor := &fakeAuditor{}
	scanner := NewScanner(auditor)

	if _, err := scanner.Scan(context.Background(), nil); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(auditor.paths) != 1 || auditor.paths[0] != "." {
		t.Fatalf("auditor paths = %v, want [.]", auditor.paths)
	}
}

func TestScanner_CloseReleasesAuditorAndIsNilSafe(t *testing.T) {
	auditor := &fakeAuditor{}
	NewScanner(auditor).Close()
	if !auditor.closed {
		t.Fatal("Close did not release the auditor")
	}

	var nilScanner *Scanner
	nilScanner.Close()
}

func TestScanner_ScanWrapsAuditorError(t *testing.T) {
	wantErr := errors.New("inventory unavailable")
	scanner := NewScanner(&fakeAuditor{err: wantErr})

	_, err := scanner.Scan(context.Background(), []string{"."})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Scan error = %v, want wrapped %v", err, wantErr)
	}
}

type concurrentAuditor struct {
	active    atomic.Int32
	maxActive atomic.Int32
}

func (a *concurrentAuditor) Audit(_ context.Context, _ []string) (AuditResult, error) {
	active := a.active.Add(1)
	for {
		maximum := a.maxActive.Load()
		if active <= maximum || a.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	a.active.Add(-1)
	return AuditResult{}, nil
}

func (a *concurrentAuditor) Close() {}

func TestScanner_ScanSerializesNativeAudits(t *testing.T) {
	auditor := &concurrentAuditor{}
	scanner := NewScanner(auditor)

	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			if _, err := scanner.Scan(context.Background(), []string{"."}); err != nil {
				t.Errorf("Scan: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := auditor.maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent depx audits = %d, want 1", got)
	}
}
