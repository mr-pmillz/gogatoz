package analyze

import (
	"fmt"
	"math"
	"testing"
)

func TestComputeScore_NoFindings(t *testing.T) {
	res := ComputeScore(nil)
	if res.Score != "A" {
		t.Errorf("expected score A, got %s", res.Score)
	}
	if res.FinalPoints != 100 {
		t.Errorf("expected 100 points, got %f", res.FinalPoints)
	}
	if res.RawPoints != 100 {
		t.Errorf("expected 100 raw points, got %f", res.RawPoints)
	}
	if res.CriticalMalusApplied {
		t.Error("malus should not be applied with no findings")
	}
	if len(res.CodeLosses) != 0 {
		t.Errorf("expected 0 code losses, got %d", len(res.CodeLosses))
	}
}

func TestComputeScore_EmptySlice(t *testing.T) {
	res := ComputeScore([]Finding{})
	if res.Score != "A" {
		t.Errorf("expected score A, got %s", res.Score)
	}
	if res.FinalPoints != 100 {
		t.Errorf("expected 100 points, got %f", res.FinalPoints)
	}
}

func TestComputeScore_SingleHigh(t *testing.T) {
	findings := []Finding{
		{ID: "VAR_INJECT", Severity: SeverityHigh},
	}
	res := ComputeScore(findings)

	// weight=15, count=1: loss = 15 * (1 + 0.5*log2(1)) = 15 * (1+0) = 15
	expectedLoss := 15.0
	expectedRaw := 100 - expectedLoss
	if math.Abs(res.RawPoints-expectedRaw) > 0.001 {
		t.Errorf("expected raw %.2f, got %.2f", expectedRaw, res.RawPoints)
	}
	if res.FinalPoints != res.RawPoints {
		t.Errorf("no malus expected: final=%.2f raw=%.2f", res.FinalPoints, res.RawPoints)
	}
	if res.Score != "B" {
		t.Errorf("expected B, got %s", res.Score)
	}
	if res.Counts.High != 1 {
		t.Errorf("expected 1 high, got %d", res.Counts.High)
	}
	if res.CriticalMalusApplied {
		t.Error("malus should not apply for high findings")
	}
}

func TestComputeScore_MultipleSameID(t *testing.T) {
	// 4 findings with same HIGH ID: loss = 15 * (1 + 0.5*log2(4)) = 15 * (1+1) = 30
	findings := []Finding{
		{ID: "SAME_CODE", Severity: SeverityHigh},
		{ID: "SAME_CODE", Severity: SeverityHigh},
		{ID: "SAME_CODE", Severity: SeverityHigh},
		{ID: "SAME_CODE", Severity: SeverityHigh},
	}
	res := ComputeScore(findings)
	expectedLoss := 15.0 * (1 + 0.5*math.Log2(4))
	expectedRaw := 100 - expectedLoss
	if math.Abs(res.RawPoints-expectedRaw) > 0.001 {
		t.Errorf("expected raw %.2f, got %.2f", expectedRaw, res.RawPoints)
	}
	if res.Counts.High != 4 {
		t.Errorf("expected 4 high, got %d", res.Counts.High)
	}
}

func TestComputeScore_HighCapApplied(t *testing.T) {
	// HIGH cap is 60. Many same-ID findings should hit the cap.
	// 2^20 = 1048576 findings: loss = 15*(1+0.5*20) = 15*11 = 165, capped to 60.
	var findings []Finding
	for i := 0; i < 1024; i++ {
		findings = append(findings, Finding{ID: "CAPPED", Severity: SeverityHigh})
	}
	res := ComputeScore(findings)

	if len(res.CodeLosses) != 1 {
		t.Fatalf("expected 1 code loss entry, got %d", len(res.CodeLosses))
	}
	cl := res.CodeLosses[0]
	if cl.CappedLoss != 60 {
		t.Errorf("expected capped loss 60, got %f", cl.CappedLoss)
	}
	if cl.UncappedLoss <= 60 {
		t.Errorf("uncapped loss should exceed cap, got %f", cl.UncappedLoss)
	}
	expectedRaw := 100.0 - 60.0
	if math.Abs(res.RawPoints-expectedRaw) > 0.001 {
		t.Errorf("expected raw %.2f, got %.2f", expectedRaw, res.RawPoints)
	}
}

func TestComputeScore_MediumCapApplied(t *testing.T) {
	// MEDIUM cap is 20, weight=6. Many findings: 6*(1+0.5*10) = 6*6 = 36 > 20.
	var findings []Finding
	for i := 0; i < 1024; i++ {
		findings = append(findings, Finding{ID: "MED_CAP", Severity: SeverityMedium})
	}
	res := ComputeScore(findings)

	if len(res.CodeLosses) != 1 {
		t.Fatalf("expected 1 code loss entry, got %d", len(res.CodeLosses))
	}
	if res.CodeLosses[0].CappedLoss != 20 {
		t.Errorf("expected capped loss 20, got %f", res.CodeLosses[0].CappedLoss)
	}
}

func TestComputeScore_LowCapApplied(t *testing.T) {
	// LOW cap is 10, weight=3. 64 findings: 3*(1+0.5*6) = 3*4 = 12 > 10.
	var findings []Finding
	for i := 0; i < 64; i++ {
		findings = append(findings, Finding{ID: "LOW_CAP", Severity: SeverityLow})
	}
	res := ComputeScore(findings)

	if len(res.CodeLosses) != 1 {
		t.Fatalf("expected 1 code loss entry, got %d", len(res.CodeLosses))
	}
	if res.CodeLosses[0].CappedLoss != 10 {
		t.Errorf("expected capped loss 10, got %f", res.CodeLosses[0].CappedLoss)
	}
}

func TestComputeScore_CriticalMalus(t *testing.T) {
	findings := []Finding{
		{ID: "CRIT_VULN", Severity: SeverityCritical},
	}
	res := ComputeScore(findings)

	// weight=25, count=1: loss = 25*(1+0) = 25, raw = 75
	// But critical malus caps final at 30.
	if res.RawPoints != 75 {
		t.Errorf("expected raw 75, got %f", res.RawPoints)
	}
	if res.FinalPoints != 30 {
		t.Errorf("expected final 30, got %f", res.FinalPoints)
	}
	if res.Score != "E" {
		t.Errorf("expected E, got %s", res.Score)
	}
	if !res.CriticalMalusApplied {
		t.Error("CriticalMalusApplied should be true")
	}
	if res.Counts.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", res.Counts.Critical)
	}
}

func TestComputeScore_CriticalAlreadyLow(t *testing.T) {
	// When raw points are already <= 30 from critical findings, the malus
	// condition (final > 30) is false, so CriticalMalusApplied stays false.
	// Two distinct critical codes, 4 occurrences each:
	// Each code: loss = 25*(1+0.5*log2(4)) = 25*2 = 50
	// Total = 100, raw = 0, final = 0. Malus doesn't fire.
	var findings []Finding
	for i := 0; i < 4; i++ {
		findings = append(findings, Finding{ID: "CRIT_A", Severity: SeverityCritical})
	}
	for i := 0; i < 4; i++ {
		findings = append(findings, Finding{ID: "CRIT_B", Severity: SeverityCritical})
	}
	res := ComputeScore(findings)

	if res.RawPoints != 0 {
		t.Errorf("expected raw 0, got %f", res.RawPoints)
	}
	if res.FinalPoints != 0 {
		t.Errorf("expected final 0, got %f", res.FinalPoints)
	}
	if res.CriticalMalusApplied {
		t.Error("malus should not be applied when raw is already <= 30")
	}
	if res.Score != "E" {
		t.Errorf("expected E, got %s", res.Score)
	}
}

func TestComputeScore_MixedSeverities(t *testing.T) {
	findings := []Finding{
		{ID: "HIGH_A", Severity: SeverityHigh},
		{ID: "MED_B", Severity: SeverityMedium},
		{ID: "MED_B", Severity: SeverityMedium},
		{ID: "LOW_C", Severity: SeverityLow},
		{ID: "INFO_D", Severity: SeverityInformational},
	}
	res := ComputeScore(findings)

	// HIGH_A: 15*(1+0) = 15
	// MED_B: 6*(1+0.5*log2(2)) = 6*(1+0.5) = 9
	// LOW_C: 3*(1+0) = 3
	// INFO_D: 0
	// total loss = 15+9+3 = 27, raw = 73
	expectedRaw := 73.0
	if math.Abs(res.RawPoints-expectedRaw) > 0.001 {
		t.Errorf("expected raw %.2f, got %.2f", expectedRaw, res.RawPoints)
	}
	if res.Score != "B" {
		t.Errorf("expected B, got %s", res.Score)
	}
	if res.Counts.High != 1 {
		t.Errorf("expected 1 high, got %d", res.Counts.High)
	}
	if res.Counts.Medium != 2 {
		t.Errorf("expected 2 medium, got %d", res.Counts.Medium)
	}
	if res.Counts.Low != 1 {
		t.Errorf("expected 1 low, got %d", res.Counts.Low)
	}
	if res.Counts.Informational != 1 {
		t.Errorf("expected 1 info, got %d", res.Counts.Informational)
	}
}

func TestComputeScore_FalsePositivesSkipped(t *testing.T) {
	findings := []Finding{
		{ID: "REAL", Severity: SeverityHigh},
		{ID: "FAKE", Severity: SeverityCritical, FalsePositive: true},
		{ID: "ALSO_FAKE", Severity: SeverityHigh, FalsePositive: true},
	}
	res := ComputeScore(findings)

	// Only REAL counts. loss = 15, raw = 85.
	if res.Counts.High != 1 {
		t.Errorf("expected 1 high (FP excluded), got %d", res.Counts.High)
	}
	if res.Counts.Critical != 0 {
		t.Errorf("expected 0 critical (FP excluded), got %d", res.Counts.Critical)
	}
	if res.CriticalMalusApplied {
		t.Error("malus should not apply when critical is a false positive")
	}
	if res.RawPoints != 85 {
		t.Errorf("expected raw 85, got %f", res.RawPoints)
	}
	if res.Score != "B" {
		t.Errorf("expected B, got %s", res.Score)
	}
}

func TestComputeScore_AllFalsePositives(t *testing.T) {
	findings := []Finding{
		{ID: "X", Severity: SeverityHigh, FalsePositive: true},
		{ID: "Y", Severity: SeverityCritical, FalsePositive: true},
	}
	res := ComputeScore(findings)
	if res.FinalPoints != 100 {
		t.Errorf("expected 100 when all are FP, got %f", res.FinalPoints)
	}
	if res.Score != "A" {
		t.Errorf("expected A, got %s", res.Score)
	}
}

func TestComputeScore_InformationalOnly(t *testing.T) {
	findings := []Finding{
		{ID: "NOTE_1", Severity: SeverityInformational},
		{ID: "NOTE_2", Severity: SeverityInformational},
	}
	res := ComputeScore(findings)
	if res.RawPoints != 100 {
		t.Errorf("informational should not reduce score: raw=%f", res.RawPoints)
	}
	if res.Score != "A" {
		t.Errorf("expected A, got %s", res.Score)
	}
	if res.Counts.Informational != 2 {
		t.Errorf("expected 2 informational, got %d", res.Counts.Informational)
	}
}

func TestComputeScore_FloorAtZero(t *testing.T) {
	// Massive losses should floor at 0, not go negative.
	var findings []Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, Finding{ID: "MEGA", Severity: SeverityCritical})
	}
	res := ComputeScore(findings)
	if res.RawPoints < 0 {
		t.Errorf("raw should not go below 0, got %f", res.RawPoints)
	}
	if res.FinalPoints < 0 {
		t.Errorf("final should not go below 0, got %f", res.FinalPoints)
	}
}

func TestComputeScore_GradeBoundaries(t *testing.T) {
	// Each unique finding with count=1 produces exactly its weight in loss.
	// HIGH=15, MEDIUM=6, LOW=3. We construct findings to hit exact boundaries.
	tests := []struct {
		name          string
		findings      []Finding
		expectedRaw   float64
		expectedGrade string
	}{
		{
			// loss=6+3+1*0 = 9 (MED+LOW) -> raw=91 -> A (but we need exactly 90)
			// Actually: 1 MED(6) + 1 LOW(3) + 1 LOW(3) = two unique LOWs -> 6+3+3=12
			// Use: we need loss=10. Can't hit 10 with these weights. Use loss=9 for raw=91.
			// Or HIGH(15)-5=not possible. Just test raw=90 exactly: not reachable
			// with these integer weights. Instead test nearest achievable boundaries.
			// loss=6+3=9 -> raw=91 -> A
			name: "raw 90 (MED+LOW loss=9) -> A remains at 91",
			findings: []Finding{
				{ID: "GB_M0", Severity: SeverityMedium},
				{ID: "GB_L0", Severity: SeverityLow},
			},
			expectedRaw:   91,
			expectedGrade: "A",
		},
		{
			// loss=15 -> raw=85 -> B
			name: "raw 85 (1 HIGH) -> B",
			findings: []Finding{
				{ID: "GB_H0", Severity: SeverityHigh},
			},
			expectedRaw:   85,
			expectedGrade: "B",
		},
		{
			// loss=15+15+15+6=51 -> raw=49 -> D (below 51)
			name: "raw 49 (3 HIGH + 1 MED) -> D",
			findings: func() []Finding {
				var f []Finding
				for i := 0; i < 3; i++ {
					f = append(f, Finding{ID: fmt.Sprintf("GB_H%d", i), Severity: SeverityHigh})
				}
				f = append(f, Finding{ID: "GB_M1", Severity: SeverityMedium})
				return f
			}(),
			expectedRaw:   49,
			expectedGrade: "D",
		},
		{
			// loss=15+15+15+6+6=57 -> raw=43 -> D (>= 31)
			name: "raw 43 (3 HIGH + 2 MED) -> D",
			findings: func() []Finding {
				var f []Finding
				for i := 0; i < 3; i++ {
					f = append(f, Finding{ID: fmt.Sprintf("GB_H%d", i), Severity: SeverityHigh})
				}
				for i := 0; i < 2; i++ {
					f = append(f, Finding{ID: fmt.Sprintf("GB_M%d", i), Severity: SeverityMedium})
				}
				return f
			}(),
			expectedRaw:   43,
			expectedGrade: "D",
		},
		{
			// loss=15*4+6+3=69 -> raw=31 -> D (exactly at boundary)
			name: "raw 31 (4 HIGH + 1 MED + 1 LOW) -> D",
			findings: func() []Finding {
				var f []Finding
				for i := 0; i < 4; i++ {
					f = append(f, Finding{ID: fmt.Sprintf("GB_H%d", i), Severity: SeverityHigh})
				}
				f = append(f, Finding{ID: "GB_M0", Severity: SeverityMedium})
				f = append(f, Finding{ID: "GB_L0", Severity: SeverityLow})
				return f
			}(),
			expectedRaw:   31,
			expectedGrade: "D",
		},
		{
			// loss=15*4+6+6=72 -> raw=28 -> E (< 31)
			name: "raw 28 (4 HIGH + 2 MED) -> E",
			findings: func() []Finding {
				var f []Finding
				for i := 0; i < 4; i++ {
					f = append(f, Finding{ID: fmt.Sprintf("GB_H%d", i), Severity: SeverityHigh})
				}
				for i := 0; i < 2; i++ {
					f = append(f, Finding{ID: fmt.Sprintf("GB_M%d", i), Severity: SeverityMedium})
				}
				return f
			}(),
			expectedRaw:   28,
			expectedGrade: "E",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := ComputeScore(tc.findings)
			if math.Abs(res.RawPoints-tc.expectedRaw) > 0.001 {
				t.Errorf("expected raw %.2f, got %.2f", tc.expectedRaw, res.RawPoints)
			}
			if res.Score != tc.expectedGrade {
				t.Errorf("expected %s, got %s (final=%.2f, raw=%.2f)",
					tc.expectedGrade, res.Score, res.FinalPoints, res.RawPoints)
			}
		})
	}
}

func TestComputeScore_BoundaryBelow90(t *testing.T) {
	// 2 medium findings with different IDs: 6+6 = 12 loss, raw = 88 -> B
	findings := []Finding{
		{ID: "M1", Severity: SeverityMedium},
		{ID: "M2", Severity: SeverityMedium},
	}
	res := ComputeScore(findings)
	if res.RawPoints != 88 {
		t.Errorf("expected raw 88, got %f", res.RawPoints)
	}
	if res.Score != "B" {
		t.Errorf("expected B for 88 points, got %s", res.Score)
	}
}

func TestComputeScore_BoundaryBelow71(t *testing.T) {
	// raw exactly 70 -> C.
	// 2 HIGH IDs: 15+15 = 30 loss, raw = 70. That's below 71 -> C.
	findings := []Finding{
		{ID: "H1", Severity: SeverityHigh},
		{ID: "H2", Severity: SeverityHigh},
	}
	res := ComputeScore(findings)
	if res.RawPoints != 70 {
		t.Errorf("expected raw 70, got %f", res.RawPoints)
	}
	if res.Score != "C" {
		t.Errorf("expected C for 70 points, got %s", res.Score)
	}
}

func TestComputeScore_BoundaryBelow51(t *testing.T) {
	// raw exactly 50 -> D.
	// HIGH cap 60, so we can lose up to 60 from one HIGH code.
	// 2 HIGH IDs + 1 MED + 1 LOW: 15+15+6+3=39 loss? No, need 50 loss.
	// 3 HIGH IDs + 1 LOW: 15+15+15+3 = 48 loss, raw=52 -> C.
	// 3 HIGH + 1 MED: 15+15+15+6 = 51 loss, raw=49 -> D. Almost.
	// Use 3 HIGH + 1 LOW + 1 LOW: 15+15+15+3+3 = 51 loss... can't get 50 exact with these weights easily.
	// Let's just use 3 HIGH + 1 MED = 51 loss, raw = 49.
	findings := []Finding{
		{ID: "HA", Severity: SeverityHigh},
		{ID: "HB", Severity: SeverityHigh},
		{ID: "HC", Severity: SeverityHigh},
		{ID: "MA", Severity: SeverityMedium},
	}
	res := ComputeScore(findings)
	expectedRaw := 100.0 - (15 + 15 + 15 + 6)
	if math.Abs(res.RawPoints-expectedRaw) > 0.001 {
		t.Errorf("expected raw %.2f, got %.2f", expectedRaw, res.RawPoints)
	}
	if res.Score != "D" {
		t.Errorf("expected D for %.2f points, got %s", res.RawPoints, res.Score)
	}
}

func TestComputeScore_CodeLossesSorted(t *testing.T) {
	findings := []Finding{
		{ID: "LOW_THING", Severity: SeverityLow},
		{ID: "HIGH_THING", Severity: SeverityHigh},
		{ID: "MED_THING", Severity: SeverityMedium},
	}
	res := ComputeScore(findings)

	if len(res.CodeLosses) != 3 {
		t.Fatalf("expected 3 code losses, got %d", len(res.CodeLosses))
	}

	// Should be sorted by capped loss descending: HIGH(15) > MED(6) > LOW(3)
	if res.CodeLosses[0].Code != "HIGH_THING" {
		t.Errorf("expected first loss to be HIGH_THING, got %s", res.CodeLosses[0].Code)
	}
	if res.CodeLosses[1].Code != "MED_THING" {
		t.Errorf("expected second loss to be MED_THING, got %s", res.CodeLosses[1].Code)
	}
	if res.CodeLosses[2].Code != "LOW_THING" {
		t.Errorf("expected third loss to be LOW_THING, got %s", res.CodeLosses[2].Code)
	}

	// Verify ordering is strictly descending.
	for i := 1; i < len(res.CodeLosses); i++ {
		if res.CodeLosses[i].CappedLoss > res.CodeLosses[i-1].CappedLoss {
			t.Errorf("losses not sorted descending at index %d: %.2f > %.2f",
				i, res.CodeLosses[i].CappedLoss, res.CodeLosses[i-1].CappedLoss)
		}
	}
}

func TestComputeScore_LogarithmicGrowth(t *testing.T) {
	// Verify the log2 scaling: doubling count adds 0.5*weight more loss.
	// 1 finding: loss = w * (1 + 0.5*0) = w
	// 2 findings: loss = w * (1 + 0.5*1) = 1.5w
	// 4 findings: loss = w * (1 + 0.5*2) = 2w
	// 8 findings: loss = w * (1 + 0.5*3) = 2.5w
	w := 6.0 // MEDIUM weight
	tests := []struct {
		count    int
		expected float64
	}{
		{1, w * 1.0},
		{2, w * 1.5},
		{4, w * 2.0},
		{8, w * 2.5},
	}
	for _, tc := range tests {
		var findings []Finding
		for i := 0; i < tc.count; i++ {
			findings = append(findings, Finding{ID: "LOG_TEST", Severity: SeverityMedium})
		}
		res := ComputeScore(findings)
		loss := 100 - res.RawPoints
		if math.Abs(loss-tc.expected) > 0.001 {
			t.Errorf("count=%d: expected loss %.2f, got %.2f", tc.count, tc.expected, loss)
		}
	}
}

func TestScoreColor(t *testing.T) {
	tests := []struct {
		score    string
		expected string
	}{
		{"A", "green"},
		{"B", "green"},
		{"C", "yellow"},
		{"D", "red"},
		{"E", "red"},
		{"?", "red"},
	}
	for _, tc := range tests {
		got := ScoreColor(tc.score)
		if got != tc.expected {
			t.Errorf("ScoreColor(%q) = %q, want %q", tc.score, got, tc.expected)
		}
	}
}

func TestComputeScore_SeverityCounts(t *testing.T) {
	findings := []Finding{
		{ID: "C1", Severity: SeverityCritical},
		{ID: "H1", Severity: SeverityHigh},
		{ID: "H2", Severity: SeverityHigh},
		{ID: "M1", Severity: SeverityMedium},
		{ID: "M2", Severity: SeverityMedium},
		{ID: "M3", Severity: SeverityMedium},
		{ID: "L1", Severity: SeverityLow},
		{ID: "I1", Severity: SeverityInformational},
		{ID: "I2", Severity: SeverityInformational},
		{ID: "FP", Severity: SeverityHigh, FalsePositive: true},
	}
	res := ComputeScore(findings)
	if res.Counts.Critical != 1 {
		t.Errorf("critical: want 1, got %d", res.Counts.Critical)
	}
	if res.Counts.High != 2 {
		t.Errorf("high: want 2, got %d", res.Counts.High)
	}
	if res.Counts.Medium != 3 {
		t.Errorf("medium: want 3, got %d", res.Counts.Medium)
	}
	if res.Counts.Low != 1 {
		t.Errorf("low: want 1, got %d", res.Counts.Low)
	}
	if res.Counts.Informational != 2 {
		t.Errorf("informational: want 2, got %d", res.Counts.Informational)
	}
}

func TestComputeScore_CriticalUncapped(t *testing.T) {
	// Critical has no per-severity cap. Many critical findings should result in
	// loss exceeding 60 (the HIGH cap), demonstrating critical is unbounded.
	var findings []Finding
	// 16 critical findings: loss = 25*(1+0.5*log2(16)) = 25*(1+2) = 75
	for i := 0; i < 16; i++ {
		findings = append(findings, Finding{ID: "BIG_CRIT", Severity: SeverityCritical})
	}
	res := ComputeScore(findings)
	expectedLoss := 25 * (1 + 0.5*math.Log2(16))
	if len(res.CodeLosses) != 1 {
		t.Fatalf("expected 1 code loss, got %d", len(res.CodeLosses))
	}
	cl := res.CodeLosses[0]
	if math.Abs(cl.CappedLoss-expectedLoss) > 0.001 {
		t.Errorf("capped loss should equal uncapped for critical: got %.2f, want %.2f",
			cl.CappedLoss, expectedLoss)
	}
	if cl.CappedLoss != cl.UncappedLoss {
		t.Errorf("critical should have capped == uncapped: capped=%.2f uncapped=%.2f",
			cl.CappedLoss, cl.UncappedLoss)
	}
}
