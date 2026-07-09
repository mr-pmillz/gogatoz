package analyze

import (
	"math"
	"sort"
)

// SeverityCounts tallies the number of findings at each severity level.
type SeverityCounts struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

// CodeLoss records the point deduction for a single finding code (ID).
type CodeLoss struct {
	Code         string   `json:"code"`
	Severity     Severity `json:"severity"`
	Count        int      `json:"count"`
	Weight       float64  `json:"weight"`
	UncappedLoss float64  `json:"uncappedLoss"`
	CappedLoss   float64  `json:"cappedLoss"`
}

// ScoreResult contains the computed compliance score and supporting detail.
type ScoreResult struct {
	RawPoints            float64        `json:"rawPoints"`
	FinalPoints          float64        `json:"finalPoints"`
	Score                string         `json:"score"`
	Counts               SeverityCounts `json:"counts"`
	CriticalMalusApplied bool           `json:"criticalMalusApplied"`
	CodeLosses           []CodeLoss     `json:"codeLosses,omitempty"`
}

const basePoints = 100.0

// severityWeight returns the point weight for a severity level.
func severityWeight(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 15
	case SeverityMedium:
		return 6
	case SeverityLow:
		return 3
	case SeverityInformational:
		return 0
	default:
		return 0
	}
}

// severityCap returns the per-severity cap on total loss for a given code.
// Critical findings have no cap (returns +Inf).
func severityCap(s Severity) float64 {
	switch s {
	case SeverityHigh:
		return 60
	case SeverityMedium:
		return 20
	case SeverityLow:
		return 10
	case SeverityCritical:
		return math.Inf(1)
	default:
		return 0 // INFORMATIONAL: weight is 0, cap is irrelevant
	}
}

// letterGrade converts a numeric score to a letter grade.
func letterGrade(pts float64) string {
	switch {
	case pts >= 90:
		return "A"
	case pts >= 71:
		return "B"
	case pts >= 51:
		return "C"
	case pts >= 31:
		return "D"
	default:
		return "E"
	}
}

// ScoreColor returns a display color name for a letter grade.
func ScoreColor(score string) string {
	switch score {
	case "A", "B":
		return "green"
	case "C":
		return "yellow"
	case "D", "E":
		return "red"
	default:
		return "red"
	}
}

// codeAgg accumulates count and worst severity per finding code.
type codeAgg struct {
	count   int
	maxSev  Severity
	maxRank int
}

// sevRank returns a numeric rank for severity comparison (higher is worse).
func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ComputeScore evaluates a slice of findings and returns a compliance score
// using the scoring-v3 algorithm (ported from Plumber).
//
// Findings are grouped by code (ID) only. The worst (highest) severity seen
// for each code determines the weight and cap, preventing a scoring inversion
// where consolidating severity levels could reduce the total penalty.
//
// False-positive findings are excluded from the calculation.
func ComputeScore(findings []Finding) ScoreResult {
	var counts SeverityCounts
	codes := make(map[string]*codeAgg)

	for _, f := range findings {
		if f.FalsePositive {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			counts.Critical++
		case SeverityHigh:
			counts.High++
		case SeverityMedium:
			counts.Medium++
		case SeverityLow:
			counts.Low++
		case SeverityInformational:
			counts.Informational++
		}
		agg, ok := codes[f.ID]
		if !ok {
			agg = &codeAgg{maxSev: f.Severity, maxRank: sevRank(f.Severity)}
			codes[f.ID] = agg
		}
		agg.count++
		if r := sevRank(f.Severity); r > agg.maxRank {
			agg.maxSev = f.Severity
			agg.maxRank = r
		}
	}

	var losses []CodeLoss
	var totalLoss float64

	for code, agg := range codes {
		w := severityWeight(agg.maxSev)
		uncapped := w * (1 + 0.5*math.Log2(float64(agg.count)))
		cap := severityCap(agg.maxSev)
		capped := math.Min(uncapped, cap)

		losses = append(losses, CodeLoss{
			Code:         code,
			Severity:     agg.maxSev,
			Count:        agg.count,
			Weight:       w,
			UncappedLoss: uncapped,
			CappedLoss:   capped,
		})
		totalLoss += capped
	}

	// Sort by capped loss descending, break ties by code name ascending.
	sort.Slice(losses, func(i, j int) bool {
		if losses[i].CappedLoss != losses[j].CappedLoss {
			return losses[i].CappedLoss > losses[j].CappedLoss
		}
		return losses[i].Code < losses[j].Code
	})

	raw := basePoints - totalLoss
	if raw < 0 {
		raw = 0
	}

	final := raw
	malusApplied := false
	if counts.Critical > 0 && final > 30 {
		final = 30
		malusApplied = true
	}

	return ScoreResult{
		RawPoints:            raw,
		FinalPoints:          final,
		Score:                letterGrade(final),
		Counts:               counts,
		CriticalMalusApplied: malusApplied,
		CodeLosses:           losses,
	}
}
