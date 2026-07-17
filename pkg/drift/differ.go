package drift

import (
	"fmt"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
)

const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"

	CategoryJob      = "job"
	CategoryVariable = "variable"
	CategoryInclude  = "include"
	CategoryStage    = "stage"
	CategoryScript   = "script"
	CategoryRule     = "rule"
)

// Change represents a single structural difference between two CI configs.
type Change struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Name     string `json:"name"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// DriftReport holds the complete diff result with optional security assessment.
type DriftReport struct {
	ProjectPath    string           `json:"project_path,omitempty"`
	CurrentRef     string           `json:"current_ref,omitempty"`
	BaselineRef    string           `json:"baseline_ref,omitempty"`
	Timestamp      time.Time        `json:"timestamp"`
	Changes        []Change         `json:"changes"`
	SecurityImpact []SecurityChange `json:"security_impact,omitempty"`
}

// Diff compares two pipeline documents and returns all structural changes.
func Diff(baseline, current *pipeline.Document) DriftReport {
	report := DriftReport{Timestamp: time.Now()}
	if baseline == nil && current == nil {
		return report
	}
	if baseline == nil {
		baseline = &pipeline.Document{}
	}
	if current == nil {
		current = &pipeline.Document{}
	}

	report.Changes = append(report.Changes, diffJobs(baseline, current)...)
	report.Changes = append(report.Changes, diffIncludes(baseline, current)...)
	report.Changes = append(report.Changes, diffVariables(baseline, current)...)
	report.Changes = append(report.Changes, diffStages(baseline, current)...)

	return report
}

func diffJobs(baseline, current *pipeline.Document) []Change {
	var changes []Change
	baseJobs := map[string]pipeline.Job{}
	for _, j := range baseline.Jobs {
		baseJobs[j.Name] = j
	}
	curJobs := map[string]pipeline.Job{}
	for _, j := range current.Jobs {
		curJobs[j.Name] = j
	}

	for name := range curJobs {
		if _, ok := baseJobs[name]; !ok {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryJob, Name: name})
		}
	}
	for name := range baseJobs {
		if _, ok := curJobs[name]; !ok {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryJob, Name: name})
		}
	}
	for name, curJob := range curJobs {
		baseJob, ok := baseJobs[name]
		if !ok {
			continue
		}
		oldScript := strings.Join(baseJob.Script, "\n")
		newScript := strings.Join(curJob.Script, "\n")
		if oldScript != newScript {
			changes = append(changes, Change{
				Type:     ChangeModified,
				Category: CategoryScript,
				Name:     name,
				OldValue: oldScript,
				NewValue: newScript,
			})
		}
		if baseJob.Image != curJob.Image {
			changes = append(changes, Change{
				Type:     ChangeModified,
				Category: CategoryJob,
				Name:     name,
				Detail:   fmt.Sprintf("image changed: %s -> %s", baseJob.Image, curJob.Image),
			})
		}
	}
	return changes
}

func diffIncludes(baseline, current *pipeline.Document) []Change {
	var changes []Change
	baseSet := map[string]bool{}
	for _, inc := range baseline.Includes {
		baseSet[includeKey(inc)] = true
	}
	curSet := map[string]bool{}
	for _, inc := range current.Includes {
		curSet[includeKey(inc)] = true
	}
	for _, inc := range current.Includes {
		if !baseSet[includeKey(inc)] {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryInclude, Name: includeKey(inc)})
		}
	}
	for _, inc := range baseline.Includes {
		if !curSet[includeKey(inc)] {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryInclude, Name: includeKey(inc)})
		}
	}
	return changes
}

func includeKey(inc pipeline.Include) string {
	if inc.Remote != "" {
		return "remote:" + inc.Remote
	}
	if inc.Project != "" {
		return fmt.Sprintf("project:%s/%s", inc.Project, strings.Join(inc.File, ","))
	}
	if inc.Local != "" {
		return "local:" + inc.Local
	}
	if inc.Template != "" {
		return "template:" + inc.Template
	}
	if inc.Component != "" {
		return "component:" + inc.Component
	}
	return "unknown"
}

func diffVariables(baseline, current *pipeline.Document) []Change {
	var changes []Change
	for k := range current.Variables {
		if _, ok := baseline.Variables[k]; !ok {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryVariable, Name: k})
		}
	}
	for k := range baseline.Variables {
		if _, ok := current.Variables[k]; !ok {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryVariable, Name: k})
		}
	}
	return changes
}

func diffStages(baseline, current *pipeline.Document) []Change {
	var changes []Change
	baseSet := map[string]bool{}
	for _, s := range baseline.Stages {
		baseSet[s] = true
	}
	curSet := map[string]bool{}
	for _, s := range current.Stages {
		curSet[s] = true
	}
	for _, s := range current.Stages {
		if !baseSet[s] {
			changes = append(changes, Change{Type: ChangeAdded, Category: CategoryStage, Name: s})
		}
	}
	for _, s := range baseline.Stages {
		if !curSet[s] {
			changes = append(changes, Change{Type: ChangeRemoved, Category: CategoryStage, Name: s})
		}
	}
	return changes
}
