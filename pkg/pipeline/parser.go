package pipeline

import (
	"errors"
	"fmt"
	"io"
	"maps"

	"gopkg.in/yaml.v3"
)

// Document represents a parsed .gitlab-ci.yml with a subset of fields we care about early on.
type Document struct {
	Raw          map[string]any
	Stages       []string
	Variables    map[string]any
	Includes     []Include
	Workflow     Workflow
	Default      map[string]any
	BeforeScript []string
	AfterScript  []string
	Jobs         []Job
	// Cache holds the global/default cache config (from default: or deprecated top-level cache:).
	// Each element is a single cache config map. GitLab supports up to 4 caches per job.
	Cache []map[string]any
	// Provenance maps job names to the include(s) they originated from during resolution.
	// Jobs defined in the root document typically have no provenance entries.
	Provenance map[string][]Include
}

// IncludeType identifies the type of GitLab include directive.
type IncludeType string

const (
	IncludeLocal     IncludeType = "local"
	IncludeProject   IncludeType = "project"
	IncludeRemote    IncludeType = "remote"
	IncludeTemplate  IncludeType = "template"
	IncludeComponent IncludeType = "component"
)

// Include is a normalized representation of an include directive.
type Include struct {
	Type      IncludeType    `json:"type"`
	Local     string         `json:"local,omitempty"`
	Project   string         `json:"project,omitempty"`
	File      []string       `json:"file,omitempty"`
	Ref       string         `json:"ref,omitempty"`
	Remote    string         `json:"remote,omitempty"`
	Template  string         `json:"template,omitempty"`
	Component string         `json:"component,omitempty"`
	Inputs    map[string]any `json:"inputs,omitempty"`
}

// Workflow models the optional top-level workflow: block, primarily its rules.
type Workflow struct {
	Name  string
	Rules any
}

// Job is a simplified view of a GitLab CI job.
type Job struct {
	Name         string
	Stage        string
	Script       []string
	BeforeScript []string // job-level before_script (nil = inherits global)
	AfterScript  []string // job-level after_script (nil = inherits global)
	Rules        any
	Only         any
	Except       any
	Tags         []string
	Variables    map[string]any
	Needs        []string
	Extends      []string       // inheritance: extends from parent job(s)
	When         string         // e.g., on_success, manual, delayed
	AllowFailure bool           // allow_failure flag
	Environment  string         // environment name (if any)
	Trigger      map[string]any // normalized trigger block (downstream pipelines)
	// Newly modeled fields for richer analysis
	Image     string           // resolved from string or image.name
	Services  []string         // normalized list of service names
	Artifacts map[string]any   // raw map for now
	Cache     map[string]any   // primary cache config (first element; nil if none)
	Caches    []map[string]any // all cache configs (supports GitLab's array-of-caches)
}

var reservedTopLevel = map[string]struct{}{
	"stages":        {},
	"variables":     {},
	"include":       {},
	"workflow":      {},
	"default":       {},
	"image":         {},
	"services":      {},
	"cache":         {},
	"before_script": {},
	"after_script":  {},
}

//// ParseFile loads and parses a .gitlab-ci.yml from disk.
// func ParseFile(path string) (*Document, error) {
//	f, err := os.Open(path)
//	if err != nil {
//		return nil, err
//	}
//	defer f.Close()
//	return Parse(f)
// }

// Parse reads YAML from r and returns a Document.
//
//nolint:gocognit
func Parse(r io.Reader) (*Document, error) {
	var raw map[string]any
	dec := yaml.NewDecoder(r)
	dec.KnownFields(false)
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("empty yaml")
	}
	// Apply YAML merge key (<<) semantics recursively before building the model
	raw = resolveMergesMap(raw)

	doc := &Document{Raw: raw}
	// stages
	if v, ok := raw["stages"]; ok {
		if arr, ok := v.([]any); ok {
			for _, it := range arr {
				if s, ok := it.(string); ok {
					doc.Stages = append(doc.Stages, s)
				}
			}
		}
	}
	// variables
	if v, ok := raw["variables"]; ok {
		if m, ok := v.(map[string]any); ok {
			doc.variablesFrom(m)
		}
	}
	// include
	if v, ok := raw["include"]; ok {
		doc.Includes = parseIncludes(v)
	}
	// workflow
	if v, ok := raw["workflow"]; ok {
		if m, ok := v.(map[string]any); ok {
			var wf Workflow
			if n, ok := m["name"].(string); ok {
				wf.Name = n
			}
			if r, ok := m["rules"]; ok {
				wf.Rules = r
			}
			doc.Workflow = wf
		}
	}
	// default
	if v, ok := raw["default"]; ok {
		if m, ok := v.(map[string]any); ok {
			doc.Default = m
		}
	}
	// global cache: prefer default:.cache, fall back to deprecated top-level cache:
	if doc.Default != nil {
		if c, ok := doc.Default["cache"]; ok {
			doc.Cache = parseCacheConfigs(c)
		}
	}
	if len(doc.Cache) == 0 {
		if c, ok := raw["cache"]; ok {
			doc.Cache = parseCacheConfigs(c)
		}
	}
	// before_script and after_script (top-level)
	if v, ok := raw["before_script"]; ok {
		doc.BeforeScript = toStringSlice(v)
	}
	if v, ok := raw["after_script"]; ok {
		doc.AfterScript = toStringSlice(v)
	}
	// jobs (heuristic: any top-level key not reserved and value is a mapping)
	jobMaps := map[string]map[string]any{}
	for k, v := range raw {
		if _, isReserved := reservedTopLevel[k]; isReserved {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		jobMaps[k] = m
	}
	// Build jobs from maps
	for k, m := range jobMaps {
		j := Job{Name: k}
		if stg, ok := m["stage"].(string); ok {
			j.Stage = stg
		}
		// script can be string or array of strings
		if sc, ok := m["script"]; ok {
			j.Script = toStringSlice(sc)
		}
		// before_script and after_script override the global defaults for this job
		if bs, ok := m["before_script"]; ok {
			j.BeforeScript = toStringSlice(bs)
		}
		if as, ok := m["after_script"]; ok {
			j.AfterScript = toStringSlice(as)
		}
		if tg, ok := m["tags"]; ok {
			j.Tags = toStringSlice(tg)
		}
		if r, ok := m["rules"]; ok {
			j.Rules = r
		}
		if o, ok := m["only"]; ok {
			j.Only = o
		}
		if e, ok := m["except"]; ok {
			j.Except = e
		}
		if vvars, ok := m["variables"].(map[string]any); ok {
			j.Variables = vvars
		}
		if needs, ok := m["needs"]; ok {
			j.Needs = toStringSlice(needs)
		}
		// extends can be string or array of strings
		if ext, ok := m["extends"]; ok {
			j.Extends = toStringSlice(ext)
		}
		// image can be string or mapping with name
		if img, ok := m["image"]; ok {
			if s, ok := img.(string); ok {
				j.Image = s
			} else if mm, ok := img.(map[string]any); ok {
				if name, ok := mm["name"].(string); ok {
					j.Image = name
				}
			}
		}
		// services can be array of strings or array of maps with name
		if sv, ok := m["services"]; ok {
			j.Services = toServiceNames(sv)
		}
		// artifacts: keep raw map for now
		if art, ok := m["artifacts"].(map[string]any); ok {
			j.Artifacts = art
		}
		// cache: supports both single map and array-of-maps
		if c, ok := m["cache"]; ok {
			j.Caches = parseCacheConfigs(c)
			if len(j.Caches) > 0 {
				j.Cache = j.Caches[0]
			}
		}
		// extra fields for analysis
		if w, ok := m["when"].(string); ok {
			j.When = w
		}
		if af, ok := m["allow_failure"].(bool); ok {
			j.AllowFailure = af
		}
		if envv, ok := m["environment"]; ok {
			if s, ok := envv.(string); ok {
				j.Environment = s
			} else if mm, ok := envv.(map[string]any); ok {
				if name, ok := mm["name"].(string); ok {
					j.Environment = name
				}
			}
		}
		if tr, ok := m["trigger"].(map[string]any); ok {
			j.Trigger = tr
		}
		doc.Jobs = append(doc.Jobs, j)
	}
	// Apply extends merge semantics after initial parse
	applyExtends(jobMaps, doc)
	return doc, nil
}

func (d *Document) variablesFrom(m map[string]any) {
	if d.Variables == nil {
		d.Variables = map[string]any{}
	}
	maps.Copy(d.Variables, m)
}

// func normalizeToSlice(v any) []any {
//	switch t := v.(type) {
//	case []any:
//		return t
//	default:
//		return []any{v}
//	}
// }

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, it := range t {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

// toServiceNames normalizes the services field into a list of service names.
// Accepts entries like:
// - ["postgres:13", {name: "docker:24.0-dind", alias: "dind"}]
// - {name: "redis:7"}
// - "mysql:8"
func toServiceNames(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, it := range t {
			switch s := it.(type) {
			case string:
				out = append(out, s)
			case map[string]any:
				if name, ok := s["name"].(string); ok {
					out = append(out, name)
					continue
				}
				if img, ok := s["image"].(string); ok {
					out = append(out, img)
				}
			}
		}
		return out
	case map[string]any:
		if name, ok := t["name"].(string); ok {
			return []string{name}
		}
		if img, ok := t["image"].(string); ok {
			return []string{img}
		}
		return nil
	default:
		return nil
	}
}

// parseCacheConfigs normalizes a YAML cache value into a slice of cache config maps.
// GitLab supports cache as a single map or an array of up to 4 maps.
func parseCacheConfigs(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		var out []map[string]any
		for _, it := range t {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

// DebugString returns a summary string for the document.
func (d *Document) DebugString() string {
	def := 0
	if d.Default != nil {
		def = 1
	}
	return fmt.Sprintf("stages=%v jobs=%d includes=%d vars=%d default=%d before=%d after=%d",
		d.Stages, len(d.Jobs), len(d.Includes), len(d.Variables), def, len(d.BeforeScript), len(d.AfterScript))
}

// parseIncludes normalizes the include directive(s) into a slice of Include values.
func parseIncludes(v any) []Include {
	var res []Include
	switch t := v.(type) {
	case []any:
		for _, it := range t {
			if inc := parseIncludeOne(it); inc != nil {
				res = append(res, *inc)
			}
		}
	default:
		if inc := parseIncludeOne(v); inc != nil {
			res = append(res, *inc)
		}
	}
	return res
}

// parseIncludeOne parses a single include entry.
func parseIncludeOne(v any) *Include {
	switch it := v.(type) {
	case string:
		return &Include{Type: IncludeLocal, Local: it}
	case map[string]any:
		inc := &Include{}
		if s, ok := it["local"].(string); ok {
			inc.Type = IncludeLocal
			inc.Local = s
			return inc
		}
		if s, ok := it["remote"].(string); ok {
			inc.Type = IncludeRemote
			inc.Remote = s
			return inc
		}
		if s, ok := it["template"].(string); ok {
			inc.Type = IncludeTemplate
			inc.Template = s
			return inc
		}
		if s, ok := it["component"].(string); ok {
			inc.Type = IncludeComponent
			inc.Component = s
			if inp, ok := it["inputs"].(map[string]any); ok {
				inc.Inputs = inp
			}
			return inc
		}
		if proj, ok := it["project"].(string); ok {
			inc.Type = IncludeProject
			inc.Project = proj
			if f, ok := it["file"]; ok {
				inc.File = toStringSlice(f)
			}
			if ref, ok := it["ref"].(string); ok {
				inc.Ref = ref
			}
			return inc
		}
	}
	return nil
}
