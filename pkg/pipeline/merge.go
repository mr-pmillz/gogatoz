package pipeline

// Helpers to implement YAML merge key (<<) semantics and GitLab extends merging for jobs.

import (
	"fmt"
)

// resolveMergesMap applies YAML merge key (<<) semantics to a mapping recursively.
// It supports value being a single map or a list of maps. Later parents override earlier ones,
// and the mapping's own keys override parents. Map values are merged recursively.
//
// This logic is inherently branchy because it normalizes heterogeneous YAML
// node types (map[string]any, map[any]any, []any) and applies merge-key rules
// while preserving GitLab-specific semantics. Splitting further would add churn
// and allocations on hot paths in parsing; keep as one function.
//
//nolint:gocognit
func resolveMergesMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	// First, deep-copy and resolve children
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case map[string]any:
			out[k] = resolveMergesMap(t)
		case map[any]any:
			// normalize to map[string]any where possible
			n := make(map[string]any, len(t))
			for kk, vv := range t {
				n[fmt.Sprint(kk)] = vv
			}
			out[k] = resolveMergesMap(n)
		case []any:
			// resolve merges inside list elements
			arr := make([]any, len(t))
			for i, el := range t {
				if mm, ok := el.(map[string]any); ok {
					arr[i] = resolveMergesMap(mm)
				} else if mm2, ok := el.(map[any]any); ok {
					n := make(map[string]any, len(mm2))
					for kk, vv := range mm2 {
						n[fmt.Sprint(kk)] = vv
					}
					arr[i] = resolveMergesMap(n)
				} else {
					arr[i] = el
				}
			}
			out[k] = arr
		default:
			out[k] = v
		}
	}
	// Apply << merges after children are normalized
	if msrc, ok := out["<<"]; ok {
		merged := map[string]any{}
		switch s := msrc.(type) {
		case map[string]any:
			deepMerge(merged, s)
		case map[any]any:
			n := make(map[string]any, len(s))
			for kk, vv := range s {
				n[fmt.Sprint(kk)] = vv
			}
			deepMerge(merged, n)
		case []any:
			for _, el := range s {
				if mm, ok := el.(map[string]any); ok {
					deepMerge(merged, mm)
				} else if mm2, ok := el.(map[any]any); ok {
					n := make(map[string]any, len(mm2))
					for kk, vv := range mm2 {
						n[fmt.Sprint(kk)] = vv
					}
					deepMerge(merged, n)
				}
			}
		}
		// Now overlay this map (out without <<) onto merged; child's keys win
		delete(out, "<<")
		deepMerge(merged, out)
		out = merged
	}
	return out
}

// deepMerge merges src into dst recursively. For maps, keys in src override dst on conflict.
func deepMerge(dst map[string]any, src map[string]any) {
	if src == nil {
		return
	}
	for k, v := range src {
		if vmap, ok := toStringAnyMap(v); ok {
			if dmap, ok2 := dst[k].(map[string]any); ok2 {
				deepMerge(dmap, vmap)
				continue
			}
			// copy new map
			dst[k] = resolveMergesMap(vmap)
			continue
		}
		// Overwrite scalars/arrays
		dst[k] = v
	}
}

func toStringAnyMap(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case map[any]any:
		n := make(map[string]any, len(t))
		for kk, vv := range t {
			n[fmt.Sprint(kk)] = vv
		}
		return n, true
	default:
		return nil, false
	}
}

// applyExtends resolves job inheritance across job maps and updates doc.Jobs accordingly.
func applyExtends(jobMaps map[string]map[string]any, doc *Document) {
	resolved := map[string]map[string]any{}
	visiting := map[string]bool{}

	var resolve func(name string) map[string]any
	resolve = func(name string) map[string]any {
		if m, ok := resolved[name]; ok {
			return m
		}
		src, ok := jobMaps[name]
		if !ok || src == nil {
			return nil
		}
		if visiting[name] {
			// cycle detected; return source as-is
			return src
		}
		visiting[name] = true
		// Start with empty base aggregated from parents
		base := map[string]any{}
		parents := toStringSlice(src["extends"])
		for _, p := range parents {
			pm := resolve(p)
			if pm == nil {
				continue
			}
			// Ensure parent merges are resolved
			pm = resolveMergesMap(pm)
			// Later parents override earlier ones
			deepMerge(base, pm)
		}
		// Overlay child on top (child wins); also resolve child's own << merges first
		child := resolveMergesMap(src)
		delete(child, "extends")
		deepMerge(base, child)
		resolved[name] = base
		visiting[name] = false
		return base
	}

	// Resolve every job map
	for name := range jobMaps {
		jobMaps[name] = resolve(name)
	}
	// Rebuild doc.Jobs from resolved maps
	for i, j := range doc.Jobs {
		if m, ok := jobMaps[j.Name]; ok && m != nil {
			nj := jobFromMap(j.Name, m)
			// Preserve original Extends list for provenance/testing
			nj.Extends = j.Extends
			doc.Jobs[i] = nj
		}
	}
}

// jobFromMap converts a job mapping into a Job struct.
func jobFromMap(name string, m map[string]any) Job {
	j := Job{Name: name}
	if stg, ok := m["stage"].(string); ok {
		j.Stage = stg
	}
	if sc, ok := m["script"]; ok {
		j.Script = toStringSlice(sc)
	}
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
	if w, ok := m["when"].(string); ok {
		j.When = w
	}
	if af, ok := m["allow_failure"].(bool); ok {
		j.AllowFailure = af
	}
	jobFromMapExtras(&j, m)
	return j
}

func jobFromMapExtras(j *Job, m map[string]any) {
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
	if img, ok := m["image"]; ok {
		if s, ok := img.(string); ok {
			j.Image = s
		} else if mm, ok := img.(map[string]any); ok {
			if name, ok := mm["name"].(string); ok {
				j.Image = name
			}
		}
	}
	if sv, ok := m["services"]; ok {
		j.Services = toServiceNames(sv)
	}
	if art, ok := m["artifacts"].(map[string]any); ok {
		j.Artifacts = art
	}
	if c, ok := m["cache"]; ok {
		j.Caches = parseCacheConfigs(c)
		if len(j.Caches) > 0 {
			j.Cache = j.Caches[0]
		}
	}
}
