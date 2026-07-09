package pipeline

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// ttl cache for remote includes across calls
var (
	remoteCacheMu sync.Mutex
	remoteCache   = map[string]remoteCacheEntry{}
)

type remoteCacheEntry struct {
	doc *Document
	exp time.Time
}

// ResolveOptions control include resolution behavior for non-GitLab (remote) sources.
// Defaults are safe: remote includes disabled unless explicitly allowed.
type ResolveOptions struct {
	AllowRemote      bool          // if true, resolve remote includes
	RemoteAllowHosts []string      // host allowlist (exact match) for remote includes
	RemoteMaxBytes   int64         // max bytes to fetch for a remote include (0 uses default 1MB)
	RemoteTimeout    time.Duration // per-remote fetch timeout (0 uses default 10s)
	RemoteCacheTTL   time.Duration // cross-call TTL cache for remote includes (0 disables cross-call cache)
}

// ResolveIncludes fetches and merges includes into the provided base document up to a given depth.
// Backwards-compatible: resolves local and project includes. Remote/template/component includes are not fetched.
func ResolveIncludes(ctx context.Context, cl *gitlabx.Client, projectID any, ref string, base *Document, depth int) (*Document, error) {
	return ResolveIncludesWithOptions(ctx, cl, projectID, ref, base, depth, ResolveOptions{})
}

// ResolveIncludesWithOptions fetches and merges includes with additional controls for remote includes.
//
//nolint:gocognit
func ResolveIncludesWithOptions(ctx context.Context, cl *gitlabx.Client, projectID any, ref string, base *Document, depth int, ropts ResolveOptions) (*Document, error) {
	if base == nil {
		return nil, errors.New("nil document")
	}
	if depth <= 0 || len(base.Includes) == 0 {
		// Nothing to do
		return base, nil
	}

	visited := map[string]struct{}{}
	cache := map[string]*Document{}
	merged := cloneDocShallow(base)

	var partials []string
	var walkInclude func(ctx context.Context, proj any, ref string, inc Include, depth int) error
	mergeDoc := func(dst *Document, src *Document, origin Include) {
		// Merge stages (unique)
		for _, s := range src.Stages {
			if !contains(dst.Stages, s) {
				dst.Stages = append(dst.Stages, s)
			}
		}
		// Merge variables (dst wins on conflict)
		if src.Variables != nil {
			if dst.Variables == nil {
				dst.Variables = map[string]any{}
			}
			for k, v := range src.Variables {
				if _, exists := dst.Variables[k]; !exists {
					dst.Variables[k] = v
				}
			}
		}
		// Append jobs and record provenance for each job from this include
		if dst.Provenance == nil {
			dst.Provenance = map[string][]Include{}
		}
		for _, j := range src.Jobs {
			dst.Jobs = append(dst.Jobs, j)
			name := strings.TrimSpace(j.Name)
			if name != "" {
				dst.Provenance[name] = append(dst.Provenance[name], origin)
			}
		}
		// Append includes to track provenance
		dst.Includes = append(dst.Includes, src.Includes...)
	}

	isAllowedHost := func(h string) bool {
		if len(ropts.RemoteAllowHosts) == 0 {
			return false
		}
		for _, a := range ropts.RemoteAllowHosts {
			if strings.EqualFold(strings.TrimSpace(a), h) {
				return true
			}
		}
		return false
	}

	remoteMax := ropts.RemoteMaxBytes
	if remoteMax <= 0 {
		remoteMax = 1 << 20
	} // 1 MiB default
	remoteTO := ropts.RemoteTimeout
	if remoteTO <= 0 {
		remoteTO = 10 * time.Second
	}

	walkInclude = func(ctx context.Context, proj any, ref string, inc Include, depth int) error {
		if depth <= 0 {
			return nil
		}
		switch inc.Type {
		case IncludeLocal:
			path := strings.TrimSpace(inc.Local)
			if path == "" {
				return nil
			}
			key := fmt.Sprintf("proj:%v@%s:%s", proj, ref, path)
			if _, ok := visited[key]; ok {
				return nil
			}
			visited[key] = struct{}{}
			file, _, err := cl.GL.RepositoryFiles.GetFile(proj, path, &gitlab.GetFileOptions{Ref: new(ref)}, gitlab.WithContext(ctx))
			if err != nil {
				partials = append(partials, fmt.Sprintf("local include fetch failed: %s (%v)", path, err))
				return nil
			}
			decoded, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				partials = append(partials, fmt.Sprintf("local include decode failed: %s (%v)", path, err))
				return nil
			}
			doc, perr := Parse(strings.NewReader(string(decoded)))
			if perr != nil {
				partials = append(partials, fmt.Sprintf("local include parse failed: %s (%v)", path, perr))
				return nil
			}
			mergeDoc(merged, doc, inc)
			for _, child := range doc.Includes {
				_ = walkInclude(ctx, proj, ref, child, depth-1)
			}
		case IncludeProject:
			projPath := strings.TrimSpace(inc.Project)
			if projPath == "" {
				return nil
			}
			files := inc.File
			if len(files) == 0 {
				files = []string{}
			} // nothing to fetch
			useRef := strings.TrimSpace(inc.Ref)
			var p any = projPath
			// If ref not specified, try default branch; note partial because unpinned
			if useRef == "" {
				projInfo, _, err := cl.GL.Projects.GetProject(projPath, nil, gitlab.WithContext(ctx))
				if err != nil {
					partials = append(partials, fmt.Sprintf("project include get project failed: %s (%v)", projPath, err))
					return nil
				}
				useRef = projInfo.DefaultBranch
				partials = append(partials, fmt.Sprintf("project include unpinned: %s (using ref=%s)", projPath, useRef))
			}
			for _, f := range files {
				f = strings.TrimSpace(f)
				if f == "" {
					continue
				}
				key := fmt.Sprintf("proj:%v@%s:%s", p, useRef, f)
				if _, ok := visited[key]; ok {
					continue
				}
				visited[key] = struct{}{}
				file, _, err := cl.GL.RepositoryFiles.GetFile(p, f, &gitlab.GetFileOptions{Ref: new(useRef)}, gitlab.WithContext(ctx))
				if err != nil {
					partials = append(partials, fmt.Sprintf("project include fetch failed: %s:%s@%s (%v)", projPath, f, useRef, err))
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(file.Content)
				if err != nil {
					partials = append(partials, fmt.Sprintf("project include decode failed: %s:%s (%v)", projPath, f, err))
					continue
				}
				doc, perr := Parse(strings.NewReader(string(decoded)))
				if perr != nil {
					partials = append(partials, fmt.Sprintf("project include parse failed: %s:%s (%v)", projPath, f, perr))
					continue
				}
				mergeDoc(merged, doc, inc)
				for _, child := range doc.Includes {
					_ = walkInclude(ctx, p, useRef, child, depth-1)
				}
			}
		case IncludeRemote:
			if !ropts.AllowRemote {
				partials = append(partials, "remote include not allowed by settings")
				return nil
			}
			raw := strings.TrimSpace(inc.Remote)
			if raw == "" {
				return nil
			}
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
				partials = append(partials, fmt.Sprintf("remote include invalid url: %q", raw))
				return nil
			}
			if !isAllowedHost(strings.ToLower(u.Host)) {
				partials = append(partials, fmt.Sprintf("remote include host not allowed: %s", u.Host))
				return nil
			}
			key := "remote:" + u.String()
			if _, ok := visited[key]; ok {
				return nil
			}
			visited[key] = struct{}{}
			// Check per-call cache first
			if cached, ok := cache[key]; ok {
				mergeDoc(merged, cached, inc)
				for _, child := range cached.Includes {
					_ = walkInclude(ctx, proj, ref, child, depth-1)
				}
				return nil
			}
			// Check cross-call TTL cache if enabled
			if ropts.RemoteCacheTTL > 0 {
				remoteCacheMu.Lock()
				entry, ok := remoteCache[key]
				if ok && time.Now().Before(entry.exp) && entry.doc != nil {
					remoteCacheMu.Unlock()
					cache[key] = entry.doc // populate per-call cache
					mergeDoc(merged, entry.doc, inc)
					for _, child := range entry.doc.Includes {
						_ = walkInclude(ctx, proj, ref, child, depth-1)
					}
					return nil
				}
				remoteCacheMu.Unlock()
			}
			// Fetch with timeout and size cap
			ctxTO, cancel := context.WithTimeout(ctx, remoteTO)
			defer cancel()
			req, err := http.NewRequestWithContext(ctxTO, http.MethodGet, u.String(), nil)
			if err != nil {
				partials = append(partials, fmt.Sprintf("remote include request build failed: %v", err))
				return nil
			}
			hc := http.DefaultClient
			if cl != nil && cl.HTTPClient() != nil {
				hc = cl.HTTPClient()
			}
			resp, err := hc.Do(req) //nolint:gosec
			if err != nil {
				partials = append(partials, fmt.Sprintf("remote include fetch failed: %v", err))
				return nil
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				partials = append(partials, fmt.Sprintf("remote include bad status: %s", resp.Status))
				return nil
			}
			// Size-limited read
			lim := &io.LimitedReader{R: resp.Body, N: remoteMax + 1}
			b, rerr := io.ReadAll(lim)
			if rerr != nil {
				partials = append(partials, fmt.Sprintf("remote include read failed: %v", rerr))
				return nil
			}
			if int64(len(b)) > remoteMax {
				partials = append(partials, fmt.Sprintf("remote include exceeds max bytes (%d)", remoteMax))
				return nil
			}
			doc, perr := Parse(strings.NewReader(string(b)))
			if perr != nil {
				partials = append(partials, fmt.Sprintf("remote include parse failed: %v", perr))
				return nil
			}
			cache[key] = doc
			// store in TTL cache if enabled
			if ropts.RemoteCacheTTL > 0 {
				remoteCacheMu.Lock()
				remoteCache[key] = remoteCacheEntry{doc: doc, exp: time.Now().Add(ropts.RemoteCacheTTL)}
				remoteCacheMu.Unlock()
			}
			mergeDoc(merged, doc, inc)
			for _, child := range doc.Includes {
				_ = walkInclude(ctx, proj, ref, child, depth-1)
			}
		case IncludeTemplate:
			// Resolve official GitLab CI/CD template via GitLab API
			name := strings.TrimSpace(inc.Template)
			if name == "" {
				return nil
			}
			key := "template:" + name
			if _, ok := visited[key]; ok {
				return nil
			}
			visited[key] = struct{}{}
			if cl == nil {
				partials = append(partials, "template include cannot be fetched: missing GitLab client")
				return nil
			}
			content, err := cl.GetCIYMLTemplate(ctx, name)
			if err != nil {
				partials = append(partials, fmt.Sprintf("template include fetch failed: %s (%v)", name, err))
				return nil
			}
			doc, perr := Parse(strings.NewReader(content))
			if perr != nil {
				partials = append(partials, fmt.Sprintf("template include parse failed: %s (%v)", name, perr))
				return nil
			}
			mergeDoc(merged, doc, inc)
			for _, child := range doc.Includes {
				_ = walkInclude(ctx, proj, ref, child, depth-1)
			}
			return nil
		case IncludeComponent:
			// Resolve CI/CD component via GitLab GraphQL helper when available.
			if cl == nil {
				partials = append(partials, "component include cannot be fetched: missing GitLab client")
				return nil
			}
			id := strings.TrimSpace(inc.Component)
			if id == "" {
				return nil
			}
			key := "component:" + id
			if inc.Ref != "" {
				key += "@" + inc.Ref
			}
			if _, ok := visited[key]; ok {
				return nil
			}
			visited[key] = struct{}{}
			content, err := cl.GetComponentYAML(ctx, id, inc.Ref)
			if err != nil {
				partials = append(partials, fmt.Sprintf("component include fetch failed: %s (%v)", id, err))
				return nil
			}
			// Guardrail: size cap (reuse remoteMax default/setting)
			if int64(len(content)) > remoteMax {
				partials = append(partials, fmt.Sprintf("component include exceeds max bytes (%d)", remoteMax))
				return nil
			}
			// Perform naive variable substitution using provided inputs: ${key}
			if len(inc.Inputs) > 0 {
				content = applyInputsSubstitution(content, inc.Inputs)
			}
			doc, perr := Parse(strings.NewReader(content))
			if perr != nil {
				partials = append(partials, fmt.Sprintf("component include parse failed: %s (%v)", id, perr))
				return nil
			}
			mergeDoc(merged, doc, inc)
			for _, child := range doc.Includes {
				_ = walkInclude(ctx, proj, ref, child, depth-1)
			}
			return nil
		default:
			return nil
		}
		return nil
	}

	for _, inc := range base.Includes {
		_ = walkInclude(ctx, projectID, ref, inc, depth)
	}

	if len(partials) > 0 {
		return merged, fmt.Errorf("partial include resolution: %s", strings.Join(partials, "; "))
	}
	return merged, nil
}

func cloneDocShallow(src *Document) *Document {
	if src == nil {
		return nil
	}
	d := &Document{
		Raw:        src.Raw,
		Stages:     append([]string{}, src.Stages...),
		Variables:  map[string]any{},
		Includes:   append([]Include{}, src.Includes...),
		Workflow:   src.Workflow,
		Jobs:       append([]Job{}, src.Jobs...),
		Provenance: map[string][]Include{},
	}
	maps.Copy(d.Variables, src.Variables)
	// copy provenance if any
	if src.Provenance != nil {
		for job, incs := range src.Provenance {
			d.Provenance[job] = append([]Include{}, incs...)
		}
	}
	return d
}

func contains(arr []string, s string) bool {
	return slices.Contains(arr, s)
}

// applyInputsSubstitution performs a naive ${key} -> value substitution over the YAML content
// for component includes with provided inputs. Values are stringified with fmt.Sprint.
func applyInputsSubstitution(content string, inputs map[string]any) string {
	if len(inputs) == 0 {
		return content
	}
	out := content
	for k, v := range inputs {
		needle := "${" + k + "}"
		out = strings.ReplaceAll(out, needle, fmt.Sprint(v))
	}
	return out
}
