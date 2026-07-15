package pivot

import (
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

const (
	// DefaultListenAddr is the default callback server listen address.
	DefaultListenAddr = ":9443"

	// DefaultReceiveTimeout is the default timeout for waiting for exfil callbacks.
	DefaultReceiveTimeout = 5 * time.Minute

	// maxCallbackBody is the maximum size of a callback HTTP request body (10 MiB).
	maxCallbackBody = 10 << 20
)

// Options configures the pivot orchestrator.
type Options struct {
	// Scope
	InitialTargets []string // project IDs/paths to start from
	GroupTargets   []string // group IDs to expand

	// Limits
	MaxDepth       int           // max pivot depth (default 3)
	MaxTargets     int           // max total projects to attack (default 50)
	MaxCredentials int           // max credentials to harvest (default 20)
	Timeout        time.Duration // overall timeout (default 30m)

	// Concurrency
	EnumConcurrency   int // enumerate workers (default 8)
	AttackConcurrency int // attack workers (default 4)

	// Attack
	AttackBranch string // branch name base (default "gogatoz-pivot")
	Deconflict   string // branch strategy (default "suffix")

	// Callback server
	ListenAddr  string // listen address (default ":9443")
	ExternalURL string // URL reachable from CI runners (required for non-dry-run)

	// RSA
	RSAKeyPath string // existing private key path (optional; generates if empty)
	RSAKeyBits int    // key size (default 2048)

	// Enumerate passthrough
	FollowIncludes bool
	IncludeDepth   int
	FetchRunners   bool
	RunnerScope    string

	// Callback timing
	ReceiveTimeout time.Duration // per-depth callback wait deadline (default 5m)
	AttackDelay    time.Duration // delay between attack launches (default 0, opt-in)

	// Client options (rate limiting, TLS, proxy, etc.) passed to all gitlabx.Client instances
	ClientOptions []gitlabx.Option

	// Control
	DryRun  bool // enumerate + identify only, no attacks
	Cleanup bool // delete attack branches after harvest

	// Progress callback
	Progress func(PivotEvent)
}

// PivotEvent reports orchestrator progress to callers.
type PivotEvent struct {
	Type    string // "depth_start", "enumerate", "attack", "credential", "depth_end", "error"
	Depth   int
	Message string
	Detail  any
}

// defaults fills in zero-value options with sensible defaults.
func (o *Options) defaults() {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 3
	}
	if o.MaxTargets <= 0 {
		o.MaxTargets = 50
	}
	if o.MaxCredentials <= 0 {
		o.MaxCredentials = 20
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Minute
	}
	if o.EnumConcurrency <= 0 {
		o.EnumConcurrency = 8
	}
	if o.AttackConcurrency <= 0 {
		o.AttackConcurrency = 4
	}
	if o.AttackBranch == "" {
		o.AttackBranch = "gogatoz-pivot"
	}
	if o.Deconflict == "" {
		o.Deconflict = "suffix"
	}
	if o.ListenAddr == "" {
		o.ListenAddr = DefaultListenAddr
	}
	if o.ReceiveTimeout <= 0 {
		o.ReceiveTimeout = DefaultReceiveTimeout
	}
	if o.RSAKeyBits <= 0 {
		o.RSAKeyBits = 2048
	}
	if o.IncludeDepth <= 0 {
		o.IncludeDepth = 2
	}
	if o.RunnerScope == "" {
		o.RunnerScope = "project"
	}
}
