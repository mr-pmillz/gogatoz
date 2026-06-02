package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	gitlabURL  string
	token      string
	outputJSON bool
	verbose    bool
	cfgFile    string

	// version, commit, and date are injected at release time via -ldflags by
	// goreleaser (see .goreleaser.yaml). The defaults below apply to local
	// `go build`; `go install ...@vX.Y.Z` recovers the version from the
	// embedded module build info (see versionString).
	version = "dev"
	commit  = "none"
	date    = "unknown"

	// Rate limiting and retry controls
	rateRPS   float64
	rateBurst int
	retryMax  int
	userAgent string

	// HTTP connection pooling and timeouts (configurable)
	httpMaxIdle        int
	httpMaxIdlePerHost int
	httpIdleTimeout    string
	httpTLSTimeout     string
	httpExpectTimeout  string
	httpRequestTimeout string

	// TLS options for self-hosted/internal GitLab
	insecureSkipTLS bool
	caCertPath      string

	// SOCKS5 proxy
	socks5Proxy string
	socks5User  string
	socks5Pass  string

	// Unauthenticated access
	noToken bool

	// Result persistence
	dbPath   string
	noDB     bool
	cliStore *store.Store
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gogatoz",
	Short: "GitLab CI/CD security scanner and attack toolkit (Go port of Gato-X)",
	Long:  "GoGatoZ scans GitLab projects for CI/CD vulnerabilities and can enumerate and attack misconfigurations.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize configuration before every command (except trivial ones)
		if err := initConfig(); err != nil {
			return err
		}
		// Allow subcommands to run without token for help etc.
		if cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "version" {
			return nil
		}
		// After config is loaded and flags/env are bound, read effective values
		gitlabURL = viper.GetString("gitlab-url")
		token = viper.GetString("token")
		outputJSON = viper.GetBool("json")
		verbose = viper.GetBool("verbose")
		rateRPS = viper.GetFloat64("rate-rps")
		rateBurst = viper.GetInt("rate-burst")
		retryMax = viper.GetInt("retry-max")
		userAgent = viper.GetString("user-agent")
		// HTTP pool/timeouts
		httpMaxIdle = viper.GetInt("http-max-idle")
		httpMaxIdlePerHost = viper.GetInt("http-max-idle-per-host")
		httpIdleTimeout = viper.GetString("http-idle-timeout")
		httpTLSTimeout = viper.GetString("http-tls-timeout")
		httpExpectTimeout = viper.GetString("http-expect-timeout")
		httpRequestTimeout = viper.GetString("http-req-timeout")
		// TLS options
		insecureSkipTLS = viper.GetBool("insecure-skip-tls-verify")
		caCertPath = viper.GetString("ca-cert")
		noToken = viper.GetBool("no-token")
		// SOCKS5 proxy
		socks5Proxy = viper.GetString("socks5-proxy")
		socks5User = viper.GetString("socks5-user")
		socks5Pass = viper.GetString("socks5-pass")

		// Open result store (non-fatal)
		if !noDB {
			dbPath = strings.TrimSpace(viper.GetString("db"))
			if dbPath == "" {
				dbPath = defaultDBPath()
			}
			if dbPath != "" {
				if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
					fmt.Fprintf(os.Stderr, "[db] warning: cannot create directory: %v\n", err)
				} else {
					st, stErr := store.Open(dbPath)
					if stErr != nil {
						fmt.Fprintf(os.Stderr, "[db] warning: %v\n", stErr)
					} else {
						cliStore = st
					}
				}
			}
		}
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if cliStore != nil {
			return cliStore.Close()
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, err = fmt.Fprintln(os.Stderr, err)
		if err != nil {
			return
		}
		os.Exit(1)
	}
}

// RootCmd exposes the root command for tooling (e.g., docs generation).
func RootCmd() *cobra.Command { return rootCmd }

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&gitlabURL, "gitlab-url", "https://gitlab.com", "Base URL of GitLab instance")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "GitLab Personal Access Token (or set GITLAB_TOKEN)")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output JSON instead of text")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", envOr("GOGATOZ_CONFIG", ""), "Path to config file (YAML/TOML/JSON). If not set, tries ./.gogatoz.yaml if present.")
	// Reliability flags
	rootCmd.PersistentFlags().Float64Var(&rateRPS, "rate-rps", 8, "Max requests per second to GitLab API (token bucket)")
	rootCmd.PersistentFlags().IntVar(&rateBurst, "rate-burst", 16, "Burst size for rate limiter tokens")
	rootCmd.PersistentFlags().IntVar(&retryMax, "retry-max", 3, "Max retry attempts on 429/5xx responses (1 disables retries)")
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "", "Custom User-Agent header (optional)")
	// HTTP pooling/timeouts
	rootCmd.PersistentFlags().IntVar(&httpMaxIdle, "http-max-idle", 0, "HTTP transport: MaxIdleConns (0=default)")
	rootCmd.PersistentFlags().IntVar(&httpMaxIdlePerHost, "http-max-idle-per-host", 0, "HTTP transport: MaxIdleConnsPerHost (0=default)")
	rootCmd.PersistentFlags().StringVar(&httpIdleTimeout, "http-idle-timeout", "", "HTTP transport: IdleConnTimeout (e.g., 90s)")
	rootCmd.PersistentFlags().StringVar(&httpTLSTimeout, "http-tls-timeout", "", "HTTP transport: TLSHandshakeTimeout (e.g., 10s)")
	rootCmd.PersistentFlags().StringVar(&httpExpectTimeout, "http-expect-timeout", "", "HTTP transport: ExpectContinueTimeout (e.g., 1s)")
	rootCmd.PersistentFlags().StringVar(&httpRequestTimeout, "http-req-timeout", "", "HTTP client: overall request timeout (e.g., 30s)")
	// TLS options
	rootCmd.PersistentFlags().BoolVar(&insecureSkipTLS, "insecure-skip-tls-verify", false, "Skip TLS certificate verification (self-hosted GitLab; use only for testing)")
	rootCmd.PersistentFlags().StringVar(&caCertPath, "ca-cert", "", "Path to PEM file with additional trusted CA certificate(s)")
	// SOCKS5 proxy
	rootCmd.PersistentFlags().StringVar(&socks5Proxy, "socks5-proxy", "", "SOCKS5 proxy address (host:port) for routing all connections")
	rootCmd.PersistentFlags().StringVar(&socks5User, "socks5-user", "", "SOCKS5 proxy username (optional)")
	rootCmd.PersistentFlags().StringVar(&socks5Pass, "socks5-pass", "", "SOCKS5 proxy password (optional)")
	// Unauthenticated access
	rootCmd.PersistentFlags().BoolVar(&noToken, "no-token", false, "Allow unauthenticated API access (for GitLab instances with public API enabled)")
	// Result persistence
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "SQLite database path for result persistence (env: GOGATOZ_DB)")
	rootCmd.PersistentFlags().BoolVar(&noDB, "no-db", false, "Disable automatic result persistence")

	// Bind flags and environment to viper keys for precedence: flags > env > config
	_ = viper.BindPFlag("gitlab-url", rootCmd.PersistentFlags().Lookup("gitlab-url"))
	_ = viper.BindPFlag("token", rootCmd.PersistentFlags().Lookup("token"))
	_ = viper.BindPFlag("json", rootCmd.PersistentFlags().Lookup("json"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("rate-rps", rootCmd.PersistentFlags().Lookup("rate-rps"))
	_ = viper.BindPFlag("rate-burst", rootCmd.PersistentFlags().Lookup("rate-burst"))
	_ = viper.BindPFlag("retry-max", rootCmd.PersistentFlags().Lookup("retry-max"))
	_ = viper.BindPFlag("user-agent", rootCmd.PersistentFlags().Lookup("user-agent"))
	_ = viper.BindPFlag("http-max-idle", rootCmd.PersistentFlags().Lookup("http-max-idle"))
	_ = viper.BindPFlag("http-max-idle-per-host", rootCmd.PersistentFlags().Lookup("http-max-idle-per-host"))
	_ = viper.BindPFlag("http-idle-timeout", rootCmd.PersistentFlags().Lookup("http-idle-timeout"))
	_ = viper.BindPFlag("http-tls-timeout", rootCmd.PersistentFlags().Lookup("http-tls-timeout"))
	_ = viper.BindPFlag("http-expect-timeout", rootCmd.PersistentFlags().Lookup("http-expect-timeout"))
	_ = viper.BindPFlag("http-req-timeout", rootCmd.PersistentFlags().Lookup("http-req-timeout"))
	_ = viper.BindPFlag("insecure-skip-tls-verify", rootCmd.PersistentFlags().Lookup("insecure-skip-tls-verify"))
	_ = viper.BindPFlag("ca-cert", rootCmd.PersistentFlags().Lookup("ca-cert"))
	_ = viper.BindPFlag("no-token", rootCmd.PersistentFlags().Lookup("no-token"))
	_ = viper.BindPFlag("db", rootCmd.PersistentFlags().Lookup("db"))
	_ = viper.BindPFlag("socks5-proxy", rootCmd.PersistentFlags().Lookup("socks5-proxy"))
	_ = viper.BindPFlag("socks5-user", rootCmd.PersistentFlags().Lookup("socks5-user"))
	_ = viper.BindPFlag("socks5-pass", rootCmd.PersistentFlags().Lookup("socks5-pass"))
	// Environment bindings for global keys
	_ = viper.BindEnv("gitlab-url", "GITLAB_URL")
	_ = viper.BindEnv("token", "GITLAB_TOKEN")
	_ = viper.BindEnv("config", "GOGATOZ_CONFIG")
	_ = viper.BindEnv("rate-rps", "GOGATOZ_RATE_RPS")
	_ = viper.BindEnv("rate-burst", "GOGATOZ_RATE_BURST")
	_ = viper.BindEnv("retry-max", "GOGATOZ_RETRY_MAX")
	_ = viper.BindEnv("user-agent", "GOGATOZ_USER_AGENT")
	_ = viper.BindEnv("http-max-idle", "GOGATOZ_HTTP_MAX_IDLE")
	_ = viper.BindEnv("http-max-idle-per-host", "GOGATOZ_HTTP_MAX_IDLE_PER_HOST")
	_ = viper.BindEnv("http-idle-timeout", "GOGATOZ_HTTP_IDLE_TIMEOUT")
	_ = viper.BindEnv("http-tls-timeout", "GOGATOZ_HTTP_TLS_TIMEOUT")
	_ = viper.BindEnv("http-expect-timeout", "GOGATOZ_HTTP_EXPECT_TIMEOUT")
	_ = viper.BindEnv("http-req-timeout", "GOGATOZ_HTTP_REQ_TIMEOUT")
	_ = viper.BindEnv("insecure-skip-tls-verify", "GOGATOZ_INSECURE")
	_ = viper.BindEnv("ca-cert", "GOGATOZ_CA_CERT")
	_ = viper.BindEnv("no-token", "GOGATOZ_NO_TOKEN")
	_ = viper.BindEnv("db", "GOGATOZ_DB")
	_ = viper.BindEnv("socks5-proxy", "GOGATOZ_SOCKS5_PROXY")
	_ = viper.BindEnv("socks5-user", "GOGATOZ_SOCKS5_USER")
	_ = viper.BindEnv("socks5-pass", "GOGATOZ_SOCKS5_PASS")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Version subcommand
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), versionString())
		},
	})
}

// versionString renders the build version, commit, and date. When the binary
// is built without -ldflags (e.g. `go install github.com/mr-pmillz/gogatoz@vX.Y.Z`),
// it falls back to the module version the Go toolchain embeds in the binary.
func versionString() string {
	v := version
	if v == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if mv := info.Main.Version; mv != "" && mv != "(devel)" {
				v = mv
			}
		}
	}
	return fmt.Sprintf("gogatoz %s\n  commit: %s\n  built:  %s", v, commit, date)
}

func initConfig() error {
	// Determine config file to read
	file := viper.GetString("config")
	if file == "" {
		// Use ./.gogatoz.yaml if present
		if _, err := os.Stat(".gogatoz.yaml"); err == nil {
			file = ".gogatoz.yaml"
		}
	}
	if file != "" {
		viper.SetConfigFile(file)
	} else {
		return nil // no config, nothing to do
	}
	if err := viper.ReadInConfig(); err != nil {
		// If file not found, ignore; otherwise return error
		if !os.IsNotExist(err) {
			return fmt.Errorf("read config: %w", err)
		}
	}
	// Normalize relative paths if needed (future use)
	_ = filepath.Base(viper.ConfigFileUsed())
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
