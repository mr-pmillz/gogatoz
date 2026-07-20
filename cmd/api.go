package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	apiListen  string
	apiBaseURL string
	apiKey     string
)

var apiCmd = &cobra.Command{
	Use:   "api-server",
	Short: "Start the GoGatoZ API HTTP server",
	Long:  "Starts an HTTP server exposing GoGatoZ capabilities (enumeration, auth ping, search) for tools/agents via simple JSON endpoints.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := api.Config{
			BaseURL:    strings.TrimSpace(viper.GetString("api-base-url")),
			ListenAddr: strings.TrimSpace(viper.GetString("api-listen")),
			APIKey:     strings.TrimSpace(viper.GetString("api-key")),
		}
		if cfg.ListenAddr == "" {
			cfg.ListenAddr = "127.0.0.1:8088"
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = strings.TrimSpace(viper.GetString("gitlab-url"))
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://gitlab.com"
		}
		if err := validateAPIListenSecurity(cfg.ListenAddr, cfg.APIKey); err != nil {
			return err
		}
		srv := api.NewServer(cfg)
		authMsg := "disabled"
		if cfg.APIKey != "" {
			authMsg = "enabled (X-API-Key)"
		}
		slog.Info("starting API server", "listen", cfg.ListenAddr, "base", cfg.BaseURL, "auth", authMsg)
		return srv.Run()
	},
}

func validateAPIListenSecurity(listenAddr, key string) error {
	if strings.TrimSpace(key) != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return fmt.Errorf("invalid API listen address: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing unauthenticated API listener on non-loopback address %q; configure --api-key", listenAddr)
}

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().StringVar(&apiListen, "listen", "127.0.0.1:8088", "Listen address for API server (host:port)")
	apiCmd.Flags().StringVar(&apiBaseURL, "base-url", "", "Default GitLab base URL for API requests (overridden by per-request)")
	apiCmd.Flags().StringVar(&apiKey, "api-key", "", "API key required for all non-healthz requests (X-API-Key header)")
	_ = viper.BindPFlag("api-listen", apiCmd.Flags().Lookup("listen"))
	_ = viper.BindPFlag("api-base-url", apiCmd.Flags().Lookup("base-url"))
	_ = viper.BindPFlag("api-key", apiCmd.Flags().Lookup("api-key"))
	_ = viper.BindEnv("api-listen", "GOGATOZ_API_LISTEN")
	_ = viper.BindEnv("api-base-url", "GOGATOZ_API_BASE_URL")
	_ = viper.BindEnv("api-key", "GOGATOZ_API_KEY")
}
