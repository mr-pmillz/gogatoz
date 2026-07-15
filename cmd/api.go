package cmd

import (
	"log/slog"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	apiListen  string
	apiBaseURL string
)

var apiCmd = &cobra.Command{
	Use:   "api-server",
	Short: "Start the GoGatoZ API HTTP server",
	Long:  "Starts an HTTP server exposing GoGatoZ capabilities (enumeration, auth ping, search) for tools/agents via simple JSON endpoints.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := api.Config{
			BaseURL:    strings.TrimSpace(viper.GetString("api-base-url")),
			ListenAddr: strings.TrimSpace(viper.GetString("api-listen")),
		}
		if cfg.ListenAddr == "" {
			cfg.ListenAddr = ":8088"
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = strings.TrimSpace(viper.GetString("gitlab-url"))
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://gitlab.com"
		}
		srv := api.NewServer(cfg)
		slog.Info("starting API server", "listen", cfg.ListenAddr, "base", cfg.BaseURL)
		return srv.Run()
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().StringVar(&apiListen, "listen", ":8088", "Listen address for API server (host:port)")
	apiCmd.Flags().StringVar(&apiBaseURL, "base-url", "", "Default GitLab base URL for API requests (overridden by per-request)")
	_ = viper.BindPFlag("api-listen", apiCmd.Flags().Lookup("listen"))
	_ = viper.BindPFlag("api-base-url", apiCmd.Flags().Lookup("base-url"))
	_ = viper.BindEnv("api-listen", "GOGATOZ_API_LISTEN")
	_ = viper.BindEnv("api-base-url", "GOGATOZ_API_BASE_URL")
}
