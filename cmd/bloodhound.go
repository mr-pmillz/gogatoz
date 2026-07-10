package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/bloodhound"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	bhURL      string
	bhTokenID  string
	bhTokenKey string
)

var bloodhoundCmd = &cobra.Command{
	Use:     "bloodhound",
	Aliases: []string{"bh"},
	Short:   "BloodHound-CE integration — export, upload, and query CI/CD attack surface graphs",
	Long: `Export GoGatoZ scan data as BloodHound-CE OpenGraph format, upload to a
BloodHound-CE instance, or install pre-built Cypher attack path queries.

Examples:
  # Export from database to ZIP
  gogatoz bloodhound export --session 1 --output attack-surface.zip

  # Export from JSONL file
  gogatoz bloodhound export --input results.jsonl --output attack-surface.zip

  # Upload schema + data to BloodHound-CE
  gogatoz bloodhound upload --session 1

  # Install saved Cypher queries
  gogatoz bloodhound queries`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		bhURL = viper.GetString("bh-url")
		bhTokenID = viper.GetString("bh-token-id")
		bhTokenKey = viper.GetString("bh-token-key")

		if !noDB {
			dbPath = strings.TrimSpace(viper.GetString("db"))
			if dbPath == "" {
				dbPath = defaultDBPath()
			}
			if dbPath != "" {
				st, err := store.Open(dbPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[db] warning: %v\n", err)
				} else {
					cliStore = st
				}
			}
		}
		return nil
	},
}

// --- export subcommand ---

var (
	bhExportSession uint
	bhExportInput   string
	bhExportOutput  string
)

var bhExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan data to a BloodHound-CE OpenGraph ZIP file",
	RunE: func(cmd *cobra.Command, args []string) error {
		output := strings.TrimSpace(bhExportOutput)
		if output == "" {
			output = fmt.Sprintf("gogatoz-bloodhound-%d.zip", time.Now().Unix())
		}

		b, err := buildGraphFromInputs(bhExportSession, bhExportInput)
		if err != nil {
			return err
		}

		if err := bloodhound.Export(b, output); err != nil {
			return fmt.Errorf("export: %w", err)
		}

		nodes := b.Nodes()
		edges := b.Edges()
		fmt.Fprintf(cmd.OutOrStdout(), "Exported %d nodes, %d edges to %s\n", len(nodes), len(edges), output)
		return nil
	},
}

// --- upload subcommand ---

var bhUploadSession uint
var bhUploadInput   string

var bhUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload scan data to a BloodHound-CE instance",
	RunE: func(cmd *cobra.Command, args []string) error {
		if bhURL == "" {
			return fmt.Errorf("--url is required (or set GOGATOZ_BH_URL)")
		}
		auth, err := bhAuth()
		if err != nil {
			return err
		}

		b, err := buildGraphFromInputs(bhUploadSession, bhUploadInput)
		if err != nil {
			return err
		}

		tmpFile, err := os.CreateTemp("", "gogatoz-bh-*.zip")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)

		if err := bloodhound.Export(b, tmpPath); err != nil {
			return fmt.Errorf("export: %w", err)
		}

		ctx := context.Background()
		client := bloodhound.NewClient(bhURL, auth)

		fmt.Fprintln(cmd.OutOrStdout(), "Uploading schema...")
		if err := client.UploadSchema(ctx); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: schema upload failed (data upload may still work): %v\n", err)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Schema uploaded (or extensions endpoint not available — generic graph mode).")
		}

		nodes := b.Nodes()
		edges := b.Edges()
		fmt.Fprintf(cmd.OutOrStdout(), "Uploading data (%d nodes, %d edges)...\n", len(nodes), len(edges))
		if err := client.UploadData(ctx, tmpPath); err != nil {
			return fmt.Errorf("upload data: %w", err)
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Upload complete.")
		return nil
	},
}

// --- queries subcommand ---

var bhQueriesCmd = &cobra.Command{
	Use:   "queries",
	Short: "Install pre-built CI/CD attack path Cypher queries in BloodHound-CE",
	RunE: func(cmd *cobra.Command, args []string) error {
		if bhURL == "" {
			return fmt.Errorf("--url is required (or set GOGATOZ_BH_URL)")
		}
		auth, err := bhAuth()
		if err != nil {
			return err
		}

		ctx := context.Background()
		client := bloodhound.NewClient(bhURL, auth)
		queries := bloodhound.AttackPathQueries()

		for _, q := range queries {
			fmt.Fprintf(cmd.OutOrStdout(), "Installing query: %s\n", q.Name)
			if err := client.CreateSavedQuery(ctx, q); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: %v\n", err)
			}
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Installed %d saved queries.\n", len(queries))
		return nil
	},
}

// --- schema subcommand ---

var bhSchemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Upload the CICD extension schema to BloodHound-CE",
	RunE: func(cmd *cobra.Command, args []string) error {
		if bhURL == "" {
			return fmt.Errorf("--url is required (or set GOGATOZ_BH_URL)")
		}
		auth, err := bhAuth()
		if err != nil {
			return err
		}

		ctx := context.Background()
		client := bloodhound.NewClient(bhURL, auth)

		fmt.Fprintln(cmd.OutOrStdout(), "Uploading schema...")
		if err := client.UploadSchema(ctx); err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Schema uploaded successfully (or extensions endpoint unavailable — generic graph mode).")
		return nil
	},
}

// --- helpers ---

func bhAuth() (bloodhound.Authenticator, error) {
	if bhTokenID != "" && bhTokenKey != "" {
		return &bloodhound.HMACAuth{TokenID: bhTokenID, TokenKey: bhTokenKey}, nil
	}
	if bhTokenID != "" {
		return &bloodhound.BearerAuth{Token: bhTokenID}, nil
	}
	return nil, fmt.Errorf("BloodHound credentials required: set --token-id/--token-key or GOGATOZ_BH_TOKEN_ID/GOGATOZ_BH_TOKEN_KEY")
}

func buildGraphFromInputs(sessionID uint, inputPath string) (*bloodhound.Builder, error) {
	glURL := strings.TrimSpace(viper.GetString("gitlab-url"))
	if glURL == "" {
		glURL = "https://gitlab.com"
	}
	b := bloodhound.NewBuilder(glURL)

	switch {
	case sessionID > 0:
		return buildFromDB(b, sessionID)
	case strings.TrimSpace(inputPath) != "":
		return buildFromFile(b, inputPath)
	default:
		defDB := defaultDBPath()
		if defDB != "" {
			if _, err := os.Stat(defDB); err == nil {
				if cliStore == nil {
					st, err := store.Open(defDB)
					if err != nil {
						return nil, err
					}
					cliStore = st
				}
				sessions, err := cliStore.ListSessions(1)
				if err != nil || len(sessions) == 0 {
					return nil, fmt.Errorf("no sessions found in default database")
				}
				return buildFromDB(b, sessions[0].ID)
			}
		}
		return nil, fmt.Errorf("specify --session or --input")
	}
}

func buildFromDB(b *bloodhound.Builder, sessionID uint) (*bloodhound.Builder, error) {
	if cliStore == nil {
		return nil, fmt.Errorf("database not available")
	}

	sess, err := cliStore.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session %d: %w", sessionID, err)
	}

	if len(sess.EnumerateResults) > 0 {
		results := storeToResults(sess.EnumerateResults)
		b.AddEnumerateResults(results)
	}

	if len(sess.SearchResults) > 0 {
		searchMaps := make([]map[string]any, len(sess.SearchResults))
		for i, sr := range sess.SearchResults {
			searchMaps[i] = map[string]any{
				"id":                  sr.GitLabProjectID,
				"path_with_namespace": sr.PathWithNamespace,
				"web_url":             sr.WebURL,
				"visibility":          sr.Visibility,
				"default_branch":      sr.DefaultBranch,
				"star_count":          sr.StarCount,
			}
		}
		b.AddSearchResults(searchMaps)
	}

	if len(sess.AttackResults) > 0 {
		b.AddAttackResults(storeToAttackViews(sess.AttackResults))
	}

	creds, _ := cliStore.GetAllHarvestedCredentials()
	secrets, _ := cliStore.GetAllExfiltratedSecrets()
	if len(creds) > 0 || len(secrets) > 0 {
		b.AddPivotData(creds, secrets)
	}

	b.BuildTransitiveDependencies()
	b.BuildSharedRunnerEdges()

	persistGraphToDB(b, sessionID)

	return b, nil
}

func buildFromFile(b *bloodhound.Builder, path string) (*bloodhound.Builder, error) {
	results, err := loadFromFile(path)
	if err != nil {
		return nil, err
	}
	b.AddEnumerateResults(results)
	b.BuildTransitiveDependencies()
	b.BuildSharedRunnerEdges()
	return b, nil
}

func persistGraphToDB(b *bloodhound.Builder, sessionID uint) {
	if cliStore == nil {
		return
	}

	nodes := b.Nodes()
	gn := make([]store.GraphNode, len(nodes))
	for i, n := range nodes {
		props, _ := json.Marshal(n.Properties)
		kind := ""
		if len(n.Kinds) > 0 {
			kind = n.Kinds[0]
		}
		gn[i] = store.GraphNode{
			NodeID:     n.ID,
			Kind:       kind,
			Properties: string(props),
		}
	}
	if err := cliStore.SaveGraphNodes(sessionID, gn); err != nil {
		fmt.Fprintf(os.Stderr, "[db] warning: save graph nodes: %v\n", err)
	}

	edges := b.Edges()
	ge := make([]store.GraphEdge, len(edges))
	for i, e := range edges {
		props, _ := json.Marshal(e.Properties)
		ge[i] = store.GraphEdge{
			StartID:    e.Start.Value,
			EndID:      e.End.Value,
			Kind:       e.Kind,
			Properties: string(props),
		}
	}
	if err := cliStore.SaveGraphEdges(sessionID, ge); err != nil {
		fmt.Fprintf(os.Stderr, "[db] warning: save graph edges: %v\n", err)
	}
}

func init() {
	rootCmd.AddCommand(bloodhoundCmd)

	// Persistent flags for all bloodhound subcommands
	bloodhoundCmd.PersistentFlags().StringVar(&bhURL, "url", "", "BloodHound-CE instance URL (env: GOGATOZ_BH_URL)")
	bloodhoundCmd.PersistentFlags().StringVar(&bhTokenID, "token-id", "", "BloodHound-CE API token ID (env: GOGATOZ_BH_TOKEN_ID)")
	bloodhoundCmd.PersistentFlags().StringVar(&bhTokenKey, "token-key", "", "BloodHound-CE API token key (env: GOGATOZ_BH_TOKEN_KEY)")
	_ = viper.BindEnv("bh-url", "GOGATOZ_BH_URL")
	_ = viper.BindEnv("bh-token-id", "GOGATOZ_BH_TOKEN_ID")
	_ = viper.BindEnv("bh-token-key", "GOGATOZ_BH_TOKEN_KEY")

	// Export subcommand
	bhExportCmd.Flags().UintVar(&bhExportSession, "session", 0, "Session ID to export from database")
	bhExportCmd.Flags().StringVarP(&bhExportInput, "input", "i", "", "Path to JSONL or JSON file with enumerate results")
	bhExportCmd.Flags().StringVarP(&bhExportOutput, "output", "o", "", "Output ZIP file path")
	bloodhoundCmd.AddCommand(bhExportCmd)

	// Upload subcommand
	bhUploadCmd.Flags().UintVar(&bhUploadSession, "session", 0, "Session ID to upload from database")
	bhUploadCmd.Flags().StringVarP(&bhUploadInput, "input", "i", "", "Path to JSONL or JSON file with enumerate results")
	bloodhoundCmd.AddCommand(bhUploadCmd)

	// Queries subcommand
	bloodhoundCmd.AddCommand(bhQueriesCmd)

	// Schema subcommand
	bloodhoundCmd.AddCommand(bhSchemaCmd)
}
