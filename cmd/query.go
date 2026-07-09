package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var (
	queryDBPath   string
	queryFormat   string
	querySession  uint
	queryLimit    int
	queryRedacted bool
)

var queryCmd = &cobra.Command{
	Use:   "query [subcommand]",
	Short: "Query the local SQLite database for scan results, findings, and attack data",
	Long: `Query and display stored scan results, findings, attack data, and harvested credentials.

Examples:
  # List all sessions
  gogatoz query sessions

  # List all projects scanned
  gogatoz query projects

  # Show findings for a session
  gogatoz query findings --session 1

  # Show attack results
  gogatoz query attacks

  # Show harvested secrets
  gogatoz query secrets

  # Show pivoted credentials
  gogatoz query credentials

  # Show exfiltrated secrets from callbacks
  gogatoz query exfil

  # JSON output
  gogatoz query sessions --format json
  gogatoz query projects --db /path/to/results.db
`,
}

// sessionListCmd - list all scan sessions
var sessionListCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List all scan sessions",
	Long:  "Display all stored scan sessions with summary statistics.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listSessions(queryFormat)
	},
}

// projectListCmd - list scanned projects
var projectListCmd = &cobra.Command{
	Use:   "projects",
	Short: "List scanned projects",
	Long:  "Display all projects that have been scanned.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listProjects(queryFormat, querySession)
	},
}

// findingsCmd - show findings
var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Show scan findings",
	Long:  "Display vulnerability findings from enumerate scans.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listFindings(queryFormat, querySession)
	},
}

// attacksCmd - show attack results
var attacksCmd = &cobra.Command{
	Use:   "attacks",
	Short: "Show attack results",
	Long:  "Display attack operations and their outcomes.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listAttacks(queryFormat, querySession)
	},
}

// secretsCmd - show exfiltrated secrets from attacks
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Show exfiltrated secrets from attack operations",
	Long:  "Display secrets extracted from CI/CD via attack operations (artifact downloads).",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listExfilSecrets(queryFormat)
	},
}

// credentialsCmd - show pivoted credentials
var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Show harvested credentials from pivot operations",
	Long:  "Display tokens harvested during pivot operations (shows hashes, not raw tokens).",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listCredentials(queryFormat)
	},
}

// exfilCmd - show exfiltrated secrets from listener callbacks
var exfilCmd = &cobra.Command{
	Use:   "exfil",
	Short: "Show exfiltrated secrets from ror-listen callbacks",
	Long:  "Display secrets received via ror-listen HTTP callbacks (not artifact-based).",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listExfilCallbacks(queryFormat)
	},
}

// redactValue masks a secret value when redaction is requested.
// Shows only the last 4 chars for values longer than 8 chars; fully masks shorter values.
func redactValue(v string, redact bool) string {
	if !redact {
		return v
	}
	if len(v) <= 8 {
		return "****"
	}
	return "****" + v[len(v)-4:]
}

func init() {
	rootCmd.AddCommand(queryCmd)
	queryCmd.AddCommand(sessionListCmd, projectListCmd, findingsCmd, attacksCmd, secretsCmd, credentialsCmd, exfilCmd)

	// Common flags
	for _, c := range []*cobra.Command{sessionListCmd, projectListCmd, findingsCmd, attacksCmd, secretsCmd, credentialsCmd, exfilCmd} {
		c.Flags().StringVar(&queryDBPath, "db", "", "SQLite database path (default: ~/.local/share/gogatoz/results.db)")
		c.Flags().StringVar(&queryFormat, "format", "text", "Output format: text|json")
		c.Flags().BoolVar(&queryRedacted, "redacted", false, "Redact (mask) secret values; unredacted by default")
	}

	// Limit flag only on sessions (the only subcommand that supports it)
	sessionListCmd.Flags().IntVar(&queryLimit, "limit", 0, "Limit number of results (0 = no limit)")

	// Session-specific flags
	findingsCmd.Flags().UintVar(&querySession, "session", 0, "Filter by session ID")
	projectListCmd.Flags().UintVar(&querySession, "session", 0, "Filter by session ID")
	attacksCmd.Flags().UintVar(&querySession, "session", 0, "Filter by session ID")
}

func getDB() (*store.Store, error) {
	dbPath := strings.TrimSpace(queryDBPath)
	if dbPath == "" {
		dbPath = defaultDBPath()
	}
	if dbPath == "" {
		return nil, fmt.Errorf("no database specified; use --db flag or set GOGATOZ_DB")
	}
	return store.Open(dbPath)
}

// ---- sessions ----

func listSessions(format string) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	sessions, err := st.ListSessions(queryLimit)
	if err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println("No sessions found.")
		return nil
	}

	if format == "json" {
		out, _ := json.MarshalIndent(sessions, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	data := pterm.TableData{{"ID", "GitLab URL", "Started", "Status", "Search", "Enum", "Findings", "Attack"}}
	for _, s := range sessions {
		data = append(data, []string{
			fmt.Sprintf("%d", s.ID),
			s.GitLabURL,
			s.StartedAt.Format("2006-01-02"),
			s.Status,
			fmt.Sprintf("%d", s.SearchTotal),
			fmt.Sprintf("%d", s.EnumTotal),
			fmt.Sprintf("%d", s.EnumFindings),
			fmt.Sprintf("%d/%d", s.AttackSuccess, s.AttackTotal),
		})
	}
	return renderTable(os.Stdout, data)
}

// ---- projects ----

func listProjects(format string, sessionID uint) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	var results []store.EnumerateResult
	if sessionID > 0 {
		results, err = st.GetEnumerateResultsBySession(sessionID)
	} else {
		results, err = st.GetAllEnumerateResults()
	}
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No projects found.")
		return nil
	}

	if format == "json" {
		type projView struct {
			ID              int64  `json:"id"`
			PathWithNS      string `json:"path_with_namespace"`
			WebURL          string `json:"web_url"`
			FindingsCount   int    `json:"findings_count"`
			HasPipeline     bool   `json:"has_ci_pipeline"`
			RunnersTotal    int    `json:"runners_total"`
			RunnersOnline   int    `json:"runners_online"`
			ProtectedBranch string `json:"protected_branches"`
		}
		view := make([]projView, len(results))
		for i, r := range results {
			view[i] = projView{
				ID:              r.GitLabProjectID,
				PathWithNS:      r.PathWithNamespace,
				WebURL:          r.WebURL,
				FindingsCount:   r.FindingsCount,
				HasPipeline:     r.HasCIPipeline,
				RunnersTotal:    r.RunnersTotal,
				RunnersOnline:   r.RunnersOnline,
				ProtectedBranch: r.ProtectedBranches,
			}
		}
		out, _ := json.MarshalIndent(view, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	data := pterm.TableData{{"ID", "Project", "Findings", "Pipeline", "Runners", "Online"}}
	for _, r := range results {
		runnersStr := "—"
		if r.RunnersTotal > 0 {
			runnersStr = fmt.Sprintf("%d/%d", r.RunnersOnline, r.RunnersTotal)
		}
		data = append(data, []string{
			fmt.Sprintf("%d", r.GitLabProjectID),
			r.PathWithNamespace,
			fmt.Sprintf("%d", r.FindingsCount),
			pterm.LightGreen("yes"),
			runnersStr,
			r.ProtectedBranches,
		})
	}
	return renderTable(os.Stdout, data)
}

// ---- findings ----

func listFindings(format string, sessionID uint) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	var results []store.EnumerateResult
	if sessionID > 0 {
		results, err = st.GetEnumerateResultsBySession(sessionID)
	} else {
		results, err = st.GetAllEnumerateResults()
	}
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No findings found.")
		return nil
	}

	// Collect all findings
	type findingView struct {
		Project   string
		FindingID string
		Severity  string
		Title     string
		Job       string
		Evidence  string
	}
	var findings []findingView
	for _, r := range results {
		for _, f := range r.Findings {
			findings = append(findings, findingView{
				Project:   r.PathWithNamespace,
				FindingID: f.FindingID,
				Severity:  f.Severity,
				Title:     f.Title,
				Job:       f.JobName,
				Evidence:  f.Evidence,
			})
		}
	}

	if len(findings) == 0 {
		fmt.Println("No findings found.")
		return nil
	}

	if format == "json" {
		out, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Group by severity
	knownSeverities := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true,
	}
	bySeverity := map[string][]findingView{
		"CRITICAL":      {},
		"HIGH":          {},
		"MEDIUM":        {},
		"LOW":           {},
		"INFORMATIONAL": {},
		"OTHER":         {},
	}
	for _, f := range findings {
		s := strings.ToUpper(f.Severity)
		if !knownSeverities[s] {
			s = "OTHER"
		}
		bySeverity[s] = append(bySeverity[s], f)
	}

	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "OTHER"} {
		list := bySeverity[sev]
		if len(list) == 0 {
			continue
		}
		fmt.Fprintln(os.Stdout, pterm.DefaultSection.Sprint(sev+" ("+fmt.Sprint(len(list))+")"))
		data := pterm.TableData{{"Project", "Finding", "Job", "Severity", "Evidence"}}
		for _, f := range list {
			severity := strings.ToUpper(f.Severity)
			evidence := f.Evidence
			if len(evidence) > 80 {
				evidence = evidence[:80] + "..."
			}
			data = append(data, []string{f.Project, f.FindingID, f.Job, severity, evidence})
		}
		_ = renderTable(os.Stdout, data)
	}
	return nil
}

// ---- attacks ----

func listAttacks(format string, sessionID uint) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	var results []store.AttackResult
	if sessionID > 0 {
		results, err = st.GetAttackResultsBySession(sessionID)
	} else {
		results, err = st.GetAllAttackResults()
	}
	if err != nil {
		return fmt.Errorf("list attacks: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No attack results found.")
		return nil
	}

	if format == "json" {
		out, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	data := pterm.TableData{{"ID", "Project", "Mode", "Payload", "Branch", "Status", "Error"}}
	for _, a := range results {
		errStr := "—"
		if a.Error != "" {
			errStr = a.Error
		}
		data = append(data, []string{
			fmt.Sprintf("%d", a.ID),
			a.PathWithNamespace,
			a.Mode,
			a.Payload,
			a.Branch,
			a.Status,
			errStr,
		})
	}
	return renderTable(os.Stdout, data)
}

// ---- exfil secrets ----

func listExfilSecrets(format string) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	type secretView struct {
		Project string `json:"project"`
		Key     string `json:"key"`
		Value   string `json:"value"`
		Created string `json:"created"`
	}

	var allSecrets []secretView
	// Get all attack results with exfil secrets
	attacks, err := st.GetAllAttackResults()
	if err != nil {
		return fmt.Errorf("list attacks: %w", err)
	}

	for _, a := range attacks {
		secrets, serr := st.GetAttackExfilSecrets(a.ID)
		if serr != nil || len(secrets) == 0 {
			continue
		}
		for _, s := range secrets {
			allSecrets = append(allSecrets, secretView{
				Project: a.PathWithNamespace,
				Key:     s.Key,
				Value:   redactValue(s.Value, queryRedacted), // mask if --redacted
				Created: s.CreatedAt.Format("2006-01-02"),
			})
		}
	}

	if len(allSecrets) == 0 {
		fmt.Println("No exfiltrated secrets found in attack operations.")
		return nil
	}

	if format == "json" {
		out, _ := json.MarshalIndent(allSecrets, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Group by project
	type groupedKey struct {
		Project string
		Key     string
	}
	grouped := make(map[groupedKey]struct{})
	var unique []struct {
		project string
		key     string
	}
	for _, s := range allSecrets {
		gk := groupedKey{s.Project, s.Key}
		if _, exists := grouped[gk]; exists {
			continue
		}
		grouped[gk] = struct{}{}
		unique = append(unique, struct{ project, key string }{s.Project, s.Key})
	}

	data := pterm.TableData{{"Project", "Key", "Value"}}
	for _, u := range unique {
		// Find matching secret for value display
		for _, s := range allSecrets {
			if s.Project == u.project && s.Key == u.key {
				data = append(data, []string{u.project, s.Key, redactValue(s.Value, queryRedacted)})
				break
			}
		}
	}
	return renderTable(os.Stdout, data)
}

// ---- credentials ----

func listCredentials(format string) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	credentials, err := st.GetAllHarvestedCredentials()
	if err != nil {
		return fmt.Errorf("list credentials: %w", err)
	}

	if len(credentials) == 0 {
		fmt.Println("No harvested credentials found.")
		return nil
	}

	if format == "json" {
		type credView struct {
			ID            uint   `json:"id"`
			TokenHash     string `json:"token_hash"`
			TokenType     string `json:"type"`
			SourceKey     string `json:"source_key"`
			SourceProject int64  `json:"source_project_id"`
			Depth         int    `json:"depth"`
			UserID        int64  `json:"user_id"`
			Username      string `json:"username"`
			IsValid       bool   `json:"is_valid"`
		}
		views := make([]credView, len(credentials))
		for i, c := range credentials {
			views[i] = credView{
				ID:            c.ID,
				TokenHash:     c.TokenHash,
				TokenType:     c.TokenType,
				SourceKey:     c.SourceKey,
				SourceProject: c.SourceProjectID,
				Depth:         c.Depth,
				UserID:        c.UserID,
				Username:      c.Username,
				IsValid:       c.IsValid,
			}
		}
		out, _ := json.MarshalIndent(views, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	data := pterm.TableData{{"ID", "Type", "Source Key", "Source Project", "Depth", "User", "Valid"}}
	for _, c := range credentials {
		userStr := "—"
		if c.Username != "" {
			userStr = c.Username
		}
		valid := "✗"
		if c.IsValid {
			valid = "✓"
		}
		data = append(data, []string{
			fmt.Sprintf("%d", c.ID),
			c.TokenType,
			c.SourceKey,
			fmt.Sprintf("%d", c.SourceProjectID),
			fmt.Sprintf("%d", c.Depth),
			userStr,
			valid,
		})
	}
	return renderTable(os.Stdout, data)
}

// ---- exfil callbacks ----

func listExfilCallbacks(format string) error {
	st, err := getDB()
	if err != nil {
		return err
	}
	defer st.Close()

	// Read pivot exfiltration results
	callbacks, err := st.GetAllExfiltratedSecrets()
	if err != nil {
		return fmt.Errorf("list exfil callbacks: %w", err)
	}

	// Read attack-mode exfiltration results
	attackResults, err := st.GetAllAttackResults()
	if err != nil {
		return fmt.Errorf("list attack results: %w", err)
	}

	type row struct {
		project   string
		mode      string
		branch    string
		key       string
		value     string
		createdAt string
	}
	var rows []row

	for _, c := range callbacks {
		rows = append(rows, row{
			project:   c.SourceProjectPath,
			mode:      "pivot",
			branch:    "—",
			key:       c.Key,
			value:     c.Value,
			createdAt: c.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	for _, ar := range attackResults {
		secrets, err := st.GetAttackExfilSecrets(ar.ID)
		if err != nil {
			continue
		}
		for _, s := range secrets {
			rows = append(rows, row{
				project:   ar.PathWithNamespace,
				mode:      "attack",
				branch:    ar.Branch,
				key:       s.Key,
				value:     s.Value,
				createdAt: ar.CreatedAt.Format("2006-01-02 15:04:05"),
			})
		}
	}

	if len(rows) == 0 {
		fmt.Println("No exfiltrated secrets from listener callbacks found.")
		return nil
	}

	if format == "json" {
		type exfilView struct {
			SourceProject string `json:"source_project"`
			Mode          string `json:"mode"`
			Branch        string `json:"branch"`
			Key           string `json:"key"`
			Value         string `json:"value"`
			CreatedAt     string `json:"created_at"`
		}
		views := make([]exfilView, len(rows))
		for i, r := range rows {
			views[i] = exfilView{
				SourceProject: r.project,
				Mode:          r.mode,
				Branch:        r.branch,
				Key:           r.key,
				Value:         redactValue(r.value, queryRedacted),
				CreatedAt:     r.createdAt,
			}
		}
		out, _ := json.MarshalIndent(views, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Group by source project
	type projData struct {
		project string
		mode    string
		branch  string
		secrets map[string]string
	}
	projects := make(map[string]*projData)
	for _, r := range rows {
		key := r.project + "|" + r.mode
		if _, ok := projects[key]; !ok {
			projects[key] = &projData{project: r.project, mode: r.mode, branch: r.branch, secrets: make(map[string]string)}
		}
		projects[key].secrets[r.key] = r.value
	}

	// Summary table
	data := pterm.TableData{{"Project", "Mode", "Keys Found", "Sample Secret Names"}}
	for _, pd := range projects {
		keys := make([]string, 0, len(pd.secrets))
		for k := range pd.secrets {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Show interesting keys
		var interesting []string
		for _, k := range keys {
			uk := strings.ToUpper(k)
			if strings.Contains(uk, "TOKEN") || strings.Contains(uk, "SECRET") ||
				strings.Contains(uk, "PASSWORD") || strings.Contains(uk, "KEY") ||
				strings.Contains(uk, "CRED") || strings.Contains(uk, "AUTH") {
				interesting = append(interesting, k)
			}
		}
		if len(interesting) == 0 {
			interesting = keys[:min(5, len(keys))]
		}
		sample := strings.Join(interesting, ", ")
		if len(sample) > 60 {
			sample = sample[:60] + "..."
		}

		data = append(data, []string{
			pd.project,
			pd.mode,
			fmt.Sprintf("%d", len(pd.secrets)),
			sample,
		})
	}
	return renderTable(os.Stdout, data)
}
