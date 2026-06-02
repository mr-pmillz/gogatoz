package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate/report"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/spf13/cobra"
)

var (
	reportInput        string
	reportDBPath       string
	reportSessionID    uint
	reportFormat       string
	reportOutputPath   string
	reportOnlyFindings bool
	reportFilterFP     bool
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate an HTML report from previous scan results",
	Long: `Reads enumerate results from a JSONL file or SQLite database and generates
a self-contained HTML report with charts and searchable tables.

Examples:
  # From JSONL file (default: HTML output)
  gogatoz report --input results.jsonl --output report.html

  # From SQLite database
  gogatoz report --db results.sqlite3 --session 1 --output report.html

  # Text format
  gogatoz report --input results.jsonl --format text`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var results []enumerate.Result
		var attacks []report.AttackView
		var err error

		switch {
		case strings.TrimSpace(reportDBPath) != "":
			results, attacks, err = loadFromDB(reportDBPath, reportSessionID)
		case strings.TrimSpace(reportInput) != "":
			results, err = loadFromFile(reportInput)
		default:
			// Fall back to default DB path if it exists
			defDB := defaultDBPath()
			if defDB != "" {
				if _, statErr := os.Stat(defDB); statErr == nil {
					results, attacks, err = loadFromDB(defDB, reportSessionID)
					break
				}
			}
			return fmt.Errorf("either --input or --db is required (no default database found at %s)", defDB)
		}
		if err != nil {
			return err
		}

		// Determine output destination
		w := cmd.OutOrStdout()
		if p := strings.TrimSpace(reportOutputPath); p != "" {
			f, fErr := os.Create(p)
			if fErr != nil {
				return fmt.Errorf("create output file: %w", fErr)
			}
			defer f.Close()
			w = f
		}

		// Apply false positive filtering if requested
		if reportFilterFP {
			rules := analyze.DefaultFPRules()
			for i := range results {
				results[i].Findings = analyze.ApplyFPRules(results[i].Findings, rules)
			}
		}

		repOpts := report.Options{OnlyFindings: reportOnlyFindings, FilterFalsePositives: reportFilterFP}
		rep := report.Build(results, repOpts)
		if len(attacks) > 0 {
			rep.AddAttacks(attacks)
		}
		fmtSel := strings.ToLower(strings.TrimSpace(reportFormat))

		switch fmtSel {
		case fmtJSON:
			return report.RenderJSON(w, rep, true)
		case fmtJSONL:
			return report.RenderJSONL(w, results, repOpts)
		case "text":
			return report.RenderPTerm(w, rep)
		default: // html is the default for this command
			return report.RenderHTML(w, rep, version)
		}
	},
}

func loadFromDB(dbPath string, sessionID uint) ([]enumerate.Result, []report.AttackView, error) {
	if sessionID == 0 {
		return nil, nil, fmt.Errorf("--session is required when using --db")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	sess, err := st.GetSession(sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("load session %d: %w", sessionID, err)
	}
	return storeToResults(sess.EnumerateResults), storeToAttackViews(sess.AttackResults), nil
}

func storeToResults(ers []store.EnumerateResult) []enumerate.Result {
	results := make([]enumerate.Result, len(ers))
	for i, er := range ers {
		results[i] = enumerate.Result{
			ProjectID:         er.GitLabProjectID,
			ProjectPathWithNS: er.PathWithNamespace,
			WebURL:            er.WebURL,
			DefaultBranch:     er.DefaultBranch,
			StarCount:         er.StarCount,
			HasCIPipeline:     er.HasCIPipeline,
			RunnersTotal:      er.RunnersTotal,
			RunnersOnline:     er.RunnersOnline,
			DurationMS:        er.DurationMS,
			Error:             er.Error,
		}
		for _, sf := range er.Findings {
			results[i].Findings = append(results[i].Findings, analyze.Finding{
				ID:                  sf.FindingID,
				Severity:            analyze.Severity(sf.Severity),
				Title:               sf.Title,
				Description:         sf.Description,
				Evidence:            sf.Evidence,
				JobName:             sf.JobName,
				Recommendation:      sf.Recommendation,
				FalsePositive:       sf.FalsePositive,
				FalsePositiveReason: sf.FalsePositiveReason,
			})
		}
	}
	return results
}

func storeToAttackViews(ars []store.AttackResult) []report.AttackView {
	views := make([]report.AttackView, len(ars))
	for i, ar := range ars {
		views[i] = report.AttackView{
			PathWithNamespace: ar.PathWithNamespace,
			WebURL:            ar.WebURL,
			Mode:              ar.Mode,
			Payload:           ar.Payload,
			Branch:            ar.Branch,
			PipelineURL:       ar.PipelineURL,
			PipelineID:        ar.PipelineID,
			Tags:              ar.Tags,
			Status:            ar.Status,
			Error:             ar.Error,
			DurationMS:        ar.DurationMS,
		}
	}
	return views
}

func loadFromFile(path string) ([]enumerate.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()

	// Peek at first non-whitespace byte to detect format
	buf := bufio.NewReader(f)
	var b byte
	for {
		b, err = buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read input: %w", err)
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			break
		}
	}
	if err := buf.UnreadByte(); err != nil {
		return nil, fmt.Errorf("unread input: %w", err)
	}

	if b == '[' {
		// JSON array
		var results []enumerate.Result
		if err := json.NewDecoder(buf).Decode(&results); err != nil {
			return nil, fmt.Errorf("decode JSON array: %w", err)
		}
		return results, nil
	}

	// JSONL: one result per line
	var results []enumerate.Result
	scanner := bufio.NewScanner(buf)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r enumerate.Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("decode JSONL line: %w", err)
		}
		results = append(results, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read JSONL: %w", err)
	}
	return results, nil
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVarP(&reportInput, "input", "i", "", "Path to JSONL or JSON file with enumerate results")
	reportCmd.Flags().StringVar(&reportDBPath, "db", "", "SQLite database path")
	reportCmd.Flags().UintVar(&reportSessionID, "session", 0, "Session ID to load from database (required with --db)")
	reportCmd.Flags().StringVar(&reportFormat, "format", "html", "Output format: html|text|json|jsonl")
	reportCmd.Flags().StringVarP(&reportOutputPath, "output", "o", "", "Output file path (default: stdout)")
	reportCmd.Flags().BoolVar(&reportOnlyFindings, "only-findings", false, "Only include projects with findings")
	reportCmd.Flags().BoolVar(&reportFilterFP, "filter-false-positives", false, "Apply false positive detection rules and show adjusted counts")
}
