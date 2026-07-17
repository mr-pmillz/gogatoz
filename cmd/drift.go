package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/drift"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	driftProject         string
	driftRef             string
	driftBaselineRef     string
	driftSaveBaseline    bool
	driftCompareBaseline bool
	driftFormat          string
	driftOutput          string
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Detect CI/CD configuration changes between two points in time",
	Long:  "Compare a project's .gitlab-ci.yml between refs or against a stored baseline to detect security-relevant changes.",
	RunE:  runDrift,
}

func runDrift(cmd *cobra.Command, _ []string) error {
	if driftProject == "" {
		return fmt.Errorf("--project is required")
	}
	ctx := context.Background()
	client, err := newGitLabClient()
	if err != nil {
		return err
	}

	proj, _, err := client.GL.Projects.GetProject(driftProject, nil, gitlab.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}

	currentRef := driftRef
	if currentRef == "" {
		currentRef = proj.DefaultBranch
	}

	currentYAML, err := fetchCIYAML(ctx, client, proj.ID, currentRef)
	if err != nil {
		return fmt.Errorf("fetch current CI config: %w", err)
	}
	currentDoc, err := pipeline.Parse(strings.NewReader(currentYAML))
	if err != nil {
		return fmt.Errorf("parse current config: %w", err)
	}

	if driftSaveBaseline {
		return handleSaveBaseline(cmd, proj.ID, proj.PathWithNamespace, currentRef, currentYAML)
	}

	report, err := buildDriftReport(ctx, cmd, client, proj.ID, proj.PathWithNamespace, currentRef, currentDoc)
	if err != nil {
		return err
	}

	return outputDriftReport(cmd, report)
}

func handleSaveBaseline(cmd *cobra.Command, projectID int64, projectPath, ref, yaml string) error {
	if cliStore == nil {
		return fmt.Errorf("database not available (use --db to specify path or remove --no-db)")
	}
	db := cliStore.DB()
	if err := db.AutoMigrate(&drift.ConfigBaseline{}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := drift.SaveBaseline(db, projectID, projectPath, ref, yaml); err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Baseline saved for %s at ref %s\n", projectPath, ref)
	return nil
}

func buildDriftReport(
	ctx context.Context, cmd *cobra.Command, client *gitlabx.Client,
	projectID int64, projectPath, currentRef string, currentDoc *pipeline.Document,
) (drift.DriftReport, error) {
	var baselineDoc *pipeline.Document
	var baselineRefName string

	switch {
	case driftCompareBaseline:
		doc, ref, err := loadBaselineDoc(cmd, projectID)
		if err != nil {
			return drift.DriftReport{}, err
		}
		baselineDoc = doc
		baselineRefName = ref
	case driftBaselineRef != "":
		baselineYAML, err := fetchCIYAML(ctx, client, projectID, driftBaselineRef)
		if err != nil {
			return drift.DriftReport{}, fmt.Errorf("fetch baseline CI config: %w", err)
		}
		doc, err := pipeline.Parse(strings.NewReader(baselineYAML))
		if err != nil {
			return drift.DriftReport{}, fmt.Errorf("parse baseline config: %w", err)
		}
		baselineDoc = doc
		baselineRefName = driftBaselineRef
	default:
		return drift.DriftReport{}, fmt.Errorf("provide --baseline-ref or --compare-baseline")
	}

	report := drift.Diff(baselineDoc, currentDoc)
	report.ProjectPath = projectPath
	report.CurrentRef = currentRef
	report.BaselineRef = baselineRefName
	report.SecurityImpact = drift.AssessSecurityImpact(report.Changes)
	return report, nil
}

func loadBaselineDoc(_ *cobra.Command, projectID int64) (*pipeline.Document, string, error) {
	if cliStore == nil {
		return nil, "", fmt.Errorf("database not available (use --db to specify path or remove --no-db)")
	}
	db := cliStore.DB()
	if err := db.AutoMigrate(&drift.ConfigBaseline{}); err != nil {
		return nil, "", fmt.Errorf("migrate: %w", err)
	}
	b, err := drift.LoadBaseline(db, projectID)
	if err != nil {
		return nil, "", fmt.Errorf("load baseline: %w", err)
	}
	doc, err := pipeline.Parse(strings.NewReader(b.ConfigYAML))
	if err != nil {
		return nil, "", fmt.Errorf("parse baseline: %w", err)
	}
	return doc, fmt.Sprintf("baseline@%s", b.Ref), nil
}

func outputDriftReport(cmd *cobra.Command, report drift.DriftReport) error {
	w := cmd.OutOrStdout()
	if driftOutput != "" {
		f, err := os.Create(driftOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(driftFormat) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default:
		renderDriftText(w, report)
		return nil
	}
}

func fetchCIYAML(ctx context.Context, cl *gitlabx.Client, projectID int64, ref string) (string, error) {
	file, resp, err := cl.GL.RepositoryFiles.GetFile(projectID, ".gitlab-ci.yml",
		&gitlab.GetFileOptions{Ref: &ref}, gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			return "", fmt.Errorf("no .gitlab-ci.yml at ref %s", ref)
		}
		return "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	return string(decoded), nil
}

func renderDriftText(w io.Writer, report drift.DriftReport) {
	header := pterm.DefaultHeader.WithFullWidth()
	fmt.Fprintln(w, header.Sprint(fmt.Sprintf("CI/CD Config Drift: %s", report.ProjectPath)))
	fmt.Fprintf(w, "Baseline: %s -> Current: %s\n\n", report.BaselineRef, report.CurrentRef)

	if len(report.Changes) == 0 {
		fmt.Fprintln(w, pterm.Green("No changes detected."))
		return
	}

	fmt.Fprintf(w, "Changes: %d total\n\n", len(report.Changes))
	for _, c := range report.Changes {
		prefix := "  "
		switch c.Type {
		case drift.ChangeAdded:
			prefix = pterm.Green("+ ")
		case drift.ChangeRemoved:
			prefix = pterm.Red("- ")
		case drift.ChangeModified:
			prefix = pterm.Yellow("~ ")
		}
		fmt.Fprintf(w, "%s[%s] %s", prefix, c.Category, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(w, " (%s)", c.Detail)
		}
		fmt.Fprintln(w)
	}

	if len(report.SecurityImpact) > 0 {
		fmt.Fprintln(w, "\nSecurity Impact:")
		for _, si := range report.SecurityImpact {
			fmt.Fprintf(w, "  [%s] %s\n", si.Severity, si.Description)
		}
	}
}

func init() {
	rootCmd.AddCommand(driftCmd)
	driftCmd.Flags().StringVar(&driftProject, "project", "", "Project ID or path-with-namespace (required)")
	driftCmd.Flags().StringVar(&driftRef, "ref", "", "Current ref to compare (default: default branch)")
	driftCmd.Flags().StringVar(&driftBaselineRef, "baseline-ref", "", "Git ref to use as baseline")
	driftCmd.Flags().BoolVar(&driftSaveBaseline, "save-baseline", false, "Save current config as baseline")
	driftCmd.Flags().BoolVar(&driftCompareBaseline, "compare-baseline", false, "Compare against stored baseline")
	driftCmd.Flags().StringVarP(&driftFormat, "format", "f", "text", "Output format: text|json")
	driftCmd.Flags().StringVarP(&driftOutput, "output", "o", "", "Write output to file")
}
