package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/dashboard"
	"github.com/mr-pmillz/gogatoz/pkg/enumerate"
	enumorg "github.com/mr-pmillz/gogatoz/pkg/enumerate/org"
	"github.com/spf13/cobra"
)

var (
	dashGroup  string
	dashJSONL  string
	dashFormat string
	dashOutput string
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Generate a group-level security dashboard",
	Long:  "Aggregate security posture across all projects in a GitLab group into a scorecard dashboard.",
	RunE:  runDashboard,
}

func runDashboard(cmd *cobra.Command, _ []string) error {
	if dashGroup == "" && dashJSONL == "" {
		return fmt.Errorf("--group or --from-jsonl is required")
	}

	var results []enumerate.Result
	var groupName string
	var groupID int64

	if dashJSONL != "" {
		var err error
		results, err = loadResultsFromJSONL(dashJSONL)
		if err != nil {
			return err
		}
		groupName = dashJSONL
	} else {
		var err error
		results, groupName, groupID, err = scanGroup(cmd, dashGroup)
		if err != nil {
			return err
		}
	}

	d := dashboard.Build(results, groupName, groupID)

	w := cmd.OutOrStdout()
	if dashOutput != "" {
		f, err := os.Create(dashOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(dashFormat) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	case "html":
		return dashboard.RenderHTML(w, d, version)
	default:
		dashboard.RenderPTerm(w, d)
		return nil
	}
}

// loadResultsFromJSONL reads enumerate results from a JSONL file.
func loadResultsFromJSONL(path string) ([]enumerate.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open jsonl: %w", err)
	}
	defer f.Close()

	var results []enumerate.Result
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		var r enumerate.Result
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		results = append(results, r)
	}
	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("scan jsonl: %w", err)
	}
	return results, nil
}

// scanGroup enumerates all projects in a GitLab group via live scan.
func scanGroup(cmd *cobra.Command, group string) ([]enumerate.Result, string, int64, error) {
	ctx := context.Background()
	client, err := newGitLabClient()
	if err != nil {
		return nil, "", 0, err
	}

	projs, err := enumorg.ListGroupProjects(ctx, client, group, true)
	if err != nil {
		return nil, "", 0, fmt.Errorf("list group projects: %w", err)
	}

	opts := enumerate.Options{
		Concurrency:    runtime.GOMAXPROCS(0),
		FollowIncludes: true,
		IncludeDepth:   2,
		FetchProtected: true,
	}
	results, err := enumerate.EnumerateProjects(ctx, client, projs, opts)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", err)
	}
	return results, group, 0, nil
}

func init() {
	rootCmd.AddCommand(dashboardCmd)
	dashboardCmd.Flags().StringVar(&dashGroup, "group", "", "GitLab group ID or path")
	dashboardCmd.Flags().StringVar(&dashJSONL, "from-jsonl", "", "Load results from JSONL file")
	dashboardCmd.Flags().StringVarP(&dashFormat, "format", "f", "text", "Output format: text|json|html")
	dashboardCmd.Flags().StringVarP(&dashOutput, "output", "o", "", "Write output to file")
}
