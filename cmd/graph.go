package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/graph"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/mr-pmillz/gogatoz/pkg/store"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

var (
	graphProject        string
	graphRef            string
	graphFormat         string
	graphOutput         string
	graphFollowIncludes bool
	graphIncludeDepth   int
	graphSession        uint
	graphAllProjects    bool
)

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Visualize CI/CD dependency graphs for GitLab projects",
	Long: `Fetch .gitlab-ci.yml configs from GitLab and output dependency graphs
in Graphviz DOT or Mermaid format.

Three modes:
  --project         Single project: job-level dependency DAG
  --session ID      Cross-project: relationships between all projects in a scan session
  --all-projects    Cross-project: relationships between all projects in the database

Cross-project mode shows include and trigger relationships between projects.
Requires a GitLab token to re-fetch CI configs.
Use "gogatoz parse graph" for local files without GitLab access.`,
	Example: `  # Single project DOT graph
  gogatoz graph --project mygroup/myproject

  # Cross-project graph from a scan session
  gogatoz graph --session 1 --format mermaid

  # All projects in the database
  gogatoz graph --all-projects -o cross-project.dot

  # With include resolution
  gogatoz graph --project 12345 --follow-includes`,
	RunE: runGraph,
}

func init() {
	rootCmd.AddCommand(graphCmd)
	graphCmd.Flags().StringVar(&graphProject, "project", "", "GitLab project ID or path (single-project mode)")
	graphCmd.Flags().StringVar(&graphRef, "ref", "", "Git ref to fetch (default: project's default branch)")
	graphCmd.Flags().StringVar(&graphFormat, "format", "dot", "Output format: dot|mermaid")
	graphCmd.Flags().StringVarP(&graphOutput, "output", "o", "", "Write output to file (default: stdout)")
	graphCmd.Flags().BoolVar(&graphFollowIncludes, "follow-includes", false, "Resolve transitive CI includes")
	graphCmd.Flags().IntVar(&graphIncludeDepth, "include-depth", 2, "Max include resolution depth")
	graphCmd.Flags().UintVar(&graphSession, "session", 0, "Scan session ID for cross-project graph")
	graphCmd.Flags().BoolVar(&graphAllProjects, "all-projects", false, "Graph all projects in the database")

	graphCmd.MarkFlagsMutuallyExclusive("project", "session", "all-projects")
}

func runGraph(cmd *cobra.Command, _ []string) error {
	if graphProject == "" && graphSession == 0 && !graphAllProjects {
		return fmt.Errorf("one of --project, --session, or --all-projects is required")
	}

	if token == "" && !noToken {
		return fmt.Errorf("GitLab token required (--token or GITLAB_TOKEN)")
	}

	if graphSession > 0 || graphAllProjects {
		return runCrossProjectGraph(cmd)
	}
	return runSingleProjectGraph(cmd)
}

func runSingleProjectGraph(cmd *cobra.Command) error {
	client, err := newGitLabClient()
	if err != nil {
		return err
	}

	ctx := context.Background()
	projectID := resolveProjectID(graphProject)

	doc, err := fetchAndParseCIConfig(ctx, client, projectID, strings.TrimSpace(graphRef), cmd)
	if err != nil {
		return err
	}

	g, err := graph.Build(doc)
	if err != nil {
		return fmt.Errorf("build graph: %w", err)
	}

	w, cleanup, err := graphWriter(graphOutput, cmd)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	switch graphFormat {
	case "dot":
		return g.WriteDOT(w)
	case "mermaid":
		return g.WriteMermaid(w)
	default:
		return fmt.Errorf("unknown format %q (use dot or mermaid)", graphFormat)
	}
}

func runCrossProjectGraph(cmd *cobra.Command) error {
	results, err := loadProjectsFromDB()
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("no projects found in the database")
	}

	client, err := newGitLabClient()
	if err != nil {
		return err
	}

	ctx := context.Background()
	projects := make(map[string]*pipeline.Document, len(results))
	errW := cmd.ErrOrStderr()

	for _, r := range results {
		if !r.HasCIPipeline {
			projects[r.PathWithNamespace] = nil
			continue
		}
		doc, fetchErr := fetchAndParseCIConfig(ctx, client, r.GitLabProjectID, r.DefaultBranch, cmd)
		if fetchErr != nil {
			fmt.Fprintf(errW, "warning: %s: %v\n", r.PathWithNamespace, fetchErr)
			projects[r.PathWithNamespace] = nil
			continue
		}
		projects[r.PathWithNamespace] = doc
	}

	cpg := graph.BuildCrossProject(projects)

	w, cleanup, err := graphWriter(graphOutput, cmd)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	switch graphFormat {
	case "dot":
		return cpg.WriteDOT(w)
	case "mermaid":
		return cpg.WriteMermaid(w)
	default:
		return fmt.Errorf("unknown format %q (use dot or mermaid)", graphFormat)
	}
}

func loadProjectsFromDB() ([]store.EnumerateResult, error) {
	st, err := openGraphStore()
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()

	if graphAllProjects {
		return st.GetAllEnumerateResults()
	}
	return st.GetEnumerateResultsBySession(graphSession)
}

func openGraphStore() (*store.Store, error) {
	if cliStore != nil {
		return cliStore, nil
	}
	path := defaultDBPath()
	if dbPath != "" {
		path = dbPath
	}
	if path == "" {
		return nil, fmt.Errorf("no database path configured (use --db or set GOGATOZ_DB)")
	}
	return store.Open(path)
}

func fetchAndParseCIConfig(ctx context.Context, client *gitlabx.Client, projectID any, ref string, cmd *cobra.Command) (*pipeline.Document, error) {
	if ref == "" {
		proj, _, err := client.GL.Projects.GetProject(projectID, nil, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("get project: %w", err)
		}
		ref = proj.DefaultBranch
		if ref == "" {
			return nil, fmt.Errorf("project has no default branch")
		}
	}

	file, resp, err := client.GL.RepositoryFiles.GetFile(projectID, ".gitlab-ci.yml",
		&gitlab.GetFileOptions{Ref: &ref}, gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.Response != nil && resp.StatusCode == 404 {
			return nil, fmt.Errorf("no .gitlab-ci.yml on ref %q", ref)
		}
		return nil, fmt.Errorf("fetch .gitlab-ci.yml: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return nil, fmt.Errorf("decode CI config: %w", err)
	}

	doc, err := pipeline.Parse(strings.NewReader(string(decoded)))
	if err != nil {
		return nil, fmt.Errorf("parse CI config: %w", err)
	}

	if graphFollowIncludes && len(doc.Includes) > 0 {
		merged, ierr := pipeline.ResolveIncludesWithOptions(ctx, client, projectID, ref, doc, graphIncludeDepth, pipeline.ResolveOptions{})
		if ierr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: include resolution: %v\n", ierr)
		}
		if merged != nil {
			doc = merged
		}
	}

	return doc, nil
}

func graphWriter(path string, cmd *cobra.Command) (io.Writer, func(), error) {
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, nil, fmt.Errorf("create output: %w", err)
		}
		return f, func() { f.Close() }, nil
	}
	return cmd.OutOrStdout(), nil, nil
}

func resolveProjectID(ident string) any {
	if id, err := strconv.ParseInt(ident, 10, 64); err == nil {
		return id
	}
	return ident
}
