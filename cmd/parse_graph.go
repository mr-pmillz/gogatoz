package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/mr-pmillz/gogatoz/pkg/graph"
	"github.com/mr-pmillz/gogatoz/pkg/pipeline"
	"github.com/spf13/cobra"
)

var (
	parseGraphFormat string
	parseGraphOutput string
)

var parseGraphCmd = &cobra.Command{
	Use:   "graph [file]",
	Short: "Visualize CI/CD job dependency graph",
	Long: `Parse a .gitlab-ci.yml file and output its job dependency graph
in Graphviz DOT or Mermaid format.

If no file is given, reads from stdin.`,
	Example: `  # Output DOT to stdout
  gogatoz parse graph .gitlab-ci.yml

  # Output Mermaid to a file
  gogatoz parse graph --format mermaid --output pipeline.md .gitlab-ci.yml

  # Pipe from stdin
  cat .gitlab-ci.yml | gogatoz parse graph --format dot`,
	Args: cobra.MaximumNArgs(1),
	RunE: runParseGraph,
}

func init() {
	parseCmd.AddCommand(parseGraphCmd)
	parseGraphCmd.Flags().StringVar(&parseGraphFormat, "format", "dot", "Output format: dot|mermaid")
	parseGraphCmd.Flags().StringVarP(&parseGraphOutput, "output", "o", "", "Write output to file (default: stdout)")
}

func runParseGraph(cmd *cobra.Command, args []string) error {
	var r io.Reader
	if len(args) > 0 {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("open %s: %w", args[0], err)
		}
		defer f.Close()
		r = f
	} else {
		r = cmd.InOrStdin()
	}

	doc, err := pipeline.Parse(r)
	if err != nil {
		return fmt.Errorf("parse pipeline: %w", err)
	}

	g, err := graph.Build(doc)
	if err != nil {
		return fmt.Errorf("build graph: %w", err)
	}

	var w io.Writer
	if parseGraphOutput != "" {
		f, err := os.Create(parseGraphOutput)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		w = f
	} else {
		w = cmd.OutOrStdout()
	}

	switch parseGraphFormat {
	case "dot":
		return g.WriteDOT(w)
	case "mermaid":
		return g.WriteMermaid(w)
	default:
		return fmt.Errorf("unknown format %q (use dot or mermaid)", parseGraphFormat)
	}
}
