package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mr-pmillz/gogatoz/cmd"
	"github.com/spf13/cobra/doc"
)

func main() {
	outDir := "docs/cmd"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(filepath.Clean(outDir), 0o755); err != nil { //nolint:gosec // G703: output directory provided by user via CLI arg
		if _, err := fmt.Fprintf(os.Stderr, "mkdir: %v\n", err); err != nil {
			return
		}
		os.Exit(1)
	}
	r := cmd.RootCmd()
	// ensure index file name
	filePrepender := func(filename string) string { return "" }
	if err := doc.GenMarkdownTreeCustom(r, outDir, filePrepender, filepath.Base); err != nil {
		if _, err := fmt.Fprintf(os.Stderr, "generate docs: %v\n", err); err != nil {
			return
		}
		os.Exit(1)
	}
}
