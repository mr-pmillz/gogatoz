package bloodhound

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

// Export writes a BloodHound-CE compatible ZIP to outputPath containing
// the graph data from the builder and the seed data for edge kind registration.
func Export(b *Builder, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	if err := ExportToWriter(b, f); err != nil {
		f.Close()
		os.Remove(outputPath)
		return err
	}
	return f.Close()
}

// ExportToWriter writes the BloodHound-CE ZIP to any io.Writer.
func ExportToWriter(b *Builder, w io.Writer) error {
	zw := zip.NewWriter(w)

	// Only include seed data if the real graph is empty (bootstraps kind registry).
	// When real data exists, the seed node pollutes the graph with a junk instance.
	if len(b.Edges()) == 0 {
		if err := writeSeedData(zw); err != nil {
			zw.Close()
			return err
		}
	}

	if err := writeGraphData(zw, b); err != nil {
		zw.Close()
		return err
	}

	return zw.Close()
}

func writeSeedData(zw *zip.Writer) error {
	fw, err := zw.Create("seed_data.json")
	if err != nil {
		return fmt.Errorf("create seed_data.json in zip: %w", err)
	}
	if _, err := fw.Write(SeedDataJSON); err != nil {
		return fmt.Errorf("write seed_data.json: %w", err)
	}
	return nil
}

func writeGraphData(zw *zip.Writer, b *Builder) error {
	fw, err := zw.Create("cicd-data.json")
	if err != nil {
		return fmt.Errorf("create cicd-data.json in zip: %w", err)
	}

	sw, err := NewStreamingWriter(fw, SourceKind)
	if err != nil {
		return fmt.Errorf("create streaming writer: %w", err)
	}

	for _, node := range b.Nodes() {
		if err := sw.WriteNode(node); err != nil {
			return fmt.Errorf("write node %s: %w", node.ID, err)
		}
	}

	for _, edge := range b.Edges() {
		if err := sw.WriteEdge(edge); err != nil {
			return fmt.Errorf("write edge: %w", err)
		}
	}

	return sw.Close()
}
