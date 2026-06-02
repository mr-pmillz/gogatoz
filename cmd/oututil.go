package cmd

import (
	"bufio"
	"encoding/json"
	"io"
)

// writeJSONL writes each item as a single JSON object per line to w.
func writeJSONL(w io.Writer, items []map[string]any) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return err
		}
	}
	return bw.Flush()
}
