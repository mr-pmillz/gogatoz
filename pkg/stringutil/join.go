package stringutil

import (
	"fmt"
	"strings"
)

// QuoteJoin returns elements quoted and joined with ", ".
func QuoteJoin(items []string) string {
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, fmt.Sprintf("%q", strings.TrimSpace(s)))
	}
	return strings.Join(parts, ", ")
}
