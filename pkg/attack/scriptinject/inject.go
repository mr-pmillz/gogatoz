package scriptinject

import (
	"strings"
)

// PrependPayload inserts the payload at the top of the script content,
// preserving the shebang line if present.
func PrependPayload(original, payload string) string {
	original = strings.TrimSpace(original)
	if original == "" {
		return payload + "\n"
	}
	lines := strings.SplitN(original, "\n", 2)
	if strings.HasPrefix(lines[0], "#!") {
		// Insert after shebang
		rest := ""
		if len(lines) > 1 {
			rest = lines[1]
		}
		return lines[0] + "\n" + payload + "\n" + rest + "\n"
	}
	return payload + "\n" + original + "\n"
}

// AppendPayload adds the payload at the end of the script content.
func AppendPayload(original, payload string) string {
	s := strings.TrimRight(original, "\n")
	return s + "\n" + payload + "\n"
}
