package pathutil

import (
	"fmt"
	"regexp"
	"strings"
)

// GlobToRegex compiles a simple glob pattern into a regexp:
//   - *  matches any sequence of characters except '/'
//   - ** matches any sequence of characters including '/'
//   - ?  matches any single character except '/'
//
// The resulting regex is anchored to match the entire string.
func GlobToRegex(glob string) (*regexp.Regexp, error) {
	g := strings.TrimSpace(glob)
	if g == "" {
		return nil, fmt.Errorf("empty glob pattern")
	}
	// Escape regex meta characters first
	esc := regexp.QuoteMeta(g)
	// Preserve our glob tokens by marking them before translation
	esc = strings.ReplaceAll(esc, "\\*\\*", "__GLOBSTAR__")
	esc = strings.ReplaceAll(esc, "\\*", "__GLOB__")
	esc = strings.ReplaceAll(esc, "\\?", "__ONE__")
	// Translate tokens to regex fragments
	// Special-case a globstar followed by a slash to allow zero or more directories,
	// so patterns like "**/*.yml" also match files in the root directory.
	esc = strings.ReplaceAll(esc, "__GLOBSTAR__/", "(?:.*/)?")
	// Remaining globstars match across '/'
	esc = strings.ReplaceAll(esc, "__GLOBSTAR__", ".*") // crosses '/'
	esc = strings.ReplaceAll(esc, "__GLOB__", "[^/]*")  // not across '/'
	esc = strings.ReplaceAll(esc, "__ONE__", "[^/]")    // single non '/'
	pat := "^" + esc + "$"
	return regexp.Compile(pat)
}
