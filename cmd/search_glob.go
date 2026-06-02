package cmd

import (
	"regexp"

	"github.com/mr-pmillz/gogatoz/pkg/pathutil"
)

// globToRegex compiles a simple glob pattern into a regexp:
//   - *  matches any sequence of characters except '/'
//   - ** matches any sequence of characters including '/'
//   - ?  matches any single character except '/'
//
// The resulting regex is anchored to match the entire string.
func globToRegex(glob string) (*regexp.Regexp, error) {
	return pathutil.GlobToRegex(glob)
}
