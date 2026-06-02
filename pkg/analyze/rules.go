package analyze

import (
	"regexp"
	"strings"
)

// EvaluateIf evaluates a minimal subset of GitLab rules:if expressions against a context of CI_* variables.
// Supported:
// - Equality / inequality: $VAR == "value", $VAR != "value"
// - Regex match / not match: $VAR =~ /regex/, $VAR !~ /regex/
// - Boolean ops: &&, ||, unary ! on a predicate
// Strings may be single or double quoted. Variable references may be quoted or unquoted.
// This is not a full parser; it is intentionally small to support common patterns used in rules.
func EvaluateIf(expr string, ctx map[string]string) bool {
	e := strings.TrimSpace(expr)
	if e == "" {
		return false
	}
	// OR-split by ||
	for _, disj := range splitKeepOuter(e, "||") {
		if evalAnd(strings.TrimSpace(disj), ctx) {
			return true
		}
	}
	return false
}

func evalAnd(s string, ctx map[string]string) bool {
	// AND over parts separated by && (all must be true)
	parts := splitKeepOuter(s, "&&")
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		neg := false
		for strings.HasPrefix(p, "!") { // allow multiple !
			neg = !neg
			p = strings.TrimSpace(strings.TrimPrefix(p, "!"))
		}
		ok := evalPred(p, ctx)
		if neg {
			ok = !ok
		}
		if !ok {
			return false
		}
	}
	return true
}

func evalPred(p string, ctx map[string]string) bool {
	// Try operators in order of complexity
	if i := strings.Index(p, "=~"); i >= 0 {
		lhs := strings.TrimSpace(p[:i])
		rhs := strings.TrimSpace(p[i+2:])
		val := resolveToken(lhs, ctx)
		pat := extractRegex(rhs)
		if pat == "" {
			return false
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false
		}
		return re.MatchString(val)
	}
	if i := strings.Index(p, "!~"); i >= 0 {
		lhs := strings.TrimSpace(p[:i])
		rhs := strings.TrimSpace(p[i+2:])
		val := resolveToken(lhs, ctx)
		pat := extractRegex(rhs)
		if pat == "" {
			return false
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false
		}
		return !re.MatchString(val)
	}
	if i := strings.Index(p, "=="); i >= 0 {
		lhs := strings.TrimSpace(p[:i])
		rhs := strings.TrimSpace(p[i+2:])
		lv := resolveToken(lhs, ctx)
		rv := unquote(strings.TrimSpace(rhs))
		return lv == rv
	}
	if i := strings.Index(p, "!="); i >= 0 {
		lhs := strings.TrimSpace(p[:i])
		rhs := strings.TrimSpace(p[i+2:])
		lv := resolveToken(lhs, ctx)
		rv := unquote(strings.TrimSpace(rhs))
		return lv != rv
	}
	return false
}

// resolveToken resolves a token that may be a variable reference like $VAR or quoted '$VAR'.
func resolveToken(tok string, ctx map[string]string) string {
	s := strings.TrimSpace(tok)
	s = unquote(s)
	if strings.HasPrefix(s, "$") {
		k := strings.TrimPrefix(s, "$")
		k = strings.Trim(k, "{}")
		return ctx[k]
	}
	return s
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// extractRegex extracts the pattern between /.../ from a token; returns empty string if not found.
func extractRegex(s string) string {
	st := strings.Index(s, "/")
	if st < 0 {
		return ""
	}
	en := strings.LastIndex(s, "/")
	if en <= st {
		return ""
	}
	return s[st+1 : en]
}

// splitKeepOuter splits by sep at top-level (not inside quotes or regex /.../), best-effort for simple cases.
func splitKeepOuter(s, sep string) []string {
	var out []string
	q := byte(0)
	re := false // in regex literal between /.../
	for i := 0; i < len(s); {
		if q == 0 && !re && strings.HasPrefix(s[i:], sep) {
			out = append(out, s[:i])
			s = s[i+len(sep):]
			i = 0
			continue
		}
		c := s[i]
		if re {
			if c == '/' {
				re = false
			}
			i++
			continue
		}
		if q != 0 {
			if c == q {
				q = 0
			}
			i++
			continue
		}
		if c == '\'' || c == '"' {
			q = c
			i++
			continue
		}
		if c == '/' {
			re = true
			i++
			continue
		}
		i++
	}
	out = append(out, s)
	return out
}

// rulesRunInContext evaluates a rules block (array or map) against a variable context.
// Returns true if at least one rule entry matches and is not when: never.
func rulesRunInContext(rules any, ctx map[string]string) bool {
	switch t := rules.(type) {
	case []any:
		for _, it := range t {
			if m, ok := it.(map[string]any); ok {
				ifVal, _ := m["if"].(string)
				whenVal, _ := m["when"].(string)
				if strings.TrimSpace(ifVal) == "" {
					continue
				}
				if EvaluateIf(ifVal, ctx) {
					if strings.EqualFold(strings.TrimSpace(whenVal), "never") {
						continue
					}
					return true
				}
			}
		}
	case map[string]any:
		// single rule map
		ifVal, _ := t["if"].(string)
		whenVal, _ := t["when"].(string)
		if strings.TrimSpace(ifVal) != "" && EvaluateIf(ifVal, ctx) {
			return !strings.EqualFold(strings.TrimSpace(whenVal), "never")
		}
	}
	return false
}
