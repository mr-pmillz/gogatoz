package analyze

import (
	"regexp"
	"strings"
	"unicode"
)

// ────────────────────────────────────────────────────────────────────────────
// Token types for the lexer
// ────────────────────────────────────────────────────────────────────────────

type tokenKind int

const (
	tokEOF      tokenKind = iota
	tokVariable           // $VAR, ${VAR}
	tokString             // "..." or '...'
	tokRegex              // /pattern/ or /pattern/i
	tokNull               // null keyword
	tokEq                 // ==
	tokNeq                // !=
	tokMatch              // =~
	tokNotMatch           // !~
	tokAnd                // &&
	tokOr                 // ||
	tokNot                // !
	tokLParen             // (
	tokRParen             // )
)

type token struct {
	kind tokenKind
	val  string
}

// ────────────────────────────────────────────────────────────────────────────
// Lexer — split into per-class scan helpers to stay under gocognit 30
// ────────────────────────────────────────────────────────────────────────────

func lex(input string) []token {
	var tokens []token
	i := 0
	for i < len(input) {
		c := input[i]

		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}

		if tok, n := lexOperatorOrParen(input, i); n > 0 {
			tokens = append(tokens, tok)
			i += n
			continue
		}

		if c == '"' || c == '\'' {
			tok, end := lexString(input, i)
			tokens = append(tokens, tok)
			i = end
			continue
		}

		if c == '/' {
			tok, end := lexRegex(input, i)
			tokens = append(tokens, tok)
			i = end
			continue
		}

		if c == '$' {
			tok, end := lexVariable(input, i)
			tokens = append(tokens, tok)
			i = end
			continue
		}

		if isWordStart(c) {
			tok, end := lexWord(input, i)
			tokens = append(tokens, tok)
			i = end
			continue
		}

		i++
	}
	tokens = append(tokens, token{tokEOF, ""})
	return tokens
}

func lexOperatorOrParen(input string, i int) (token, int) {
	c := input[i]
	switch c {
	case '(':
		return token{tokLParen, "("}, 1
	case ')':
		return token{tokRParen, ")"}, 1
	case '&':
		if i+1 < len(input) && input[i+1] == '&' {
			return token{tokAnd, "&&"}, 2
		}
	case '|':
		if i+1 < len(input) && input[i+1] == '|' {
			return token{tokOr, "||"}, 2
		}
	case '=':
		if i+1 < len(input) {
			if input[i+1] == '=' {
				return token{tokEq, "=="}, 2
			}
			if input[i+1] == '~' {
				return token{tokMatch, "=~"}, 2
			}
		}
	case '!':
		if i+1 < len(input) && input[i+1] == '=' {
			return token{tokNeq, "!="}, 2
		}
		if i+1 < len(input) && input[i+1] == '~' {
			return token{tokNotMatch, "!~"}, 2
		}
		return token{tokNot, "!"}, 1
	}
	return token{}, 0
}

func lexString(input string, i int) (token, int) {
	quote := input[i]
	end := i + 1
	for end < len(input) && input[end] != quote {
		if input[end] == '\\' {
			end++
		}
		end++
	}
	if end < len(input) {
		end++
	}
	return token{tokString, input[i:end]}, end
}

func lexRegex(input string, i int) (token, int) {
	end := i + 1
	for end < len(input) && input[end] != '/' {
		if input[end] == '\\' {
			end++
		}
		end++
	}
	if end < len(input) {
		end++
	}
	for end < len(input) && (input[end] == 'i' || input[end] == 'g' || input[end] == 'm') {
		end++
	}
	return token{tokRegex, input[i:end]}, end
}

func lexVariable(input string, i int) (token, int) {
	end := i + 1
	if end < len(input) && input[end] == '{' {
		close := strings.IndexByte(input[end:], '}')
		if close >= 0 {
			end += close + 1
		}
	} else {
		for end < len(input) && isVarChar(input[end]) {
			end++
		}
	}
	return token{tokVariable, input[i:end]}, end
}

func lexWord(input string, i int) (token, int) {
	end := i + 1
	for end < len(input) && isVarChar(input[end]) {
		end++
	}
	word := input[i:end]
	if word == "null" {
		return token{tokNull, word}, end
	}
	return token{tokString, word}, end
}

func isVarChar(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isWordStart(c byte) bool {
	return unicode.IsLetter(rune(c)) || c == '_'
}

// ────────────────────────────────────────────────────────────────────────────
// Recursive Descent Parser + Evaluator
// ────────────────────────────────────────────────────────────────────────────
//
// Grammar (GitLab rules:if expressions):
//
//   expr       → or_expr
//   or_expr    → and_expr ( '||' and_expr )*
//   and_expr   → not_expr ( '&&' not_expr )*
//   not_expr   → '!' not_expr | primary
//   primary    → '(' expr ')' | comparison
//   comparison → atom ( ('==' | '!=' | '=~' | '!~') atom )?
//   atom       → VARIABLE | STRING | REGEX | NULL

type parser struct {
	tokens []token
	pos    int
	ctx    map[string]string
}

func (p *parser) peek() token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return token{tokEOF, ""}
}

func (p *parser) advance() token {
	t := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

func (p *parser) expect(k tokenKind) token {
	t := p.advance()
	if t.kind != k {
		return token{tokEOF, ""}
	}
	return t
}

// EvaluateIf evaluates a GitLab rules:if expression against a context of
// CI/CD variables. Supports the full expression syntax: ==, !=, =~, !~,
// &&, ||, !, parentheses, null keyword, and variable truthiness checks.
func EvaluateIf(expr string, ctx map[string]string) bool {
	e := strings.TrimSpace(expr)
	if e == "" {
		return false
	}
	tokens := lex(e)
	p := &parser{tokens: tokens, ctx: ctx}
	return p.parseOrExpr()
}

func (p *parser) parseOrExpr() bool {
	result := p.parseAndExpr()
	for p.peek().kind == tokOr {
		p.advance()
		rhs := p.parseAndExpr()
		result = result || rhs
	}
	return result
}

func (p *parser) parseAndExpr() bool {
	result := p.parseNotExpr()
	for p.peek().kind == tokAnd {
		p.advance()
		rhs := p.parseNotExpr()
		result = result && rhs
	}
	return result
}

func (p *parser) parseNotExpr() bool {
	if p.peek().kind == tokNot {
		p.advance()
		return !p.parseNotExpr()
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() bool {
	if p.peek().kind == tokLParen {
		p.advance()
		result := p.parseOrExpr()
		p.expect(tokRParen)
		return result
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() bool {
	lhs := p.parseAtom()

	switch p.peek().kind {
	case tokEq:
		p.advance()
		rhs := p.parseAtom()
		return lhs.strVal == rhs.strVal
	case tokNeq:
		p.advance()
		rhs := p.parseAtom()
		return lhs.strVal != rhs.strVal
	case tokMatch:
		p.advance()
		rhs := p.parseAtom()
		return regexMatch(lhs.strVal, rhs.strVal)
	case tokNotMatch:
		p.advance()
		rhs := p.parseAtom()
		return !regexMatch(lhs.strVal, rhs.strVal)
	default:
		return lhs.truthy
	}
}

type atomVal struct {
	strVal string
	truthy bool
}

func (p *parser) parseAtom() atomVal {
	t := p.advance()
	switch t.kind {
	case tokVariable:
		name := extractVarName(t.val)
		val, defined := p.ctx[name]
		return atomVal{strVal: val, truthy: defined && val != ""}
	case tokString:
		s := unquote(t.val)
		return atomVal{strVal: s, truthy: s != ""}
	case tokRegex:
		return atomVal{strVal: t.val, truthy: true}
	case tokNull:
		return atomVal{strVal: "", truthy: false}
	default:
		return atomVal{strVal: "", truthy: false}
	}
}

func extractVarName(tok string) string {
	s := strings.TrimPrefix(tok, "$")
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return s
}

func regexMatch(value, pattern string) bool {
	pat := extractRegex(pattern)
	if pat == "" {
		return false
	}
	flags := ""
	if strings.HasSuffix(pattern, "i") {
		closing := strings.LastIndex(pattern[:len(pattern)-1], "/")
		if closing >= 0 {
			flags = "(?i)"
		}
	}
	re, err := regexp.Compile(flags + pat)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// extractRegex extracts the pattern between /.../ from a token.
func extractRegex(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '/' {
		return ""
	}
	end := len(s) - 1
	for end > 0 && s[end] != '/' {
		end--
	}
	if end <= 0 {
		return ""
	}
	return s[1:end]
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
		ifVal, _ := t["if"].(string)
		whenVal, _ := t["when"].(string)
		if strings.TrimSpace(ifVal) != "" && EvaluateIf(ifVal, ctx) {
			return !strings.EqualFold(strings.TrimSpace(whenVal), "never")
		}
	}
	return false
}
