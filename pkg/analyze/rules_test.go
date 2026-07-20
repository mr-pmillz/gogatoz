package analyze

import (
	"testing"
)

func TestEvaluateIf_Basics(t *testing.T) {
	ctx := map[string]string{
		"CI_PIPELINE_SOURCE": "merge_request_event",
		"CI_COMMIT_BRANCH":   "feature/foo",
		"CI_COMMIT_REF_NAME": "release/1.2.3",
		"CI_COMMIT_TAG":      "",
		"CUSTOM":             "abc",
	}

	t.Run("equality true", func(t *testing.T) {
		if !EvaluateIf("$CI_PIPELINE_SOURCE == \"merge_request_event\"", ctx) {
			t.Fatalf("expected equality to be true")
		}
	})

	t.Run("equality false", func(t *testing.T) {
		if EvaluateIf("$CI_PIPELINE_SOURCE == \"push\"", ctx) {
			t.Fatalf("expected equality to be false")
		}
	})

	t.Run("inequality true", func(t *testing.T) {
		if !EvaluateIf("$CI_COMMIT_BRANCH != \"main\"", ctx) {
			t.Fatalf("expected inequality to be true")
		}
	})

	t.Run("regex match true", func(t *testing.T) {
		if !EvaluateIf("$CI_COMMIT_REF_NAME =~ /release\\/.*/", ctx) {
			t.Fatalf("expected regex match to be true")
		}
	})

	t.Run("regex not match true via !~", func(t *testing.T) {
		if !EvaluateIf("$CI_COMMIT_BRANCH !~ /main|stable/", ctx) {
			t.Fatalf("expected regex not-match to be true")
		}
	})

	t.Run("negation of predicate", func(t *testing.T) {
		if !EvaluateIf("!$CI_COMMIT_TAG =~ /v.*/", ctx) {
			t.Fatalf("expected negated predicate to be true")
		}
	})

	t.Run("and+or precedence", func(t *testing.T) {
		expr := "$CI_PIPELINE_SOURCE == \"merge_request_event\" && $CUSTOM == \"abc\" || $CUSTOM == \"nope\""
		if !EvaluateIf(expr, ctx) {
			t.Fatalf("expected complex expression to be true")
		}
	})
}

func TestEvaluateIf_Parentheses(t *testing.T) {
	ctx := map[string]string{
		"CI_COMMIT_BRANCH":   "main",
		"CI_PIPELINE_SOURCE": "merge_request_event",
		"MY_VARIABLE":        "yes",
		"EMPTY":              "",
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "simple parens",
			expr: `($CI_COMMIT_BRANCH == "main")`,
			want: true,
		},
		{
			name: "parens change precedence — without parens false",
			expr: `$EMPTY && ($CI_COMMIT_BRANCH == "main" || $CI_PIPELINE_SOURCE == "push")`,
			want: false,
		},
		{
			name: "parens change precedence — or group",
			expr: `($CI_COMMIT_BRANCH == "main" || $CI_COMMIT_BRANCH == "develop") && $MY_VARIABLE`,
			want: true,
		},
		{
			name: "nested parens",
			expr: `(($CI_COMMIT_BRANCH == "main" || $CI_COMMIT_BRANCH == "develop") && $MY_VARIABLE)`,
			want: true,
		},
		{
			name: "negated parens group",
			expr: `!($CI_COMMIT_BRANCH == "develop")`,
			want: true,
		},
		{
			name: "negated parens group true becomes false",
			expr: `!($CI_COMMIT_BRANCH == "main")`,
			want: false,
		},
		{
			name: "complex from GitLab docs",
			expr: `($CI_COMMIT_BRANCH == "main" || $CI_COMMIT_BRANCH == "develop") && $MY_VARIABLE`,
			want: true,
		},
		{
			name: "real-world triple parens",
			expr: `$CI_COMMIT_BRANCH == "main" || (($MY_VARIABLE == "yes" || $EMPTY == "thing") && $CI_PIPELINE_SOURCE)`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateIf(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("EvaluateIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvaluateIf_Truthiness(t *testing.T) {
	ctx := map[string]string{
		"DEFINED":   "value",
		"EMPTY":     "",
		"ZERO":      "0",
		"FALSE_STR": "false",
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"defined var is truthy", "$DEFINED", true},
		{"empty var is falsy", "$EMPTY", false},
		{"undefined var is falsy", "$UNDEFINED", false},
		{"zero string is truthy", "$ZERO", true},
		{"false string is truthy", "$FALSE_STR", true},
		{"negated defined is false", "!$DEFINED", false},
		{"negated empty is true", "!$EMPTY", true},
		{"negated undefined is true", "!$UNDEFINED", true},
		{"double negation", "!!$DEFINED", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateIf(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("EvaluateIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvaluateIf_Null(t *testing.T) {
	ctx := map[string]string{
		"DEFINED": "value",
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"defined == null is false", `$DEFINED == null`, false},
		{"undefined == null is true", `$UNDEFINED == null`, true},
		{"defined != null is true", `$DEFINED != null`, true},
		{"undefined != null is false", `$UNDEFINED != null`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateIf(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("EvaluateIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvaluateIf_VariableToVariable(t *testing.T) {
	ctx := map[string]string{
		"CI_COMMIT_BRANCH":  "main",
		"CI_DEFAULT_BRANCH": "main",
		"OTHER_BRANCH":      "develop",
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"same value", `$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`, true},
		{"different value", `$CI_COMMIT_BRANCH == $OTHER_BRANCH`, false},
		{"not equal different", `$CI_COMMIT_BRANCH != $OTHER_BRANCH`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateIf(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("EvaluateIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvaluateIf_CaseInsensitiveRegex(t *testing.T) {
	ctx := map[string]string{
		"BRANCH": "Feature/MyFeature",
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"case sensitive no match", `$BRANCH =~ /feature\/.*/`, false},
		{"case insensitive match", `$BRANCH =~ /feature\/.*/i`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateIf(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("EvaluateIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvaluateIf_EmptyAndEdgeCases(t *testing.T) {
	ctx := map[string]string{}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"compare to empty string", `$UNDEFINED == ""`, true},
		{"compare to non-empty string", `$UNDEFINED == "something"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateIf(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("EvaluateIf(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvaluateIf_BraceVariables(t *testing.T) {
	ctx := map[string]string{
		"MY_VAR": "hello",
	}
	if !EvaluateIf(`${MY_VAR} == "hello"`, ctx) {
		t.Error("expected ${MY_VAR} to resolve")
	}
}

func TestRulesRunInContext_ArrayAndMap(t *testing.T) {
	ctxMR := map[string]string{"CI_PIPELINE_SOURCE": "merge_request_event"}
	ctxPush := map[string]string{"CI_PIPELINE_SOURCE": "push"}

	rulesArr := []any{
		map[string]any{"if": "$CI_PIPELINE_SOURCE == \"push\"", "when": "on_success"},
		map[string]any{"if": "$CI_PIPELINE_SOURCE == \"merge_request_event\"", "when": "on_success"},
	}
	if !rulesRunInContext(rulesArr, ctxMR) {
		t.Fatalf("expected rules array to match MR context")
	}
	if !rulesRunInContext(rulesArr, ctxPush) {
		t.Fatalf("expected rules array to match push context")
	}

	ruleMap := map[string]any{"if": "$CI_PIPELINE_SOURCE == \"push\"", "when": "on_success"}
	if !rulesRunInContext(ruleMap, ctxPush) {
		t.Fatalf("expected single rule map to match push context")
	}

	rulesNever := []any{
		map[string]any{"if": "$CI_PIPELINE_SOURCE == \"merge_request_event\"", "when": "never"},
	}
	if rulesRunInContext(rulesNever, ctxMR) {
		t.Fatalf("expected when: never rule not to run")
	}
}

func TestLex_TokenTypes(t *testing.T) {
	tokens := lex(`$VAR == "hello" && $OTHER =~ /pat/ || !($X != null)`)
	kinds := make([]tokenKind, len(tokens))
	for i, tok := range tokens {
		kinds[i] = tok.kind
	}
	expected := []tokenKind{
		tokVariable, tokEq, tokString, tokAnd,
		tokVariable, tokMatch, tokRegex, tokOr,
		tokNot, tokLParen, tokVariable, tokNeq, tokNull, tokRParen,
		tokEOF,
	}
	if len(kinds) != len(expected) {
		t.Fatalf("token count: got %d, want %d\ntokens: %v", len(kinds), len(expected), tokens)
	}
	for i := range expected {
		if kinds[i] != expected[i] {
			t.Errorf("token[%d]: got kind %d, want %d (val=%q)", i, kinds[i], expected[i], tokens[i].val)
		}
	}
}
