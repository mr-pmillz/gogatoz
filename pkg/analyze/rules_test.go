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
		// CI_COMMIT_TAG is empty; "$CI_COMMIT_TAG =~ /v.*/" is false, so negation should be true
		if !EvaluateIf("!$CI_COMMIT_TAG =~ /v.*/", ctx) {
			t.Fatalf("expected negated predicate to be true")
		}
	})

	t.Run("and+or precedence (left-to-right)", func(t *testing.T) {
		// EvaluateIf implements simple OR-of-ANDs without parentheses.
		// This expression should be true because left disjunct becomes true.
		expr := "$CI_PIPELINE_SOURCE == \"merge_request_event\" && $CUSTOM == \"abc\" || $CUSTOM == \"nope\""
		if !EvaluateIf(expr, ctx) {
			t.Fatalf("expected complex expression to be true")
		}
	})
}

func TestRulesRunInContext_ArrayAndMap(t *testing.T) {
	ctxMR := map[string]string{"CI_PIPELINE_SOURCE": "merge_request_event"}
	ctxPush := map[string]string{"CI_PIPELINE_SOURCE": "push"}

	// Array form with two rules; first doesn't match, second matches
	rulesArr := []any{
		map[string]any{"if": "$CI_PIPELINE_SOURCE == \"push\"", "when": "on_success"},
		map[string]any{"if": "$CI_PIPELINE_SOURCE == \"merge_request_event\"", "when": "on_success"},
	}
	if !rulesRunInContext(rulesArr, ctxMR) {
		t.Fatalf("expected rules array to match MR context")
	}
	if rulesRunInContext(rulesArr, ctxPush) == false {
		// For push context, first rule matches; should be true
		// This assert ensures both contexts work
		t.Fatalf("expected rules array to match push context")
	}

	// Single map rule
	ruleMap := map[string]any{"if": "$CI_PIPELINE_SOURCE == \"push\"", "when": "on_success"}
	if !rulesRunInContext(ruleMap, ctxPush) {
		t.Fatalf("expected single rule map to match push context")
	}

	// When: never should negate a matching rule
	rulesNever := []any{
		map[string]any{"if": "$CI_PIPELINE_SOURCE == \"merge_request_event\"", "when": "never"},
	}
	if rulesRunInContext(rulesNever, ctxMR) {
		t.Fatalf("expected when: never rule not to run")
	}
}

func TestSplitKeepOuter_DoesNotSplitInsideQuotesOrRegex(t *testing.T) {
	in := "a == \"x||y\" && $VAR =~ /foo||bar/ || b == 'z&&w'"
	parts := splitKeepOuter(in, "||")
	if len(parts) != 2 {
		t.Fatalf("expected 2 top-level OR parts, got %d: %#v", len(parts), parts)
	}
	left := parts[0]
	andParts := splitKeepOuter(left, "&&")
	if len(andParts) != 2 {
		t.Fatalf("expected 2 top-level AND parts on left, got %d: %#v", len(andParts), andParts)
	}
}
