package secretsdump

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestListProjectVariables_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/variables", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{
			{"key": "DB_HOST", "value": "localhost", "masked": false, "protected": false, "environment_scope": "*"},
			{"key": "DB_PASS", "value": "secret", "masked": true, "protected": true, "environment_scope": "production"},
			{"key": "API_TOKEN", "value": "tok123", "masked": false, "protected": false, "environment_scope": "*"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	t.Run("include_protected_true", func(t *testing.T) {
		vars, err := ListProjectVariables(context.Background(), cl, "1", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vars) != 3 {
			t.Fatalf("expected 3 variables with includeProtected=true, got %d", len(vars))
		}
	})

	t.Run("include_protected_false", func(t *testing.T) {
		vars, err := ListProjectVariables(context.Background(), cl, "1", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// DB_PASS is protected, should be excluded
		if len(vars) != 2 {
			t.Fatalf("expected 2 variables with includeProtected=false, got %d", len(vars))
		}
		for _, v := range vars {
			if v.Protected {
				t.Fatalf("expected no protected variables, but found %s", v.Key)
			}
		}
	})
}

func TestListProjectVariables_FieldMapping(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/variables", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{
			{"key": "MY_VAR", "value": "myval", "masked": true, "protected": false, "environment_scope": "staging"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	vars, err := ListProjectVariables(context.Background(), cl, "1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 1 {
		t.Fatalf("expected 1 variable, got %d", len(vars))
	}
	v := vars[0]
	if v.Key != "MY_VAR" {
		t.Fatalf("expected key=MY_VAR, got %s", v.Key)
	}
	if v.Value != "myval" {
		t.Fatalf("expected value=myval, got %s", v.Value)
	}
	if !v.Masked {
		t.Fatal("expected masked=true")
	}
	if v.Protected {
		t.Fatal("expected protected=false")
	}
	if v.Scope != "staging" {
		t.Fatalf("expected scope=staging, got %s", v.Scope)
	}
}

func TestListProjectVariables_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/1/variables", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]any{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	vars, err := ListProjectVariables(context.Background(), cl, "1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 0 {
		t.Fatalf("expected 0 variables, got %d", len(vars))
	}
}

func TestListProjectVariables_NilClient(t *testing.T) {
	_, err := ListProjectVariables(context.Background(), nil, "1", true)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestListGroupVariables_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/groups/5/variables", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{
			{"key": "GROUP_KEY", "value": "gval", "masked": false, "protected": false, "environment_scope": "*"},
			{"key": "SECURE_KEY", "value": "sval", "masked": true, "protected": true, "environment_scope": "production"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	t.Run("include_protected_true", func(t *testing.T) {
		vars, err := ListGroupVariables(context.Background(), cl, "5", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vars) != 2 {
			t.Fatalf("expected 2 variables with includeProtected=true, got %d", len(vars))
		}
	})

	t.Run("include_protected_false", func(t *testing.T) {
		vars, err := ListGroupVariables(context.Background(), cl, "5", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vars) != 1 {
			t.Fatalf("expected 1 variable with includeProtected=false, got %d", len(vars))
		}
		if vars[0].Key != "GROUP_KEY" {
			t.Fatalf("expected GROUP_KEY, got %s", vars[0].Key)
		}
	})
}

func TestListGroupVariables_NilClient(t *testing.T) {
	_, err := ListGroupVariables(context.Background(), nil, "5", true)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}
