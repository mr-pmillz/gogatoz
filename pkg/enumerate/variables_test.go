package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestFetchProjectVariables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/1/variables" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "20")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "2")
			vars := []map[string]any{
				{"key": "DB_PASSWORD", "protected": true, "masked": true, "environment_scope": "*", "variable_type": "env_var"},
				{"key": "DEBUG_FLAG", "protected": false, "masked": false, "environment_scope": "*", "variable_type": "env_var"},
			}
			json.NewEncoder(w).Encode(vars)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	vars, err := FetchProjectVariables(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("FetchProjectVariables: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(vars))
	}
	if vars[0].Key != "DB_PASSWORD" || !vars[0].Protected || !vars[0].Masked {
		t.Errorf("var[0] mismatch: %+v", vars[0])
	}
	if vars[1].Key != "DEBUG_FLAG" || vars[1].Protected || vars[1].Masked {
		t.Errorf("var[1] mismatch: %+v", vars[1])
	}
	for _, v := range vars {
		if v.Source != "project" {
			t.Errorf("expected source=project, got %s", v.Source)
		}
	}
}

func TestFetchGroupVariables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/groups/10/variables" {
			w.Header().Set("X-Page", "1")
			w.Header().Set("X-Next-Page", "")
			w.Header().Set("X-Per-Page", "20")
			w.Header().Set("X-Total-Pages", "1")
			w.Header().Set("X-Total", "1")
			vars := []map[string]any{
				{"key": "GROUP_TOKEN", "protected": true, "masked": true, "environment_scope": "*", "variable_type": "env_var"},
			}
			json.NewEncoder(w).Encode(vars)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cl, err := gitlabx.New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("gitlabx.New: %v", err)
	}

	vars, err := FetchGroupVariables(context.Background(), cl, 10)
	if err != nil {
		t.Fatalf("FetchGroupVariables: %v", err)
	}
	if len(vars) != 1 {
		t.Fatalf("expected 1 var, got %d", len(vars))
	}
	if vars[0].Source != "group" {
		t.Errorf("expected source=group, got %s", vars[0].Source)
	}
}

func TestFetchProjectVariables_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Page", "1")
		w.Header().Set("X-Next-Page", "")
		w.Header().Set("X-Per-Page", "20")
		w.Header().Set("X-Total-Pages", "1")
		w.Header().Set("X-Total", "0")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	cl, _ := gitlabx.New(srv.URL, "tok")
	vars, err := FetchProjectVariables(context.Background(), cl, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 0 {
		t.Errorf("expected 0 vars, got %d", len(vars))
	}
}
