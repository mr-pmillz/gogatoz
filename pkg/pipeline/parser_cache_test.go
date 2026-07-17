package pipeline

import (
	"strings"
	"testing"
)

func TestParse_GlobalCacheFromDefault(t *testing.T) {
	yml := `
default:
  cache:
    key: global-key
    paths:
      - vendor/
    policy: pull-push

build:
  stage: build
  script: go build
`
	doc, err := Parse(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Cache) != 1 {
		t.Fatalf("expected 1 global cache config, got %d", len(doc.Cache))
	}
	if doc.Cache[0]["key"] != "global-key" {
		t.Fatalf("global cache key = %v, want global-key", doc.Cache[0]["key"])
	}
}

func TestParse_DeprecatedTopLevelCache(t *testing.T) {
	yml := `
cache:
  key: top-level
  paths:
    - .cache/

build:
  stage: build
  script: make build
`
	doc, err := Parse(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Cache) != 1 {
		t.Fatalf("expected 1 global cache from deprecated top-level, got %d", len(doc.Cache))
	}
	if doc.Cache[0]["key"] != "top-level" {
		t.Fatalf("cache key = %v, want top-level", doc.Cache[0]["key"])
	}
}

func TestParse_DefaultCacheTakesPrecedenceOverTopLevel(t *testing.T) {
	yml := `
cache:
  key: deprecated
  paths:
    - old/

default:
  cache:
    key: preferred
    paths:
      - new/

build:
  stage: build
  script: echo hi
`
	doc, err := Parse(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Cache) != 1 {
		t.Fatalf("expected 1 global cache, got %d", len(doc.Cache))
	}
	if doc.Cache[0]["key"] != "preferred" {
		t.Fatalf("expected default: cache to win, got key=%v", doc.Cache[0]["key"])
	}
}

func TestParse_JobCacheArray(t *testing.T) {
	yml := `
build:
  stage: build
  script: npm install
  cache:
    - key: npm
      paths:
        - node_modules/
      policy: pull
    - key: pip
      paths:
        - .cache/pip
      policy: push
`
	doc, err := Parse(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(doc.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(doc.Jobs))
	}
	j := doc.Jobs[0]
	if len(j.Caches) != 2 {
		t.Fatalf("expected 2 cache configs, got %d", len(j.Caches))
	}
	if j.Cache["key"] != "npm" {
		t.Fatalf("Cache (primary) should be first element, got key=%v", j.Cache["key"])
	}
	if j.Caches[1]["policy"] != "push" {
		t.Fatalf("second cache policy = %v, want push", j.Caches[1]["policy"])
	}
}

func TestParse_TopLevelCacheNotMisidentifiedAsJob(t *testing.T) {
	yml := `
cache:
  key: global
  paths:
    - vendor/

build:
  stage: build
  script: go build
`
	doc, err := Parse(strings.NewReader(yml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	for _, j := range doc.Jobs {
		if j.Name == "cache" {
			t.Fatalf("top-level cache: was misidentified as a job")
		}
	}
}
