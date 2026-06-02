package enumerate

import "testing"

const refMain = "main"

func TestDetermineRefs_DedupeAndCap(t *testing.T) {
	// no refs
	if r := determineRefs(Options{}); r != nil {
		t.Fatalf("expected nil when no refs, got %v", r)
	}
	// dedupe and preserve order, with cap
	opts := Options{Refs: []string{refMain, "prod", refMain, "v1.0"}, MaxRefs: 2}
	r := determineRefs(opts)
	if len(r) != 2 {
		t.Fatalf("expected 2 refs due to cap, got %d: %v", len(r), r)
	}
	if r[0] != refMain || r[1] != "prod" {
		t.Fatalf("unexpected order/content: %v", r)
	}
	// no cap
	opts2 := Options{Refs: []string{"a", "b", "a", "c"}, MaxRefs: 0}
	r2 := determineRefs(opts2)
	if len(r2) != 3 {
		t.Fatalf("expected 3 unique refs, got %d: %v", len(r2), r2)
	}
	if r2[0] != "a" || r2[1] != "b" || r2[2] != "c" {
		t.Fatalf("unexpected order/content: %v", r2)
	}
}
