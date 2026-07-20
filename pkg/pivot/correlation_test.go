package pivot

import "testing"

func TestCorrelateCredentials_SharedToken(t *testing.T) {
	store := NewCredentialStore()
	store.Add(&Credential{Token: "glpat-abc123def456ghij", TokenHash: "hash1", TokenType: "pat"})
	store.RecordTokenProject("hash1", 100)
	store.RecordTokenProject("hash1", 200)
	store.RecordTokenProject("hash1", 300)

	corrs := CorrelateCredentials(store)
	if len(corrs) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(corrs))
	}
	if corrs[0].SharedCount != 3 {
		t.Fatalf("expected shared count 3, got %d", corrs[0].SharedCount)
	}
	if corrs[0].TokenType != "pat" {
		t.Fatalf("expected token type pat, got %s", corrs[0].TokenType)
	}
}

func TestCorrelateCredentials_SingleProject(t *testing.T) {
	store := NewCredentialStore()
	store.Add(&Credential{Token: "glpat-abc123def456ghij", TokenHash: "hash1", TokenType: "pat"})
	store.RecordTokenProject("hash1", 100)

	corrs := CorrelateCredentials(store)
	if len(corrs) != 0 {
		t.Fatalf("expected no correlations for single project, got %d", len(corrs))
	}
}

func TestCorrelateCredentials_Empty(t *testing.T) {
	store := NewCredentialStore()
	corrs := CorrelateCredentials(store)
	if len(corrs) != 0 {
		t.Fatalf("expected no correlations for empty store, got %d", len(corrs))
	}
}

func TestCorrelateCredentials_Nil(t *testing.T) {
	corrs := CorrelateCredentials(nil)
	if corrs != nil {
		t.Fatalf("expected nil for nil store, got %v", corrs)
	}
}
