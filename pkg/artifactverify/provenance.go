package artifactverify

import (
	"context"
	"errors"
	"net/http"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const (
	ProvenanceMismatchID = "PROVENANCE_MISMATCH"
	ReleaseTagMismatchID = "RELEASE_TAG_MISMATCH"
)

// ProvenanceSummary records the source identity extracted from an attestation.
type ProvenanceSummary struct {
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Pipeline   string `json:"pipeline,omitempty"`
}

type provenanceExpectations struct {
	repository string
	commit     string
	ref        string
	pipeline   string
}

func inspectProvenance(
	_ context.Context,
	_ string,
	_ provenanceExpectations,
	_ int64,
	_ *http.Client,
) (*ProvenanceSummary, []analyze.Finding, error) {
	return nil, nil, errors.New("provenance inspection is not implemented")
}

func releaseTagFindings(_ []FileRecord, _ string) []analyze.Finding {
	return nil
}
