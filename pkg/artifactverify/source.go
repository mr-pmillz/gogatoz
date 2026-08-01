package artifactverify

import (
	"context"
	"errors"
	"net/http"

	"github.com/mr-pmillz/gogatoz/pkg/analyze"
)

const (
	SourceDivergenceID = "ARTIFACT_SOURCE_DIVERGENCE"
	PartialBuildID     = "ARTIFACT_PARTIAL_BUILD"
)

func inspectSource(_ context.Context, _ string, _ Limits, _ *http.Client) (archiveReport, error) {
	return archiveReport{}, errors.New("source inspection is not implemented")
}

func compareSource(_ []FileRecord, _ []FileRecord, _, _ int64) []analyze.Finding {
	return nil
}
