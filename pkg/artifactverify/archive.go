package artifactverify

import "errors"

type archiveReport struct {
	format        string
	files         []FileRecord
	expandedBytes int64
}

func inspectArchive(_ []byte, _ string, _ Limits) (archiveReport, error) {
	return archiveReport{}, errors.New("archive inspection is not implemented")
}
