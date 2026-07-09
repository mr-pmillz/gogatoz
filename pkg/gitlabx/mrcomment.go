package gitlabx

import (
	"context"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// ListMergeRequestNotes returns all notes on a merge request.
func (c *Client) ListMergeRequestNotes(ctx context.Context, projectID int64, mrIID int64) ([]*gitlab.Note, error) {
	opts := &gitlab.ListMergeRequestNotesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
		OrderBy:     new("created_at"),
		Sort:        new("asc"),
	}
	var all []*gitlab.Note
	for {
		notes, resp, err := c.GL.Notes.ListMergeRequestNotes(projectID, mrIID, opts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		all = append(all, notes...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// CreateMergeRequestNote creates a new note on a merge request.
func (c *Client) CreateMergeRequestNote(ctx context.Context, projectID int64, mrIID int64, body string) (*gitlab.Note, error) {
	note, _, err := c.GL.Notes.CreateMergeRequestNote(projectID, mrIID, &gitlab.CreateMergeRequestNoteOptions{
		Body: new(body),
	}, gitlab.WithContext(ctx))
	return note, err
}

// UpdateMergeRequestNote updates an existing note on a merge request.
func (c *Client) UpdateMergeRequestNote(ctx context.Context, projectID int64, mrIID int64, noteID int64, body string) (*gitlab.Note, error) {
	note, _, err := c.GL.Notes.UpdateMergeRequestNote(projectID, mrIID, noteID, &gitlab.UpdateMergeRequestNoteOptions{
		Body: new(body),
	}, gitlab.WithContext(ctx))
	return note, err
}
