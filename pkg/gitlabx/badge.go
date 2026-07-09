package gitlabx

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const badgeName = "GoGatoZ"

// ListProjectBadges returns all badges for a project.
func (c *Client) ListProjectBadges(ctx context.Context, projectID int64) ([]*gitlab.ProjectBadge, error) {
	badges, _, err := c.GL.ProjectBadges.ListProjectBadges(projectID, nil, gitlab.WithContext(ctx))
	return badges, err
}

// UpsertComplianceBadge creates or updates the GoGatoZ compliance badge on a project.
func (c *Client) UpsertComplianceBadge(ctx context.Context, projectID int64, score string, linkURL string) error {
	imageURL := ScoreBadgeURL(score)

	badges, err := c.ListProjectBadges(ctx, projectID)
	if err != nil {
		return fmt.Errorf("list badges: %w", err)
	}

	var existingID *int64
	for _, b := range badges {
		if b.Name == badgeName {
			id := b.ID
			existingID = &id
			break
		}
		if existingID == nil && strings.Contains(b.ImageURL, "shields.io") && strings.Contains(b.ImageURL, "GoGatoZ") {
			id := b.ID
			existingID = &id
		}
	}

	if existingID != nil {
		_, _, err = c.GL.ProjectBadges.EditProjectBadge(projectID, *existingID, &gitlab.EditProjectBadgeOptions{
			LinkURL:  new(linkURL),
			ImageURL: new(imageURL),
			Name:     new(badgeName),
		}, gitlab.WithContext(ctx))
		return err
	}

	_, _, err = c.GL.ProjectBadges.AddProjectBadge(projectID, &gitlab.AddProjectBadgeOptions{
		LinkURL:  new(linkURL),
		ImageURL: new(imageURL),
		Name:     new(badgeName),
	}, gitlab.WithContext(ctx))
	return err
}

// ScoreBadgeURL returns a shields.io badge URL for the given letter score.
func ScoreBadgeURL(score string) string {
	color := "lightgrey"
	switch strings.ToUpper(score) {
	case "A":
		color = "brightgreen"
	case "B":
		color = "green"
	case "C":
		color = "yellow"
	case "D":
		color = "orange"
	case "E":
		color = "red"
	}
	return fmt.Sprintf("https://img.shields.io/badge/GoGatoZ-%s-%s", url.PathEscape(score), color)
}
