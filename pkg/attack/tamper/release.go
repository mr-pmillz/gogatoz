package tamper

import (
	"context"
	"fmt"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// ReleaseInfo captures release metadata for reporting.
type ReleaseInfo struct {
	TagName     string     `json:"tag_name"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Links       []LinkInfo `json:"links"`
}

// LinkInfo captures a release asset link.
type LinkInfo struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ListReleases returns all releases for a project.
func ListReleases(ctx context.Context, client *gitlabx.Client, projectID any) ([]ReleaseInfo, error) {
	var result []ReleaseInfo
	opt := &gitlab.ListReleasesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 20},
	}
	for {
		releases, resp, err := client.GL.Releases.ListReleases(projectID, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("list releases: %w", err)
		}
		for _, r := range releases {
			ri := ReleaseInfo{
				TagName:     r.TagName,
				Name:        r.Name,
				Description: r.Description,
			}
			result = append(result, ri)
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return result, nil
}

// ListReleaseLinks returns all asset links for a release.
func ListReleaseLinks(ctx context.Context, client *gitlabx.Client, projectID any, tagName string) ([]LinkInfo, error) {
	var result []LinkInfo
	opt := &gitlab.ListReleaseLinksOptions{
		ListOptions: gitlab.ListOptions{PerPage: 20},
	}
	for {
		links, resp, err := client.GL.ReleaseLinks.ListReleaseLinks(projectID, tagName, opt, gitlab.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("list release links: %w", err)
		}
		for _, l := range links {
			result = append(result, LinkInfo{ID: l.ID, Name: l.Name, URL: l.URL})
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return result, nil
}

// TamperReleaseOptions configures release tampering.
type TamperReleaseOptions struct {
	NewName        string            // update release name
	NewDescription string            // update release description
	ReplaceLinks   map[string]string // map of link name -> new URL (replaces existing links with matching names)
	AddLinks       map[string]string // map of link name -> URL to add
}

// TamperRelease modifies a release's metadata and/or replaces asset links.
// Returns the number of links replaced and added.
func TamperRelease(ctx context.Context, client *gitlabx.Client, projectID any, tagName string, opts TamperReleaseOptions) (replaced, added int, err error) {
	// Update release metadata if requested.
	if opts.NewName != "" || opts.NewDescription != "" {
		updateOpts := &gitlab.UpdateReleaseOptions{}
		if opts.NewName != "" {
			updateOpts.Name = gitlab.Ptr(opts.NewName)
		}
		if opts.NewDescription != "" {
			updateOpts.Description = gitlab.Ptr(opts.NewDescription)
		}
		_, _, err = client.GL.Releases.UpdateRelease(projectID, tagName, updateOpts, gitlab.WithContext(ctx))
		if err != nil {
			return 0, 0, fmt.Errorf("update release: %w", err)
		}
	}

	// Replace existing links by name.
	if len(opts.ReplaceLinks) > 0 {
		links, lerr := ListReleaseLinks(ctx, client, projectID, tagName)
		if lerr != nil {
			return 0, 0, fmt.Errorf("list links for replacement: %w", lerr)
		}
		for _, link := range links {
			newURL, ok := opts.ReplaceLinks[link.Name]
			if !ok {
				continue
			}
			// Delete old link.
			_, _, derr := client.GL.ReleaseLinks.DeleteReleaseLink(projectID, tagName, link.ID, gitlab.WithContext(ctx))
			if derr != nil {
				return replaced, added, fmt.Errorf("delete link %q: %w", link.Name, derr)
			}
			// Create replacement with same name.
			_, _, cerr := client.GL.ReleaseLinks.CreateReleaseLink(projectID, tagName, &gitlab.CreateReleaseLinkOptions{
				Name: gitlab.Ptr(link.Name),
				URL:  gitlab.Ptr(newURL),
			}, gitlab.WithContext(ctx))
			if cerr != nil {
				return replaced, added, fmt.Errorf("create replacement link %q: %w", link.Name, cerr)
			}
			replaced++
		}
	}

	// Add new links.
	for name, url := range opts.AddLinks {
		_, _, cerr := client.GL.ReleaseLinks.CreateReleaseLink(projectID, tagName, &gitlab.CreateReleaseLinkOptions{
			Name: gitlab.Ptr(name),
			URL:  gitlab.Ptr(url),
		}, gitlab.WithContext(ctx))
		if cerr != nil {
			return replaced, added, fmt.Errorf("add link %q: %w", name, cerr)
		}
		added++
	}

	return replaced, added, nil
}
