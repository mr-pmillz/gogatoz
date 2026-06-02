package tamper

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// PackageResult captures the outcome of a package upload.
type PackageResult struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	FileName       string `json:"file_name"`
	URL            string `json:"url"`
}

// PublishPackage uploads a file to the GitLab Generic Packages registry,
// potentially replacing a legitimate package version with a malicious one.
func PublishPackage(ctx context.Context, client *gitlabx.Client, projectID any, packageName, version, fileName string, content io.Reader) (*PackageResult, error) {
	packageName = strings.TrimSpace(packageName)
	version = strings.TrimSpace(version)
	fileName = strings.TrimSpace(fileName)
	if packageName == "" || version == "" || fileName == "" {
		return nil, fmt.Errorf("package name, version, and file name are required")
	}

	opts := &gitlab.PublishPackageFileOptions{
		Status: gitlab.Ptr(gitlab.PackageDefault),
	}
	pkg, _, err := client.GL.GenericPackages.PublishPackageFile(
		projectID, packageName, version, fileName,
		content, opts, gitlab.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("publish package: %w", err)
	}

	url, _ := client.GL.GenericPackages.FormatPackageURL(projectID, packageName, version, fileName)

	return &PackageResult{
		PackageName:    packageName,
		PackageVersion: version,
		FileName:       pkg.FileName,
		URL:            url,
	}, nil
}
