# pkg/models

Lightweight shared data models for GoGatoZ. Defines JSON-serializable types for CI/CD secrets (metadata only, never values), runners, repositories, organizations, execution tracking, and composite objects. Pure data carriers with no business logic, no methods, and no internal dependencies. Currently a reserved placeholder for future library/API consumers — not directly imported by active codebase packages.

## Files

| File | Purpose |
|------|---------|
| `models.go` | All 6 exported types with JSON struct tags. No functions, methods, or interfaces. |

## Exported API

### Types

- `Secret` — name, scope (project/group/instance/environment), environment, protected, masked, Raw (any), SelectedRepos. **Values are never included (security by design).**
- `Runner` — name, description, runner_type, tags, executor, OS, status, NonEphemeral, TokenPermissions
- `Repository` — ProjectID, PathWithNamespace, WebURL, DefaultBranch
- `Organization` — GroupID, FullPath, WebURL, ParentID (for nested group hierarchy)
- `Execution` — ID, StartedAt/FinishedAt (unix), Status (running/success/error), Error
- `Composite` — optional pointers to Organization, Repository, Runner + Secrets slice. Documentation notes: "Prefer direct composition in other structs when possible."

## Internal Patterns

- Zero custom methods — all types are plain data carriers
- JSON struct tags on all fields with `omitempty` for optional fields
- Pointer fields in Composite for nil-ability
- Field names match GitLab API conventions

## Testing

No tests — intentional for a pure data model package. Validated implicitly through JSON marshaling in integration tests of consuming packages.

## Dependencies

**Imports:** None — leaf package, no internal or third-party dependencies.

**Depended on by:** Currently unused in active codebase. Reserved for future library/SDK consumers and external API contracts.

## Gotchas

1. **Secret never contains values** — only metadata. This is a critical security design decision.
2. **Raw field uses `any`** — callers must type-assert carefully.
3. **Currently unused** — exists as a documented API contract for future consumers.
4. **Scope values are convention-based** — no validation; callers must respect string conventions.
5. **ParentID in Organization** — enables hierarchy representation but no built-in tree traversal.
