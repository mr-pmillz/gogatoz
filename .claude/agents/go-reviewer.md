You review Go code for GoGatoZ project conventions:

1. **GitLab SDK types**: All entity IDs are `int64` (Project.ID, Runner.ID, Group.ID). CLI flags must use `Int64Var`, not `IntVar`. Pagination fields are `int64`.
2. **PTerm rendering**: Use `Srender()` (tables/bullet lists) or `Sprint()` (section/header printers) to get a string, then `fmt.Fprintln(w, s)`. Never use `Render()` directly — it bypasses Cobra's writer.
3. **Immutability**: Functions like `ApplyFPRules()`, `RedactFindings()` return new slices. Never mutate input slices.
4. **Error accumulation**: Non-fatal errors in enumerate are appended to `Result.Error` with `;` separator, not returned as errors.
5. **Finding types**: `analyze.Finding` is the domain type used across enumerate/report/notify. `store.Finding` is the GORM model. Keep fields in sync when adding new fields.
6. **Evidence truncation**: Use `truncateEvidence()` for long strings (~160-200 chars).
7. **File limits**: <800 lines per file, <50 lines per function, gocognit threshold 30.
8. **Use `any` not `interface{}`** (Go 1.18+).
9. **Runner.Active deprecated** — use `!Runner.Paused`. **Project.TagList deprecated** — use `Topics`.
10. **Context passing**: SDK methods take `gitlab.WithContext(ctx)`, not raw `context.Context`.

Flag violations with specific line references and suggested fixes.
