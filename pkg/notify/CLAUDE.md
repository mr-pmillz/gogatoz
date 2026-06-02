# pkg/notify

Notification system for shipping CI/CD analysis findings to external systems. Supports raw webhook POSTs, Apprise API (Discord/Slack/etc.), and direct Discord webhooks with rich embed formatting.

## Files

| File | Purpose |
|------|---------|
| `notifier.go` | `Options` struct, `Notifier` type with `SendJSON()`/`SendFinding()`, `FindingEnvelope` schema |
| `sender.go` | `Sender` interface, `Message`/`DiscordEmbed` types, color and type constants |
| `format.go` | `FormatDiscordMessages()` and `FormatAppriseMarkdown()` — convert enumerate results to formatted messages |
| `apprise.go` | `AppriseSender` — posts markdown to Apprise API with tag/type/format fields |
| `discord.go` | `DiscordSender` — posts embeds to Discord webhook URL with auto-chunking |
| `notifier_test.go` | Unit tests for Notifier (4 tests) |
| `format_test.go` | Unit tests for formatting (5 tests) |
| `apprise_test.go` | Unit tests for Apprise backend (6 tests) |
| `discord_test.go` | Unit tests for Discord backend (5 tests) |

## Exported API

**Interfaces:**
- `Sender` — `Send(ctx, msg Message) error`

**Types:**
- `Options` — URL (required), Headers (map), Timeout (duration), Client (*http.Client, optional)
- `Notifier` — raw webhook sender, created via `New()`
- `FindingEnvelope` — Project, Finding, Tool, Version, Occurred, Meta
- `Message` — Title, Body (markdown), Embeds ([]DiscordEmbed), Type (info/success/warning/failure)
- `DiscordEmbed` — Title, Description, Color, Fields, Footer
- `AppriseOptions` — URL, Tag (default "gogatoz"), Timeout, Client
- `DiscordOptions` — WebhookURL, Timeout, Client

**Constants:**
- `ColorCritical` (0x9B59B6), `ColorHigh` (0xFF0000), `ColorMedium` (0xFF8C00), `ColorLow` (0xFFD700), `ColorInformational` (0x17A2B8), `ColorInfo` (0x3498DB)
- `TypeInfo`, `TypeSuccess`, `TypeWarning`, `TypeFailure`

**Functions:**
- `New(opts Options) (*Notifier, error)` — raw webhook sender
- `NewAppriseSender(opts AppriseOptions) (*AppriseSender, error)` — Apprise API sender
- `NewDiscordSender(opts DiscordOptions) (*DiscordSender, error)` — Discord webhook sender
- `FormatDiscordMessages(results []enumerate.Result) []Message` — results → Discord embeds (chunked at 10/msg)
- `FormatAppriseMarkdown(results []enumerate.Result) Message` — results → markdown message

## Internal Patterns

- **Sender interface**: Both AppriseSender and DiscordSender implement Sender
- **Embed chunking**: Discord limits 10 embeds/message; FormatDiscordMessages auto-chunks
- **Severity mapping**: HIGH→red, MEDIUM→orange, LOW→yellow, INFO→blue (colors and emojis)
- **Type mapping**: 0 findings→"success", any HIGH→"failure", MEDIUM only→"warning", else→"info"
- **Error wrapping**: Prefixed with "notify:" then backend name (e.g., "notify: apprise http 400")

## Dependencies

**Imports:**
- `pkg/analyze` — `Finding`, `Severity`, `SeverityHigh/Medium/Low`
- `pkg/enumerate` — `Result` type for formatting functions

**Depended on by:**
- `cmd/enumerate.go` — sends findings to webhook (Notifier)
- `cmd/notify.go` — CLI command using Sender backends and formatting functions

## Configuration

**Via `cmd/notify.go` flags:**
- `--apprise-url` — Apprise API URL
- `--apprise-tag` — routing tag (default: "gogatoz")
- `--discord-webhook` — Discord webhook URL
- `--dry-run` — print formatted output without sending

**Via `cmd/enumerate.go` flags:**
- `--webhook-url` — raw webhook URL (uses Notifier)
- `--webhook-header` — custom headers
- `--webhook-timeout` — per-request timeout

**Environment variables:** `APPRISE_URL`, `DISCORD_WEBHOOK` (fallbacks for CLI flags)
