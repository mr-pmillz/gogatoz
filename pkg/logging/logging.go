package logging

import (
	"log/slog"
	"os"

	"golang.org/x/term"
)

// NewLogger creates a structured logger. When json is true or stderr is not a
// terminal, it uses JSON output; otherwise it uses the human-readable text
// handler. The logger writes to stderr so it does not interfere with normal
// command output on stdout.
func NewLogger(json bool, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if json || !term.IsTerminal(int(os.Stderr.Fd())) {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// ParseLevel parses a log level string (debug, info, warn, error).
// Returns slog.LevelWarn as default for unrecognised values.
func ParseLevel(s string) slog.Level {
	switch s {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "info", "INFO":
		return slog.LevelInfo
	case "warn", "WARN", "warning", "WARNING":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}
