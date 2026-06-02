package notify

import "context"

// Sender sends formatted notification messages to an external service.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// Message holds a formatted notification payload.
type Message struct {
	Title  string
	Body   string         // markdown-formatted text
	Embeds []DiscordEmbed // used by Discord backend; ignored by Apprise
	Type   string         // "info", "success", "warning", "failure"
}

// DiscordEmbed represents a Discord rich embed.
type DiscordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
}

// DiscordEmbedField is a single field in a Discord embed.
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// DiscordEmbedFooter is the footer of a Discord embed.
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// Severity color constants for Discord embeds.
const (
	ColorCritical      = 0x9B59B6 // purple
	ColorHigh          = 0xFF0000 // red
	ColorMedium        = 0xFF8C00 // orange
	ColorLow           = 0xFFD700 // yellow
	ColorInformational = 0x17A2B8 // teal
	ColorInfo          = 0x3498DB // blue (non-severity)
)

// Message type constants for Apprise/notification severity mapping.
const (
	TypeInfo    = "info"
	TypeSuccess = "success"
	TypeWarning = "warning"
	TypeFailure = "failure"
)

const contentTypeJSON = "application/json"
