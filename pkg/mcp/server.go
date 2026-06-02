// Package mcpserver implements a Model Context Protocol server exposing
// GoGatoZ search and enumerate tools over stdio transport.
package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"github.com/mr-pmillz/gogatoz/pkg/store"
)

// version is the MCP server version reported during initialization.
const version = "0.1.0"

// Server wraps the MCP SDK server and holds shared dependencies.
// The GitLab client is created once at startup and reused for all tool calls,
// preserving rate-limiting and connection pooling.
type Server struct {
	mcpSrv    *mcp.Server
	client    *gitlabx.Client
	store     *store.Store // nil when storage is disabled
	gitlabURL string       // for session metadata
}

// New creates an MCP server with search and enumerate tools registered.
// If st is non-nil, results are automatically persisted to SQLite.
func New(client *gitlabx.Client, st *store.Store, gitlabURL string) *Server {
	s := &Server{client: client, store: st, gitlabURL: gitlabURL}
	s.mcpSrv = mcp.NewServer(
		&mcp.Implementation{Name: "gogatoz", Version: version},
		nil,
	)
	s.registerTools()
	return s
}

func (s *Server) registerTools() {
	mcp.AddTool(s.mcpSrv, searchTool, s.handleSearchProjects)
	mcp.AddTool(s.mcpSrv, enumerateTool, s.handleEnumerateProjects)
	mcp.AddTool(s.mcpSrv, attackTool, s.handleAttackProject)
	mcp.AddTool(s.mcpSrv, secretScanTool, s.handleSecretScan)
	mcp.AddTool(s.mcpSrv, pivotTool, s.handlePivotScan)
}

// Run starts the MCP server over stdio (blocking).
// All logging goes to stderr; stdout is reserved for the MCP protocol.
func (s *Server) Run(ctx context.Context) error {
	if err := s.mcpSrv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}
