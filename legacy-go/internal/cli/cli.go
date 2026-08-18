// Package cli implements MCPRift's command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sanjayy0612/MCPRift/internal/mcp"
)

const usage = `Usage: mcprift <command>

MCPRift is an authorized security-testing framework for MCP servers.

Commands:
  connect URL  Make a baseline connection to a controlled MCP Streamable HTTP URL.
  help       Show this help message.
  version    Show the MCPRift version.

Use MCPRift only on systems you are authorized to test.
`

// Run executes a command and returns its process exit code.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, _ = io.WriteString(stdout, usage)
		return 0
	}

	switch args[0] {
	case "connect":
		if len(args) != 2 {
			_, _ = io.WriteString(stderr, "mcprift: connect requires exactly one URL\n\n")
			_, _ = io.WriteString(stderr, usage)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := (mcp.Client{}).Connect(ctx, args[1])
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "mcprift: baseline connection failed:", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "connected to %s %s using %s (protocol %s)\n", result.ServerName, result.ServerVersion, result.Transport, result.ProtocolVersion)
		return 0
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "mcprift %s\n", version)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "mcprift: unknown command %q\n\n", args[0])
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
}
