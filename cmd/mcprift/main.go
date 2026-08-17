// Command mcprift is the command-line entry point for MCPRift.
package main

import (
	"os"

	"github.com/sanjayy0612/MCPRift/internal/cli"
)

// version is set at build time with -ldflags when a release is produced.
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
