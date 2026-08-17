// Command phase1-fixture serves a disposable, tool-free MCP server for the
// Phase 1 manual connectivity demo.
package main

import (
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "phase-1-fixture", Version: "0.0.1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})

	log.Print("Phase 1 fixture listening at http://127.0.0.1:8080/mcp")
	if err := http.ListenAndServe("127.0.0.1:8080", handler); err != nil {
		log.Fatal(err)
	}
}
