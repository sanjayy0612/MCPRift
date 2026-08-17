// Package mcp implements MCPRift's safe baseline MCP connection.
package mcp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Transport = "streamable-http"

// Result records the information negotiated during a baseline connection.
type Result struct {
	ProtocolVersion string
	ServerName      string
	ServerVersion   string
	Transport       string
}

// Client connects to one controlled Streamable HTTP MCP endpoint.
type Client struct {
	HTTPClient *http.Client
}

// Connect establishes a valid baseline MCP session using the official MCP Go
// SDK. It does not inspect capabilities or invoke server features.
func (c Client) Connect(ctx context.Context, rawURL string) (Result, error) {
	endpoint, err := controlledEndpoint(rawURL)
	if err != nil {
		return Result{}, err
	}

	client := mcp.NewClient(
		&mcp.Implementation{Name: "mcprift", Version: "dev"},
		&mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}},
	)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint.String(),
		HTTPClient:           c.HTTPClient,
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return Result{}, errors.New("baseline MCP connection failed")
	}
	defer session.Close()

	initialized := session.InitializeResult()
	if initialized == nil || initialized.ServerInfo == nil || initialized.ServerInfo.Name == "" || initialized.ServerInfo.Version == "" || initialized.ProtocolVersion == "" {
		return Result{}, errors.New("server did not provide a complete baseline result")
	}

	return Result{
		ProtocolVersion: initialized.ProtocolVersion,
		ServerName:      initialized.ServerInfo.Name,
		ServerVersion:   initialized.ServerInfo.Version,
		Transport:       Transport,
	}, nil
}

func controlledEndpoint(rawURL string) (*url.URL, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil {
		return nil, errors.New("target must be an absolute loopback HTTP or HTTPS URL")
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, errors.New("target must use HTTP or HTTPS")
	}

	host := strings.TrimSuffix(endpoint.Hostname(), ".")
	if strings.EqualFold(host, "localhost") {
		return endpoint, nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("target must use a loopback host during Phase 1")
	}
	return endpoint, nil
}
