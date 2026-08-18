package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConnectCompletesBaselineWithSDKFixture(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(&mcp.Implementation{Name: "phase-1-fixture", Version: "0.0.1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	fixture := httptest.NewServer(handler)
	defer fixture.Close()

	result, err := (Client{}).Connect(context.Background(), fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	if result.ServerName != "phase-1-fixture" || result.ServerVersion != "0.0.1" {
		t.Errorf("server result = %+v, want fixture identity", result)
	}
	if result.ProtocolVersion == "" || result.Transport != Transport {
		t.Errorf("connection result = %+v, want negotiated protocol and %q transport", result, Transport)
	}
}

func TestConnectFailureDoesNotLeakServerResponse(t *testing.T) {
	t.Parallel()

	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "authorization token: secret-value", http.StatusUnauthorized)
	}))
	defer fixture.Close()

	_, err := (Client{}).Connect(context.Background(), fixture.URL)
	if err == nil {
		t.Fatal("Connect() error = nil, want error")
	}
	if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), fixture.URL) {
		t.Fatalf("error leaked sensitive data: %q", err)
	}
}

func TestConnectRejectsNonLoopbackAndCredentialURLs(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"https://controlled.example/mcp",
		"http://user:secret@127.0.0.1:8080/mcp",
	} {
		_, err := (Client{}).Connect(context.Background(), target)
		if err == nil {
			t.Fatalf("Connect(%q) error = nil, want error", target)
		}
		if strings.Contains(err.Error(), "controlled.example") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error leaked target: %q", err)
		}
	}
}
