package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr, "test"); code != 0 {
				t.Fatalf("Run(%q) exit code = %d, want 0", args, code)
			}
			if !strings.Contains(stdout.String(), "Usage: mcprift <command>") {
				t.Fatalf("help output = %q, want usage", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version"}, &stdout, &stderr, "v0.1.0"); code != 0 {
		t.Fatalf("Run(version) exit code = %d, want 0", code)
	}
	if got, want := stdout.String(), "mcprift v0.1.0\n"; got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"scan"}, &stdout, &stderr, "test"); code != 2 {
		t.Fatalf("Run(scan) exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, `unknown command "scan"`) || !strings.Contains(got, "Usage: mcprift <command>") {
		t.Errorf("stderr = %q, want error and usage", got)
	}
}
