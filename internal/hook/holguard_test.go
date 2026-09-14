package hook

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func withHOLGuardRun(t *testing.T, fn func(context.Context, string) ([]byte, error)) {
	t.Helper()
	old := holGuardRun
	holGuardRun = fn
	t.Cleanup(func() { holGuardRun = old })
}

func TestHOLGuardAllowsExplicitBenignAllow(t *testing.T) {
	withHOLGuardRun(t, func(context.Context, string) ([]byte, error) {
		return []byte(`{"minimum_action":"allow","classification":{"explicitly_benign":true}}`), nil
	})
	if !holGuardAllows("git status") {
		t.Fatal("expected allow")
	}
}

func TestHOLGuardRejectsImplicitAllow(t *testing.T) {
	withHOLGuardRun(t, func(context.Context, string) ([]byte, error) {
		return []byte(`{"minimum_action":"allow","classification":{"explicitly_benign":false}}`), nil
	})
	if holGuardAllows("git status") {
		t.Fatal("expected deny")
	}
}

func TestHOLGuardRejectsReview(t *testing.T) {
	withHOLGuardRun(t, func(context.Context, string) ([]byte, error) {
		return []byte(`{"minimum_action":"review","classification":{"explicitly_benign":false}}`), nil
	})
	if holGuardAllows("rm -rf /tmp/x") {
		t.Fatal("expected deny")
	}
}

func TestHOLGuardRejectsMalformedOutput(t *testing.T) {
	withHOLGuardRun(t, func(context.Context, string) ([]byte, error) {
		return []byte(`not-json`), nil
	})
	if holGuardAllows("git status") {
		t.Fatal("expected deny")
	}
}

func TestHOLGuardRejectsRunnerError(t *testing.T) {
	withHOLGuardRun(t, func(context.Context, string) ([]byte, error) {
		return nil, errors.New("failed")
	})
	if holGuardAllows("git status") {
		t.Fatal("expected deny")
	}
}

func TestRunHOLGuardDenyPrecedesRewrite(t *testing.T) {
	t.Setenv("SNIP_HOL_GUARD", "1")
	var got string
	withHOLGuardRun(t, func(_ context.Context, command string) ([]byte, error) {
		got = command
		return []byte(`{"minimum_action":"review","classification":{"explicitly_benign":false}}`), nil
	})

	in := bytes.NewBufferString(`{"tool_name":"Bash","tool_input":{"command":"git status"}}`)
	var out bytes.Buffer
	if err := Run(in, &out, []string{"git"}, nil, "/usr/local/bin/snip"); err != nil {
		t.Fatal(err)
	}
	if got != "git status" {
		t.Fatalf("command = %q", got)
	}
	if permissionDecisionOf(t, out.String()) != "deny" {
		t.Fatalf("response = %s", out.String())
	}
}

func TestRunHOLGuardAllowContinuesRewrite(t *testing.T) {
	t.Setenv("SNIP_HOL_GUARD", "1")
	withHOLGuardRun(t, func(context.Context, string) ([]byte, error) {
		return []byte(`{"minimum_action":"allow","classification":{"explicitly_benign":true}}`), nil
	})

	in := bytes.NewBufferString(`{"tool_name":"Bash","tool_input":{"command":"git status"}}`)
	var out bytes.Buffer
	if err := Run(in, &out, []string{"git"}, nil, "/usr/local/bin/snip"); err != nil {
		t.Fatal(err)
	}
	if permissionDecisionOf(t, out.String()) != "allow" {
		t.Fatalf("response = %s", out.String())
	}
}
