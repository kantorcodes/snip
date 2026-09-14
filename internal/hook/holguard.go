package hook

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"time"
)

const holGuardTimeout = 10 * time.Second

type holGuardResult struct {
	MinimumAction string `json:"minimum_action"`
	Classification struct {
		ExplicitlyBenign bool `json:"explicitly_benign"`
	} `json:"classification"`
}

var holGuardRun = func(ctx context.Context, command string) ([]byte, error) {
	return exec.CommandContext(ctx, "hol-guard", "command", "test", command, "--json").Output()
}

func holGuardEnabled() bool {
	return os.Getenv("SNIP_HOL_GUARD") == "1"
}

func holGuardAllows(command string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), holGuardTimeout)
	defer cancel()

	output, err := holGuardRun(ctx, command)
	if err != nil {
		return false
	}

	var result holGuardResult
	if err := json.Unmarshal(output, &result); err != nil {
		return false
	}

	return result.MinimumAction == "allow" && result.Classification.ExplicitlyBenign
}

func writeHOLGuardDeny(w io.Writer) error {
	return json.NewEncoder(w).Encode(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":      "PreToolUse",
			"permissionDecision": "deny",
		},
	})
}
