// Package execx wraps command execution so tests can substitute a fake.
package execx

import (
	"bytes"
	"context"
	"os/exec"
)

// Result is the outcome of a command run.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes an external command. Err is non-nil when the command could
// not be started or the context ended; a non-zero exit is reported via ExitCode.
type Runner func(ctx context.Context, name string, args ...string) (Result, error)

// Run is the default Runner backed by os/exec. Stdin is /dev/null.
func Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			return res, nil
		}
		return res, err
	}
	return res, nil
}
