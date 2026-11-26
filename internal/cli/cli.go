// Package cli is the moley command line: thin wrappers over the daemon's
// RPC methods, built to be driven by scripts and AI agents as well as
// people. Every command takes --json; output is versioned ("v": 1); it
// never prompts; exit codes are stable:
//
//	0 ok · 1 error · 2 usage or confirmation needed · 3 daemon unreachable · 4 check failed
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"moley/internal/platform"
	"moley/internal/rpc"
)

const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitUnreachable = 3
	ExitCheckFailed = 4
	SchemaVersion   = 1
)

// Env is the process environment a command runs in.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	JSON           bool
}

type command struct {
	name    string // "rules add"
	args    string // usage after the name
	summary string
	example string
	run     func(c *call) error
}

// call is one command invocation.
type call struct {
	*Env
	cmd    *command
	flags  *flag.FlagSet
	args   []string // positional
	after  []string // after "--"
	client *rpc.Client
}

// Run executes args and returns the process exit code.
func Run(args []string, env *Env) int {
	env.JSON = env.JSON || os.Getenv("MOLEY_OUTPUT") == "json"
	if i := slices.Index(args, "--json"); i >= 0 && (slices.Index(args, "--") < 0 || i < slices.Index(args, "--")) {
		env.JSON = true
		args = slices.Delete(slices.Clone(args), i, i+1)
	}
	cmd, rest := lookup(args)
	if cmd == nil {
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
			printUsage(env.Stdout)
			return ExitOK
		}
		return fail(env, usageErr("unknown command %q; run `moley help`", strings.Join(args, " ")))
	}
	c := &call{Env: env, cmd: cmd, flags: flag.NewFlagSet(cmd.name, flag.ContinueOnError)}
	c.flags.SetOutput(io.Discard)
	c.flags.Usage = func() {}
	if i := slices.Index(rest, "--"); i >= 0 {
		rest, c.after = rest[:i], rest[i+1:]
	}
	c.args = rest
	err := cmd.run(c)
	if c.client != nil {
		c.client.Close()
	}
	if err != nil {
		return fail(env, err)
	}
	return ExitOK
}

func lookup(args []string) (*command, []string) {
	// Longest match first: "rules add" before "rules".
	for n := min(len(args), 2); n > 0; n-- {
		name := strings.Join(args[:n], " ")
		for i := range commands {
			if commands[i].name == name {
				return &commands[i], args[n:]
			}
		}
	}
	return nil, nil
}

// parse reads flags anywhere among the positional args (so
// `moley import work.ovpn --id sq1` works), then checks the positional
// count is within [minN, maxN] (maxN < 0: unlimited).
func (c *call) parse(minN, maxN int) error {
	var pos []string
	rest := c.args
	for {
		if err := c.flags.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return helpRequested{c.cmd}
			}
			return usageErr("%v (see `moley help %s`)", err, c.cmd.name)
		}
		rest = c.flags.Args()
		if len(rest) == 0 {
			break
		}
		pos, rest = append(pos, rest[0]), rest[1:]
	}
	c.args = pos
	if len(pos) < minN || (maxN >= 0 && len(pos) > maxN) {
		return usageErr("usage: moley %s %s", c.cmd.name, c.cmd.args)
	}
	return nil
}

// rpc calls the daemon, connecting on first use.
func (c *call) rpc(method string, params, out any) error {
	return c.rpcTimeout(method, params, out, 60*time.Second)
}

func (c *call) rpcTimeout(method string, params, out any, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.connect(); err != nil {
		return err
	}
	return rpcError(method, c.client.Call(ctx, method, params, out))
}

// connect dials the daemon unless already connected.
func (c *call) connect() error {
	if c.client != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := platform.Dial(ctx)
	if err != nil {
		return &cliError{code: ExitUnreachable, rpc: rpc.Error{
			Code: "daemon_unreachable", Message: "the moley daemon is not running",
			Hint: "start it with `moley start` (or `moley service` in the foreground)"}}
	}
	c.client = rpc.NewClient(conn)
	return nil
}

// rpcError maps a call's error to the CLI's exit codes.
func rpcError(method string, err error) error {
	var re *rpc.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &re):
		code := ExitError
		switch re.Code {
		case rpc.CodeConfirm, rpc.CodeInvalidParams, rpc.CodeUnknownMethod, "key_password_required":
			code = ExitUsage
		case rpc.CodeCheckFailed, "kill_switch_failed":
			code = ExitCheckFailed
		case "needs_service":
			code = ExitUsage
		}
		return &cliError{code: code, rpc: *re}
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return &cliError{code: ExitError, rpc: rpc.Error{Code: "timeout", Message: method + " timed out"}}
	default:
		return &cliError{code: ExitUnreachable, rpc: rpc.Error{Code: "daemon_unreachable", Message: err.Error()}}
	}
}

// emit prints a result: JSON (with "v") or the text renderer's output.
func (c *call) emit(v any, text func(w io.Writer)) error {
	if c.JSON {
		return writeJSON(c.Stdout, envelope(v))
	}
	if text != nil {
		text(c.Stdout)
		return nil
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(c.Stdout, string(b))
	return nil
}

// envelope merges "v" into an object result.
func envelope(v any) any {
	b, _ := json.Marshal(v)
	var m map[string]any
	if json.Unmarshal(b, &m) == nil && m != nil {
		m["v"] = SchemaVersion
		return m
	}
	return map[string]any{"v": SchemaVersion, "result": v}
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

type cliError struct {
	code int
	rpc  rpc.Error
}

func (e *cliError) Error() string { return e.rpc.Message }

func usageErr(format string, a ...any) error {
	return &cliError{code: ExitUsage, rpc: rpc.Error{Code: "usage", Message: fmt.Sprintf(format, a...)}}
}

func checkFailed(code, hint, format string, a ...any) error {
	return &cliError{code: ExitCheckFailed, rpc: rpc.Error{Code: code, Message: fmt.Sprintf(format, a...), Hint: hint}}
}

type helpRequested struct{ cmd *command }

func (helpRequested) Error() string { return "help" }

func fail(env *Env, err error) int {
	var h helpRequested
	if errors.As(err, &h) {
		printCommandHelp(env.Stdout, h.cmd)
		return ExitOK
	}
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = &cliError{code: ExitError, rpc: rpc.Error{Code: "error", Message: err.Error()}}
	}
	if env.JSON {
		_ = writeJSON(env.Stderr, map[string]any{"v": SchemaVersion, "error": ce.rpc})
	} else {
		fmt.Fprintln(env.Stderr, "moley: "+ce.rpc.Message)
		if ce.rpc.Hint != "" {
			fmt.Fprintln(env.Stderr, "  hint: "+ce.rpc.Hint)
		}
	}
	return ce.code
}
