package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"moley/internal/platform"
	"moley/internal/rpc"
)

// ExtensionID is fixed by the public key in extension/manifest.json.
const ExtensionID = "jgocaoindhiabkkjonnhimocmpeinmmp"

// ExtensionOrigins are the extension origins allowed to use the native
// host. MOLEY_EXTENSION_IDS (comma-separated) adds more, e.g. for a
// store-published build.
func ExtensionOrigins() []string {
	ids := append([]string{ExtensionID}, list(os.Getenv("MOLEY_EXTENSION_IDS"))...)
	origins := make([]string, len(ids))
	for i, id := range ids {
		origins[i] = "chrome-extension://" + id + "/"
	}
	return origins
}

// nmhMethods is all the browser may call: read state and set quick picks.
var nmhMethods = []string{"client.hello", "status", "exits.list", "quick.set", "rules.list", "conns.list"}

// IsNativeHostLaunch reports whether the browser started us: Chromium
// passes the caller's origin as the first argument.
func IsNativeHostLaunch(args []string) bool {
	return len(args) > 0 && strings.HasPrefix(args[0], "chrome-extension://")
}

// NativeHost relays native messages between the browser (stdio) and the
// daemon (pipe). Both sides use the same framing, so it forwards frames
// as they are, after checking the origin and the method allowlist.
func NativeHost(origin string, stdin io.Reader, stdout io.Writer) int {
	if !slices.Contains(ExtensionOrigins(), origin) {
		fmt.Fprintln(os.Stderr, "moley: native host refused origin "+origin)
		return ExitUsage
	}
	var out sync.Mutex
	reply := func(b []byte) {
		out.Lock()
		defer out.Unlock()
		_ = rpc.WriteFrame(stdout, b)
	}
	fail := func(id json.RawMessage, e rpc.Error) {
		b, _ := json.Marshal(rpc.Response{ID: id, Error: &e})
		reply(b)
	}
	var daemon io.ReadWriteCloser
	connect := func() bool {
		if daemon != nil {
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := platform.Dial(ctx)
		if err != nil {
			return false
		}
		daemon = c
		go func(c io.ReadWriteCloser) {
			for {
				frame, err := rpc.ReadFrame(c)
				if err != nil {
					// The daemon went away: tell the extension by closing.
					os.Exit(ExitUnreachable)
				}
				reply(frame)
			}
		}(c)
		return true
	}
	for {
		frame, err := rpc.ReadFrame(stdin)
		if err != nil {
			return ExitOK // browser closed the port
		}
		var req rpc.Request
		if err := json.Unmarshal(frame, &req); err != nil {
			fail(nil, rpc.Error{Code: rpc.CodeInvalidParams, Message: "malformed request"})
			continue
		}
		if !slices.Contains(nmhMethods, req.Method) {
			fail(req.ID, rpc.Error{Code: "forbidden", Message: req.Method + " is not available to the browser"})
			continue
		}
		if frame, err = restrict(req); err != nil {
			fail(req.ID, rpc.Error{Code: "forbidden", Message: err.Error()})
			continue
		}
		if !connect() {
			fail(req.ID, rpc.Error{Code: "daemon_unreachable", Message: "Moley is not running"})
			continue
		}
		if err := rpc.WriteFrame(daemon, frame); err != nil {
			return ExitUnreachable
		}
	}
}

// restrict narrows what the browser may ask for, beyond the method list:
// no hint secret (Chromium can't use it) and no listing of every app's
// connections, only those of a named host.
func restrict(req rpc.Request) ([]byte, error) {
	switch req.Method {
	case "client.hello":
		req.Params = json.RawMessage(`{"no_secret":true}`)
	case "conns.list":
		var p struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(req.Params, &p) != nil || strings.TrimSpace(p.Host) == "" {
			return nil, errors.New("conns.list needs a host")
		}
	}
	return json.Marshal(req)
}
