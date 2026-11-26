package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"moley/internal/rpc"
)

// Bridge is what the window may ask of the app: any daemon call, plus the
// few things only the app can do (start the daemon, install the service,
// start at login, updates). The window only ever loads Moley's own pages.
type Bridge struct{ ui *ui }

// Reply carries a call's result or its coded error to the window.
type Reply struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpc.Error      `json:"error,omitempty"`
}

func reply(res json.RawMessage, err error) Reply {
	if err == nil {
		return Reply{OK: true, Result: res}
	}
	var re *rpc.Error
	if !errors.As(err, &re) {
		re = &rpc.Error{Code: "error", Message: err.Error()}
	}
	return Reply{Error: re}
}

// Call makes one daemon call.
func (b *Bridge) Call(method string, params json.RawMessage) Reply {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return reply(call(ctx, method, params))
}

// Snapshot is the latest state, so an opening window draws at once.
func (b *Bridge) Snapshot() map[string]json.RawMessage { return b.ui.snapshot() }

// WatchConns streams open connections while the Activity view shows.
func (b *Bridge) WatchConns(on bool) { b.ui.link.watchConns(on) }

// StartDaemon starts Moley (the service, if installed).
func (b *Bridge) StartDaemon() Reply {
	err := startDaemon()
	if err == nil {
		b.ui.link.retry()
	}
	return reply(nil, err)
}

// InstallService installs the privileged service, asking for elevation.
func (b *Bridge) InstallService() Reply {
	err := elevate(moleyExe(), "service", "install")
	if err == nil {
		b.ui.link.retry()
	}
	return reply(nil, err)
}

// Notify shows a system notification for the window: what an action did,
// or why it failed.
func (b *Bridge) Notify(title, body string) { b.ui.notify(title, body) }

// Autostart reports whether the tray starts at login.
func (b *Bridge) Autostart() bool { return autostartEnabled() }

func (b *Bridge) SetAutostart(on bool) Reply { return reply(nil, setAutostart(on)) }

type About struct {
	Version string `json:"version"`
	Updates bool   `json:"updates"` // this build can update itself
	OS      string `json:"os"`
}

func (b *Bridge) About() About {
	return About{Version: version, Updates: updatesEnabled(), OS: runtime.GOOS}
}

// moleyExe is the daemon and CLI binary: next to this one, else on PATH.
func moleyExe() string {
	name := "moley"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(self), name); fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// startDaemon runs `moley start`, which starts the service if it is
// installed and a per-user daemon otherwise.
func startDaemon() error {
	cmd := exec.Command(moleyExe(), "start", "--json")
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var e struct {
			Error rpc.Error `json:"error"`
		}
		if json.Unmarshal(out, &e) == nil && e.Error.Message != "" {
			return &e.Error
		}
		return err
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
