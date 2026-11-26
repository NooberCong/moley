// Package daemon is the Moley service: it owns the config, the engine and
// the audit log, and serves the RPC methods every client (CLI, UI,
// extension) uses.
package daemon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"moley/internal/compile"
	"moley/internal/engine"
	"moley/internal/model"
	"moley/internal/platform"
	"moley/internal/rpc"
)

const Version = "0.2.0"

type Daemon struct {
	dir    string
	logs   *engine.Logs
	engine *engine.Engine
	sealer model.Sealer
	secret string

	mu  sync.Mutex // serializes mutations
	cfg model.Config
	// modeErr says why the configured system mode isn't running (this
	// daemon lacks the privileges, say); browser routing still works.
	modeErr string

	changeMu sync.Mutex
	changed  chan struct{} // closed on every config change (events)

	auditMu sync.Mutex

	stopOnce sync.Once
	stopped  chan struct{}
}

// Stopped is closed when a client asked the daemon to stop.
func (d *Daemon) Stopped() <-chan struct{} { return d.stopped }

// Open loads state from dir and starts the engine with it.
func Open(dir string, logs *engine.Logs) (*Daemon, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	secret, err := loadSecret(filepath.Join(dir, "secret"))
	if err != nil {
		return nil, err
	}
	d := &Daemon{dir: dir, logs: logs, sealer: platform.NewSealer(), secret: secret,
		stopped: make(chan struct{}), changed: make(chan struct{})}
	if d.cfg, err = model.Load(d.configPath(), d.sealer); err != nil {
		return nil, err
	}
	if d.engine, err = engine.New(dir, secret, logs); err != nil {
		return nil, err
	}
	_, err = d.engine.Apply(d.cfg)
	if err != nil && d.cfg.Mode.TUN {
		// Keep the browser and exec routes working without system mode,
		// and say why; a persistent kill switch still blocks the rest.
		d.modeErr = "system mode is off: " + err.Error()
		d.logs.Error(d.modeErr)
		d.cfg.Mode = model.Mode{}
		_, err = d.engine.Apply(d.cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("start engine: %w", err)
	}
	if err := d.setKillSwitch(d.cfg.Mode); err != nil {
		d.engine.Close()
		return nil, err
	}
	return d, nil
}

// Close stops the engine. An "on" kill switch lifts with it; a persistent
// one keeps blocking until Moley is back.
func (d *Daemon) Close() error {
	platform.ReleaseKillSwitch()
	return d.engine.Close()
}

// setKillSwitch brings the firewall in line with m. It runs after the
// engine (re)creates the TUN interface, since the filters name it.
func (d *Daemon) setKillSwitch(m model.Mode) error {
	if m.Kill() == model.KillSwitchOff && !platform.System() {
		return nil // a per-user daemon never sets one
	}
	if err := platform.SetKillSwitch(m.Kill(), compile.TUNName); err != nil {
		return rpc.Errorf("kill_switch_failed", "see `moley logs`", "%v", err)
	}
	return nil
}

func (d *Daemon) configPath() string { return filepath.Join(d.dir, "moley.json") }
func (d *Daemon) auditPath() string  { return filepath.Join(d.dir, "audit.jsonl") }

// Serve accepts control connections until ctx ends.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go rpc.Serve(ctx, c, platform.Peer(c), d.handle)
	}
}

func (d *Daemon) handle(ctx context.Context, peer any, method string, params json.RawMessage) (any, error) {
	m, ok := methods[method]
	if !ok {
		return nil, rpc.Errorf(rpc.CodeUnknownMethod, "run `moley help --json` for the method list", "unknown method %q", method)
	}
	caller, _ := peer.(platform.Caller)
	return m.call(ctx, d, caller, params)
}

// mutate runs fn on a copy of the config. If fn and validation succeed,
// the copy is applied to the engine, saved and audited, in that order: a
// change the engine rejects is never persisted.
func (d *Daemon) mutate(caller platform.Caller, method string, dryRun bool, fn func(*model.Config) (string, error)) (engine.ApplyResult, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := d.cfg.Clone()
	summary, err := fn(&next)
	if err != nil {
		return engine.ApplyResult{}, "", err
	}
	if err := next.Validate(); err != nil {
		return engine.ApplyResult{}, "", rpc.Errorf(rpc.CodeInvalidParams, "", "%v", err)
	}
	if next.Mode.TUN && !d.cfg.Mode.TUN {
		if err := platform.CanRouteSystem(); err != nil {
			return engine.ApplyResult{}, "", rpc.Errorf(CodeNeedsService, "", "%v", err)
		}
	}
	if dryRun {
		if err := d.engine.Check(next); err != nil {
			return engine.ApplyResult{}, summary, rpc.Errorf(rpc.CodeInvalidParams, "", "core rejected the config: %v", err)
		}
		return engine.ApplyResult{}, summary, nil
	}
	prev, prevKill := d.cfg.Mode, d.cfg.Mode.Kill()
	// Lifting the kill switch goes first, while the tunnel still carries
	// everything; turning it on (or keeping it on across a rebuild, which
	// recreates the interface it names) goes after.
	lifting := prevKill != model.KillSwitchOff && next.Mode.Kill() == model.KillSwitchOff
	if lifting {
		if err := d.setKillSwitch(next.Mode); err != nil {
			return engine.ApplyResult{}, "", err
		}
	}
	rollback := func(why string) {
		if _, err := d.engine.Apply(d.cfg); err != nil {
			d.logs.Error("roll back after " + why + ": " + err.Error())
		}
		if err := d.setKillSwitch(prev); err != nil {
			d.logs.Error("restore the kill switch after " + why + ": " + err.Error())
		}
	}
	res, err := d.engine.Apply(next)
	if err != nil {
		if lifting {
			rollback("a rejected config")
		}
		return res, "", rpc.Errorf(rpc.CodeInvalidParams, "", "core rejected the config: %v", err)
	}
	if !lifting && next.Mode.Kill() != model.KillSwitchOff && (res.Rebuilt || prevKill != next.Mode.Kill()) {
		if err := d.setKillSwitch(next.Mode); err != nil {
			rollback("a failed kill switch")
			return res, "", err
		}
	}
	if err := model.Save(d.configPath(), next, d.sealer); err != nil {
		// Never run a config that a restart would silently undo.
		rollback("a failed save")
		return res, "", fmt.Errorf("save: %w (change rolled back)", err)
	}
	d.cfg = next
	if next.Mode != prev {
		d.modeErr = ""
	}
	d.audit(AuditEntry{Method: method, Caller: caller.String(), Summary: summary, Rebuilt: res.Rebuilt})
	d.notify()
	return res, summary, nil
}

// CodeNeedsService: the change needs the privileged service.
const CodeNeedsService = "needs_service"

func (d *Daemon) config() model.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.Clone()
}

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	Time    time.Time `json:"time"`
	Method  string    `json:"method"`
	Caller  string    `json:"caller"`
	Summary string    `json:"summary"`
	Rebuilt bool      `json:"rebuilt,omitempty"`
}

func (d *Daemon) audit(e AuditEntry) {
	e.Time = time.Now().UTC()
	b, _ := json.Marshal(e)
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	f, err := os.OpenFile(d.auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		d.logs.Error("audit: " + err.Error())
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
	d.logs.Info(fmt.Sprintf("%s by %s: %s", e.Method, e.Caller, e.Summary))
}

func (d *Daemon) history(limit int) ([]AuditEntry, error) {
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	f, err := os.Open(d.auditPath())
	if errors.Is(err, os.ErrNotExist) {
		return []AuditEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, sc.Err()
}

func loadSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return string(b), nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := hex.EncodeToString(buf)
	return s, os.WriteFile(path, []byte(s), 0o600)
}
