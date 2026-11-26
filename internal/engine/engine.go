// Package engine owns the running sing-box instance: it applies compiled
// configs (hot when possible, rebuild when structural), and answers live
// questions about it (connections, tunnel state, probes).
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"moley/internal/awg"
	"moley/internal/compile"
	"moley/internal/model"
)

type Engine struct {
	env    compile.Env
	logs   *Logs
	recent history // closed connections, across rebuilds
	usage  usage   // bytes per exit of closed connections
	learn  sync.Mutex // the auto rules' learned files: read, changed, written

	mu     sync.Mutex
	cfg    model.Config
	out    *compile.Output
	inst   *instance
	closed bool
}

// instance is one running sing-box box plus the indexes we need to read it.
type instance struct {
	box     *box.Box
	ctx     context.Context
	cancel  context.CancelFunc
	traffic *trafficcontrol.Manager
	ruleIDs atomic.Pointer[map[adapter.Rule]string]
	stop    chan struct{}
}

// New prepares an engine that keeps its rule-set files and cache in dir.
func New(dir, secret string, logs *Logs) (*Engine, error) {
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o700); err != nil {
		return nil, err
	}
	return &Engine{
		env:  compile.Env{RulesDir: rules, CacheFile: filepath.Join(dir, "cache.db"), Secret: secret, LogOutput: os.DevNull},
		logs: logs,
	}, nil
}

// ApplyResult says how a config was applied.
type ApplyResult struct {
	Rebuilt bool `json:"rebuilt"`
}

// Apply makes cfg the running config. If only rule-set contents or group
// selections changed, it is applied in place and no connection drops.
// Otherwise the new config is validated, then swapped in (~100 ms). On an
// invalid config the running instance is left untouched.
func (e *Engine) Apply(cfg model.Config) (ApplyResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ApplyResult{}, errors.New("engine closed")
	}
	out, err := compile.Compile(cfg, e.env)
	if err != nil {
		return ApplyResult{}, err
	}
	if e.inst != nil && bytes.Equal(out.Options, e.out.Options) {
		e.writeFiles(out.Files, e.inst)
		e.cfg, e.out = cfg, out
		e.inst.index(out) // a renamed rule can keep identical options
		e.applySelections()
		return ApplyResult{}, nil
	}
	// sing-box reads local rule-sets when the instance is created, so the
	// files go first; on failure the previous ones are put back.
	e.writeFiles(out.Files, nil)
	next, err := e.newInstance(out)
	if err != nil {
		if e.out != nil {
			e.writeFiles(e.out.Files, nil)
		}
		return ApplyResult{}, err
	}
	if e.inst != nil {
		e.inst.close()
		e.inst = nil
	}
	if err := next.start(); err != nil {
		next.close()
		// Bring the previous config back so a bad start (a port in use, say)
		// never leaves the user with nothing.
		if e.out == nil {
			return ApplyResult{}, fmt.Errorf("start: %w", err)
		}
		e.writeFiles(e.out.Files, nil)
		prev, perr := e.newInstance(e.out)
		if perr == nil {
			if perr = prev.start(); perr != nil {
				prev.close()
			}
		}
		if perr != nil {
			return ApplyResult{}, fmt.Errorf("start: %w; restoring the previous config also failed, so the engine is stopped: %v", err, perr)
		}
		e.inst = prev
		e.applySelections()
		go e.watch(prev)
		return ApplyResult{}, fmt.Errorf("start: %w (the previous config is running again)", err)
	}
	e.inst, e.cfg, e.out = next, cfg, out
	e.applySelections()
	go e.watch(next)
	return ApplyResult{Rebuilt: true}, nil
}

// Check validates cfg against the core without touching the running instance.
// It compiles into a scratch rules dir so new rules can be checked too.
func (e *Engine) Check(cfg model.Config) error {
	dir, err := os.MkdirTemp("", "moley-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	out, err := compile.Compile(cfg, compile.Env{RulesDir: dir, Secret: e.env.Secret, LogOutput: os.DevNull,
		// A log writer makes sing-box open a cache file; keep it in dir.
		CacheFile: filepath.Join(dir, "cache.db")})
	if err != nil {
		return err
	}
	for name, content := range out.Files {
		if content == nil {
			content = compile.RuleSetJSON(model.Match{})
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(boxContext())
	defer cancel()
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, out.Options)
	if err != nil {
		return err
	}
	b, err := box.New(box.Options{Options: opts, Context: ctx, PlatformLogWriter: discard{}})
	if err != nil {
		return err
	}
	return b.Close()
}

func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if e.inst != nil {
		e.inst.close()
		e.inst = nil
	}
	return nil
}

// Running reports whether an instance is up.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inst != nil
}

func boxContext() context.Context {
	ctx := context.Background()
	outbounds := include.OutboundRegistry()
	awg.Register(outbounds)
	return box.Context(ctx, include.InboundRegistry(), outbounds, include.EndpointRegistry(),
		include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
}

func (e *Engine) newInstance(out *compile.Output) (*instance, error) {
	ctx, cancel := context.WithCancel(boxContext())
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, out.Options)
	if err != nil {
		cancel()
		return nil, err
	}
	b, err := box.New(box.Options{Options: opts, Context: ctx, PlatformLogWriter: e.logs})
	if err != nil {
		cancel()
		return nil, err
	}
	inst := &instance{box: b, ctx: ctx, cancel: cancel, stop: make(chan struct{})}
	inst.traffic = service.PtrFromContext[trafficcontrol.Manager](ctx)
	inst.index(out)
	return inst, nil
}

// index maps the running route rules to Moley rule ids.
func (i *instance) index(out *compile.Output) {
	ids := map[adapter.Rule]string{}
	for n, r := range i.box.Router().Rules() {
		if n < len(out.RuleIDs) && out.RuleIDs[n] != "" {
			ids[r] = out.RuleIDs[n]
		}
	}
	i.ruleIDs.Store(&ids)
}

// ruleID names the Moley rule behind a matched core rule.
func (i *instance) ruleID(r adapter.Rule) (string, bool) {
	id, ok := (*i.ruleIDs.Load())[r]
	return id, ok
}

func (i *instance) start() error { return i.box.Start() }

func (i *instance) close() {
	close(i.stop)
	_ = i.box.Close()
	i.cancel()
}

// writeFiles writes rule-set files whose content changed. With a running
// instance it waits (briefly) for sing-box to reload each one, so a caller
// that changes a rule and immediately probes sees the new rule.
func (e *Engine) writeFiles(files map[string][]byte, inst *instance) {
	var wg sync.WaitGroup
	for name, content := range files {
		path := filepath.Join(e.env.RulesDir, name)
		old, err := os.ReadFile(path)
		if content == nil {
			if err != nil {
				_ = writeAtomic(path, compile.RuleSetJSON(model.Match{}))
			}
			continue
		}
		if err == nil && bytes.Equal(old, content) {
			continue
		}
		var done chan struct{}
		if inst != nil {
			if rs, ok := inst.box.Router().RuleSet(trimJSON(name)); ok {
				done = make(chan struct{})
				var once sync.Once
				el := rs.RegisterCallback(func(adapter.RuleSet) { once.Do(func() { close(done) }) })
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer rs.UnregisterCallback(el)
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						e.logs.Warn("rule-set reload not observed: " + name)
					}
				}()
			}
		}
		if err := writeAtomic(path, content); err != nil {
			e.logs.Error("write " + name + ": " + err.Error())
		}
	}
	wg.Wait()
}

func trimJSON(name string) string { return name[:len(name)-len(".json")] }

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// applySelections pushes the default exit and persisted manual-group picks
// into the running selectors. It is an in-process call and never rebuilds.
func (e *Engine) applySelections() {
	def := e.cfg.DefaultExit
	if def == "" {
		def = model.ExitDirect
	}
	e.inst.selectIn(compile.DefaultOutbound, def)
	for _, x := range e.cfg.Exits {
		if x.Group == model.GroupManual && x.Selected != "" {
			e.inst.selectIn(x.ID, x.Selected)
		}
	}
}

func (i *instance) selectIn(selector, member string) {
	if ob, ok := i.box.Outbound().Outbound(selector); ok {
		if sel, ok := ob.(*group.Selector); ok {
			sel.SelectOutbound(member)
		}
	}
}

// current returns the running instance and the output it was built from.
func (e *Engine) current() (*instance, *compile.Output, model.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inst, e.out, e.cfg
}
