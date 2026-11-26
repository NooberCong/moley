package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"moley/internal/importer"
	"moley/internal/model"
	"moley/internal/platform"
	"moley/internal/rpc"
)

type method struct {
	desc   string
	params reflect.Type
	call   func(ctx context.Context, d *Daemon, c platform.Caller, raw json.RawMessage) (any, error)
}

// def declares a method with typed params.
func def[P any](desc string, f func(ctx context.Context, d *Daemon, c platform.Caller, p P) (any, error)) method {
	return method{desc: desc, params: reflect.TypeFor[P](), call: func(ctx context.Context, d *Daemon, c platform.Caller, raw json.RawMessage) (any, error) {
		var p P
		if len(raw) > 0 && string(raw) != "null" {
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "params: %v", err)
			}
		}
		return f(ctx, d, c, p)
	}}
}

type none struct{}

var methods map[string]method

func init() {
	methods = map[string]method{
		"status":           def("Daemon, engine and per-profile state.", status),
		"client.hello":     def("Proxy ports and hint secret for clients (extension, exec).", hello),
		"profiles.import":  def("Import profiles from file content, links or a subscription body.", importProfiles),
		"profiles.list":    def("List profiles with live state.", listProfiles),
		"profiles.update":  def("Change a profile's name or auto rule.", updateProfile),
		"profiles.remove":  def("Remove a profile (needs yes).", removeProfile),
		"profiles.test":    def("Fetch the IP-echo URL through an exit: latency, exit IP, country.", testExit),
		"exits.list":       def("List every exit: built-ins, profiles and groups.", listExits),
		"exits.put":        def("Create or replace a group exit.", putExit),
		"exits.remove":     def("Remove a group exit (needs yes).", removeExit),
		"exits.select":     def("Pick the member of a manual group (no rebuild).", selectExit),
		"rules.list":       def("List rules in match order, with auto rules and quick picks.", listRules),
		"rules.show":       def("Show one rule; auto-<profile> shows the pushed and learned routes.", showRule),
		"rules.put":        def("Create or replace a rule; index inserts a new rule at that position.", putRule),
		"rules.forget":     def("Clear what an auto rule learned.", forgetRule),
		"rules.remove":     def("Remove a rule (needs yes).", removeRule),
		"rules.move":       def("Move a rule to a new index.", moveRule),
		"quick.set":        def("Route a host (and its subdomains) via an exit; empty exit clears (no rebuild).", setQuick),
		"default.set":      def("Set the exit for traffic no rule matches.", setDefault),
		"dns.set":          def("How the direct exit looks up names: a DNS-over-HTTPS URL, system (the OS resolver), or empty for the default.", setDNS),
		"holds.put":        def("Keep the network adapter up for a while (system mode), without changing where anything goes. Putting a name again renews it; each hold lapses on its own.", putHold),
		"holds.release":    def("Release a hold by name; releasing one that's gone is not an error.", releaseHold),
		"config.export":    def("The whole config; secrets redacted unless reveal.", exportConfig),
		"config.apply":     def("Replace the whole config; dry_run returns the diff only.", applyConfig),
		"history.list":     def("The audit log: who changed what.", listHistory),
		"probe":            def("Make a real request through the engine and report rule, exit and resolver.", probe),
		"wait":             def("Block until a profile is connected or an exit is healthy.", wait),
		"conns.list":       def("Connections and the rule and exit each actually used.", listConns),
		"logs":             def("Recent daemon and core log lines.", logs),
		"rpc.methods":      def("Describe every method and its params.", listMethods),
		"daemon.stop":      def("Stop the daemon.", stopDaemon),
		"mode.set":         def("System mode: tun routes every app; kill_switch off|on|persistent (persistent needs yes). Needs the service.", setMode),
		"events.subscribe": def("Stream status, traffic and (with conns) open connections as they change, until the client disconnects.", subscribe),
	}
}

// --- state -----------------------------------------------------------------

type ProfileInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Kind     string   `json:"kind"`
	Source   string   `json:"source,omitempty"`
	Via      string   `json:"via,omitempty"`
	AutoRule bool     `json:"auto_rule,omitempty"`
	DNS      []string `json:"dns,omitempty"`
	State    string   `json:"state"`
	Error    string   `json:"error,omitempty"`
}

type StatusResult struct {
	Version     string        `json:"version"`
	Running     bool          `json:"running"`
	ProxyPort   uint16        `json:"proxy_port"`
	DefaultExit string        `json:"default_exit"`
	DirectDNS   string        `json:"direct_dns"` // a DNS-over-HTTPS URL or "system"
	Profiles    []ProfileInfo `json:"profiles"`
	Exits       []string      `json:"exits"`
	Rules       int           `json:"rules"`
	QuickPicks  int           `json:"quick_picks"`
	Mode        ModeInfo      `json:"mode"`
	Holds       []Hold        `json:"holds"`
}

type ModeInfo struct {
	TUN        bool   `json:"tun"`
	KillSwitch string `json:"kill_switch"`
	// Service: this daemon is the privileged service and can run system
	// mode; a per-user daemon routes the browser and exec only.
	Service bool `json:"service"`
	// SystemRouting: the adapter is up now, so every program follows the
	// rules, not just the browser and `moley exec`. System mode brings it up
	// while you're connected, a kill switch is on, or a client holds it.
	SystemRouting bool   `json:"system_routing"`
	Error         string `json:"error,omitempty"`
}

func status(_ context.Context, d *Daemon, _ platform.Caller, _ none) (any, error) {
	d.mu.Lock()
	cfg, modeErr, holds := d.cfg.Clone(), d.modeErr, d.activeHolds()
	d.mu.Unlock()
	return StatusResult{
		Version: Version, Running: d.engine.Running(), ProxyPort: cfg.Settings.Port(),
		DefaultExit: or(cfg.DefaultExit, model.ExitDirect), DirectDNS: or(cfg.Settings.DirectDNS, model.DefaultDirectDNS),
		Profiles: d.profileInfos(cfg),
		Exits:    cfg.ExitIDs(), Rules: len(cfg.Rules), QuickPicks: len(cfg.Quick),
		Mode: ModeInfo{TUN: cfg.Mode.TUN, KillSwitch: cfg.Mode.Kill(), Service: platform.System(),
			SystemRouting: cfg.SystemRouting(len(holds) > 0), Error: modeErr},
		Holds: holds,
	}, nil
}

func (d *Daemon) profileInfos(cfg model.Config) []ProfileInfo {
	res := make([]ProfileInfo, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		st := d.engine.State(p.ID)
		res = append(res, ProfileInfo{ID: p.ID, Name: p.Name, Kind: p.Kind, Source: p.Source, Via: p.Via,
			AutoRule: p.AutoRule, DNS: p.DNS, State: st.State, Error: st.Error})
	}
	return res
}

type HelloResult struct {
	Version   string   `json:"version"`
	ProxyPort uint16   `json:"proxy_port"`
	HintPort  uint16   `json:"hint_port"`
	Secret    string   `json:"secret,omitempty"`
	Exits     []string `json:"exits"`
}

type HelloParams struct {
	// NoSecret leaves out the hint secret; the browser relay always sets it
	// (Chromium can't use the hint inbound).
	NoSecret bool `json:"no_secret,omitempty"`
}

func hello(_ context.Context, d *Daemon, _ platform.Caller, p HelloParams) (any, error) {
	cfg := d.config()
	res := HelloResult{Version: Version, ProxyPort: cfg.Settings.Port(), HintPort: cfg.Settings.Port() + 1, Exits: cfg.ExitIDs()}
	if !p.NoSecret {
		res.Secret = d.secret
	}
	return res, nil
}

// --- profiles ----------------------------------------------------------------

type ImportParams struct {
	Data     string `json:"data"`
	Name     string `json:"name,omitempty"`      // file name hint
	ID       string `json:"id,omitempty"`        // override; single profile only
	AutoRule *bool  `json:"auto_rule,omitempty"` // override the importer default
	Replace  bool   `json:"replace,omitempty"`   // overwrite profiles with the same id
	// KeyPassword decrypts an encrypted private key at import; only the
	// decrypted key is kept (sealed at rest).
	KeyPassword string `json:"key_password,omitempty"`
}

type ImportResult struct {
	Profiles []ProfileInfo `json:"profiles"`
	Warnings []string      `json:"warnings"`
	Rebuilt  bool          `json:"rebuilt"`
}

func importProfiles(_ context.Context, d *Daemon, c platform.Caller, p ImportParams) (any, error) {
	res, err := importer.ParseWith(p.Name, []byte(p.Data), importer.Options{KeyPassword: p.KeyPassword})
	if errors.Is(err, importer.ErrKeyEncrypted) {
		return nil, rpc.Errorf("key_password_required", "pipe the password in: moley import <file> --key-password-stdin", "the profile's private key is encrypted")
	}
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "%v", err)
	}
	if p.ID != "" {
		if len(res.Profiles) != 1 {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "drop --id to keep the generated ids", "--id needs exactly one profile, input has %d", len(res.Profiles))
		}
		res.Profiles[0].ID = p.ID
	}
	var ids []string
	applied, _, err := d.mutate(c, "profiles.import", false, func(cfg *model.Config) (string, error) {
		for _, np := range res.Profiles {
			if p.AutoRule != nil && np.Kind == model.KindOpenVPN {
				np.AutoRule = *p.AutoRule
			}
			if old := cfg.Profile(np.ID); old != nil {
				if !p.Replace {
					return "", rpc.Errorf(rpc.CodeInvalidParams, "pass replace (--replace) to overwrite it, or --id to import under another id", "profile %q already exists", np.ID)
				}
				// Replacing updates the connection, not how it's used: keep
				// the name, the chain, and the auto rule unless asked otherwise.
				np.Name, np.Via = old.Name, old.Via
				if p.AutoRule == nil && np.Kind == old.Kind {
					np.AutoRule = old.AutoRule
				}
				*old = np
			} else {
				cfg.Profiles = append(cfg.Profiles, np)
			}
			ids = append(ids, np.ID+" ("+np.Kind+")")
		}
		return "import " + strings.Join(ids, ", "), nil
	})
	if err != nil {
		return nil, err
	}
	out := ImportResult{Warnings: orEmpty(res.Warnings), Rebuilt: applied.Rebuilt}
	cfg := d.config()
	for _, info := range d.profileInfos(cfg) {
		for _, np := range res.Profiles {
			if info.ID == np.ID {
				out.Profiles = append(out.Profiles, info)
			}
		}
	}
	return out, nil
}

type UpdateProfileParams struct {
	ID       string  `json:"id"`
	Name     *string `json:"name,omitempty"`      // "" clears it
	AutoRule *bool   `json:"auto_rule,omitempty"` // OpenVPN only
}

func updateProfile(_ context.Context, d *Daemon, c platform.Caller, p UpdateProfileParams) (any, error) {
	res, summary, err := d.mutate(c, "profiles.update", false, func(cfg *model.Config) (string, error) {
		pr := cfg.Profile(p.ID)
		if pr == nil {
			return "", rpc.Errorf(rpc.CodeNotFound, "`moley profiles` lists them", "no profile %q", p.ID)
		}
		if p.Name != nil {
			pr.Name = strings.TrimSpace(*p.Name)
		}
		if p.AutoRule != nil {
			pr.AutoRule = *p.AutoRule
		}
		return "update profile " + p.ID, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": p.ID, "rebuilt": res.Rebuilt, "summary": summary}, nil
}

func listProfiles(_ context.Context, d *Daemon, _ platform.Caller, _ none) (any, error) {
	return d.profileInfos(d.config()), nil
}

type RemoveParams struct {
	ID  string `json:"id"`
	Yes bool   `json:"yes,omitempty"`
}

func removeProfile(_ context.Context, d *Daemon, c platform.Caller, p RemoveParams) (any, error) {
	return d.remove(c, "profiles.remove", p, func(cfg *model.Config) bool {
		i := slices.IndexFunc(cfg.Profiles, func(x model.Profile) bool { return x.ID == p.ID })
		if i < 0 {
			return false
		}
		cfg.Profiles = slices.Delete(cfg.Profiles, i, i+1)
		return true
	})
}

// remove deletes an exit target after checking nothing points at it.
func (d *Daemon) remove(c platform.Caller, method string, p RemoveParams, del func(*model.Config) bool) (any, error) {
	if refs := references(d.config(), p.ID); len(refs) > 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "change or remove those first", "%q is still used by %s", p.ID, strings.Join(refs, ", "))
	}
	if !p.Yes {
		return nil, rpc.Errorf(rpc.CodeConfirm, "pass yes (--yes) to confirm", "this would remove %q", p.ID)
	}
	res, _, err := d.mutate(c, method, false, func(cfg *model.Config) (string, error) {
		if !del(cfg) {
			return "", rpc.Errorf(rpc.CodeNotFound, "", "%q not found", p.ID)
		}
		return "remove " + p.ID, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"removed": p.ID, "rebuilt": res.Rebuilt}, nil
}

// references lists what points at exit id.
func references(cfg model.Config, id string) []string {
	var refs []string
	for _, r := range cfg.Rules {
		if r.Exit == id {
			refs = append(refs, "rule "+r.ID)
		}
	}
	for _, e := range cfg.Exits {
		if slices.Contains(e.Members, id) {
			refs = append(refs, "exit "+e.ID)
		}
	}
	for _, p := range cfg.Profiles {
		if p.Via == id {
			refs = append(refs, "profile "+p.ID+" (via)")
		}
	}
	for host, exit := range cfg.Quick {
		if exit == id {
			refs = append(refs, "quick pick "+host)
		}
	}
	if cfg.DefaultExit == id {
		refs = append(refs, "default_exit")
	}
	sort.Strings(refs)
	return refs
}

type ExitParams struct {
	Exit string `json:"exit"`
}

func testExit(ctx context.Context, d *Daemon, _ platform.Caller, p ExitParams) (any, error) {
	if p.Exit == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "exit is required")
	}
	info, err := d.engine.Test(ctx, p.Exit)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "%v", err)
	}
	return info, nil
}

// --- exits -------------------------------------------------------------------

type ExitInfo struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`     // profiles: display name
	Kind     string   `json:"kind"`               // builtin | profile | group
	Protocol string   `json:"protocol,omitempty"` // profiles: wireguard, openvpn, ...
	Group    string   `json:"group,omitempty"`
	Members  []string `json:"members,omitempty"`
	Selected string   `json:"selected,omitempty"`
	State    string   `json:"state,omitempty"` // profiles: live state
}

func listExits(_ context.Context, d *Daemon, _ platform.Caller, _ none) (any, error) {
	cfg := d.config()
	res := []ExitInfo{{ID: model.ExitDirect, Kind: "builtin"}, {ID: model.ExitBlock, Kind: "builtin"}}
	for _, p := range cfg.Profiles {
		res = append(res, ExitInfo{ID: p.ID, Name: p.Name, Kind: "profile", Protocol: p.Kind, State: d.engine.State(p.ID).State})
	}
	for _, e := range cfg.Exits {
		res = append(res, ExitInfo{ID: e.ID, Kind: "group", Group: e.Group, Members: e.Members, Selected: e.Selected})
	}
	return res, nil
}

func putExit(_ context.Context, d *Daemon, c platform.Caller, p model.Exit) (any, error) {
	res, summary, err := d.mutate(c, "exits.put", false, func(cfg *model.Config) (string, error) {
		if old := cfg.Exit(p.ID); old != nil {
			*old = p
			return "update exit " + p.ID, nil
		}
		cfg.Exits = append(cfg.Exits, p)
		return "add exit " + p.ID, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"exit": p, "rebuilt": res.Rebuilt, "summary": summary}, nil
}

func removeExit(_ context.Context, d *Daemon, c platform.Caller, p RemoveParams) (any, error) {
	return d.remove(c, "exits.remove", p, func(cfg *model.Config) bool {
		i := slices.IndexFunc(cfg.Exits, func(x model.Exit) bool { return x.ID == p.ID })
		if i < 0 {
			return false
		}
		cfg.Exits = slices.Delete(cfg.Exits, i, i+1)
		return true
	})
}

type SelectParams struct {
	ID     string `json:"id"`
	Member string `json:"member"`
}

func selectExit(_ context.Context, d *Daemon, c platform.Caller, p SelectParams) (any, error) {
	res, _, err := d.mutate(c, "exits.select", false, func(cfg *model.Config) (string, error) {
		e := cfg.Exit(p.ID)
		if e == nil || e.Group != model.GroupManual {
			return "", rpc.Errorf(rpc.CodeNotFound, "", "no manual group %q", p.ID)
		}
		e.Selected = p.Member
		return fmt.Sprintf("select %s → %s", p.ID, p.Member), nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": p.ID, "selected": p.Member, "rebuilt": res.Rebuilt}, nil
}

// --- rules -------------------------------------------------------------------

type RulesResult struct {
	Rules       []model.Rule      `json:"rules"`
	Auto        []string          `json:"auto"`  // auto rule ids, matched before rules
	Quick       map[string]string `json:"quick"` // matched first
	DefaultExit string            `json:"default_exit"`
}

func listRules(_ context.Context, d *Daemon, _ platform.Caller, _ none) (any, error) {
	cfg := d.config()
	res := RulesResult{Rules: orEmpty(cfg.Rules), Auto: []string{}, Quick: cfg.Quick, DefaultExit: or(cfg.DefaultExit, model.ExitDirect)}
	if res.Quick == nil {
		res.Quick = map[string]string{}
	}
	for _, p := range cfg.Profiles {
		if p.AutoRule {
			res.Auto = append(res.Auto, model.AutoRuleID(p.ID))
		}
	}
	return res, nil
}

type IDParams struct {
	ID string `json:"id"`
}

func showRule(_ context.Context, d *Daemon, _ platform.Caller, p IDParams) (any, error) {
	if prof, ok := strings.CutPrefix(p.ID, "auto-"); ok {
		ar, err := d.engine.AutoRule(prof)
		if err != nil {
			return nil, rpc.Errorf(rpc.CodeNotFound, "", "%v", err)
		}
		return ar, nil
	}
	cfg := d.config()
	if r := cfg.Rule(p.ID); r != nil {
		return r, nil
	}
	return nil, rpc.Errorf(rpc.CodeNotFound, "`moley rules` lists them", "no rule %q", p.ID)
}

type PutRuleParams struct {
	Rule  model.Rule `json:"rule"`
	Index *int       `json:"index,omitempty"`
}

func putRule(_ context.Context, d *Daemon, c platform.Caller, p PutRuleParams) (any, error) {
	res, summary, err := d.mutate(c, "rules.put", false, func(cfg *model.Config) (string, error) {
		if old := cfg.Rule(p.Rule.ID); old != nil {
			*old = p.Rule
			return fmt.Sprintf("update rule %s → %s", p.Rule.ID, p.Rule.Exit), nil
		}
		i := len(cfg.Rules)
		if p.Index != nil {
			i = max(0, min(*p.Index, len(cfg.Rules)))
		}
		cfg.Rules = slices.Insert(cfg.Rules, i, p.Rule)
		return fmt.Sprintf("add rule %s → %s at %d", p.Rule.ID, p.Rule.Exit, i), nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"rule": p.Rule, "rebuilt": res.Rebuilt, "summary": summary}, nil
}

// forgetRule clears what an auto rule learned, e.g. after the server's push
// changed; it learns again from the live push.
func forgetRule(_ context.Context, d *Daemon, _ platform.Caller, p IDParams) (any, error) {
	profile, ok := strings.CutPrefix(p.ID, "auto-")
	if !ok {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "only auto rules learn: auto-<profile>", "%q is not an auto rule", p.ID)
	}
	if err := d.engine.Forget(profile); err != nil {
		return nil, rpc.Errorf(rpc.CodeNotFound, "`moley rules` lists them", "%v", err)
	}
	return map[string]any{"forgot": p.ID}, nil
}

func removeRule(_ context.Context, d *Daemon, c platform.Caller, p RemoveParams) (any, error) {
	if !p.Yes {
		return nil, rpc.Errorf(rpc.CodeConfirm, "pass yes (--yes) to confirm", "this would remove rule %q", p.ID)
	}
	res, _, err := d.mutate(c, "rules.remove", false, func(cfg *model.Config) (string, error) {
		i := slices.IndexFunc(cfg.Rules, func(r model.Rule) bool { return r.ID == p.ID })
		if i < 0 {
			return "", rpc.Errorf(rpc.CodeNotFound, "", "no rule %q", p.ID)
		}
		cfg.Rules = slices.Delete(cfg.Rules, i, i+1)
		return "remove rule " + p.ID, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"removed": p.ID, "rebuilt": res.Rebuilt}, nil
}

type MoveParams struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

func moveRule(_ context.Context, d *Daemon, c platform.Caller, p MoveParams) (any, error) {
	res, _, err := d.mutate(c, "rules.move", false, func(cfg *model.Config) (string, error) {
		i := slices.IndexFunc(cfg.Rules, func(r model.Rule) bool { return r.ID == p.ID })
		if i < 0 {
			return "", rpc.Errorf(rpc.CodeNotFound, "", "no rule %q", p.ID)
		}
		r := cfg.Rules[i]
		cfg.Rules = slices.Delete(cfg.Rules, i, i+1)
		to := max(0, min(p.Index, len(cfg.Rules)))
		cfg.Rules = slices.Insert(cfg.Rules, to, r)
		return fmt.Sprintf("move rule %s to %d", p.ID, to), nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": p.ID, "index": p.Index, "rebuilt": res.Rebuilt}, nil
}

type QuickParams struct {
	Host string `json:"host"`
	Exit string `json:"exit,omitempty"` // empty clears
}

func setQuick(_ context.Context, d *Daemon, c platform.Caller, p QuickParams) (any, error) {
	host := model.NormalizeHost(p.Host)
	if host == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "host is required")
	}
	res, summary, err := d.mutate(c, "quick.set", false, func(cfg *model.Config) (string, error) {
		if p.Exit == "" {
			delete(cfg.Quick, host)
			return "quick " + host + " cleared", nil
		}
		if cfg.Quick == nil {
			cfg.Quick = map[string]string{}
		}
		cfg.Quick[host] = p.Exit
		return "quick " + host + " → " + p.Exit, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"host": host, "exit": p.Exit, "rebuilt": res.Rebuilt, "summary": summary}, nil
}

func setDefault(_ context.Context, d *Daemon, c platform.Caller, p ExitParams) (any, error) {
	res, _, err := d.mutate(c, "default.set", false, func(cfg *model.Config) (string, error) {
		cfg.DefaultExit = p.Exit
		return "default exit → " + p.Exit, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"default_exit": p.Exit, "rebuilt": res.Rebuilt}, nil
}

type DNSParams struct {
	DirectDNS string `json:"direct_dns"`
}

func setDNS(_ context.Context, d *Daemon, c platform.Caller, p DNSParams) (any, error) {
	if p.DirectDNS == model.DefaultDirectDNS {
		p.DirectDNS = "" // the default is stored as unset, so it follows a new default
	}
	shown := or(p.DirectDNS, model.DefaultDirectDNS)
	res, _, err := d.mutate(c, "dns.set", false, func(cfg *model.Config) (string, error) {
		cfg.Settings.DirectDNS = p.DirectDNS
		return "direct dns → " + shown, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"direct_dns": shown, "rebuilt": res.Rebuilt}, nil
}

// --- config ------------------------------------------------------------------

// redacted replaces a profile config in exports; applying it keeps the
// existing secret.
var redacted = json.RawMessage(`"redacted"`)

type ExportParams struct {
	Reveal bool `json:"reveal,omitempty"`
}

func exportConfig(_ context.Context, d *Daemon, c platform.Caller, p ExportParams) (any, error) {
	cfg := d.config()
	if p.Reveal {
		d.audit(AuditEntry{Method: "config.export", Caller: c.String(), Summary: "export with secrets revealed"})
	} else {
		for i := range cfg.Profiles {
			cfg.Profiles[i].Config = redacted
		}
	}
	return cfg, nil
}

type ApplyParams struct {
	Config model.Config `json:"config"`
	DryRun bool         `json:"dry_run,omitempty"`
	Yes    bool         `json:"yes,omitempty"`
}

type ApplyResult struct {
	Changes []string `json:"changes"`
	Applied bool     `json:"applied"`
	Rebuilt bool     `json:"rebuilt"`
}

func applyConfig(_ context.Context, d *Daemon, c platform.Caller, p ApplyParams) (any, error) {
	var changes []string
	res, _, err := d.mutate(c, "config.apply", p.DryRun, func(cfg *model.Config) (string, error) {
		next := p.Config
		for i := range next.Profiles {
			if string(next.Profiles[i].Config) == string(redacted) {
				old := cfg.Profile(next.Profiles[i].ID)
				if old == nil {
					return "", rpc.Errorf(rpc.CodeInvalidParams, "export with --reveal to move profiles between machines", "profile %q is redacted and doesn't exist here", next.Profiles[i].ID)
				}
				next.Profiles[i].Config = old.Config
			}
		}
		var deletes bool
		changes, deletes = diff(*cfg, next)
		if deletes && !p.Yes && !p.DryRun {
			return "", rpc.Errorf(rpc.CodeConfirm, "review with --dry-run, then pass --yes", "this apply removes things: %s", strings.Join(changes, "; "))
		}
		*cfg = next
		return "apply: " + or(strings.Join(changes, "; "), "no changes"), nil
	})
	if err != nil {
		return nil, err
	}
	return ApplyResult{Changes: orEmpty(changes), Applied: !p.DryRun, Rebuilt: res.Rebuilt}, nil
}

// diff summarizes what changes between two configs, and whether anything
// is removed.
func diff(a, b model.Config) (changes []string, deletes bool) {
	type item struct {
		kind string
		ids  func(model.Config) map[string]string
	}
	enc := func(v any) string { s, _ := json.Marshal(v); return string(s) }
	items := []item{
		{"profile", func(c model.Config) map[string]string {
			m := map[string]string{}
			for _, p := range c.Profiles {
				m[p.ID] = enc(p)
			}
			return m
		}},
		{"exit", func(c model.Config) map[string]string {
			m := map[string]string{}
			for _, e := range c.Exits {
				m[e.ID] = enc(e)
			}
			return m
		}},
		{"rule", func(c model.Config) map[string]string {
			m := map[string]string{}
			for _, r := range c.Rules {
				m[r.ID] = enc(r)
			}
			return m
		}},
		{"quick pick", func(c model.Config) map[string]string { return c.Quick }},
	}
	for _, it := range items {
		am, bm := it.ids(a), it.ids(b)
		for _, id := range sortedKeys(bm) {
			if old, ok := am[id]; !ok {
				changes = append(changes, "add "+it.kind+" "+id)
			} else if old != bm[id] {
				changes = append(changes, "change "+it.kind+" "+id)
			}
		}
		for _, id := range sortedKeys(am) {
			if _, ok := bm[id]; !ok {
				changes = append(changes, "remove "+it.kind+" "+id)
				deletes = true
			}
		}
	}
	order := func(c model.Config) []string {
		var ids []string
		for _, r := range c.Rules {
			ids = append(ids, r.ID)
		}
		return ids
	}
	if ao, bo := order(a), order(b); !slices.Equal(ao, bo) && len(ao) == len(bo) {
		changes = append(changes, "reorder rules")
	}
	if or(a.DefaultExit, model.ExitDirect) != or(b.DefaultExit, model.ExitDirect) {
		changes = append(changes, "default exit "+or(b.DefaultExit, model.ExitDirect))
	}
	if a.Settings != b.Settings {
		changes = append(changes, "change settings")
	}
	if a.Mode != b.Mode {
		changes = append(changes, fmt.Sprintf("mode tun=%v kill_switch=%s", b.Mode.TUN, b.Mode.Kill()))
	}
	return changes, deletes
}

type ModeParams struct {
	TUN        *bool   `json:"tun,omitempty"`
	KillSwitch *string `json:"kill_switch,omitempty"` // off | on | persistent
	Yes        bool    `json:"yes,omitempty"`
}

func setMode(_ context.Context, d *Daemon, c platform.Caller, p ModeParams) (any, error) {
	next := d.config().Mode
	if p.TUN != nil {
		next.TUN = *p.TUN
		if !next.TUN {
			next.KillSwitch = "" // nothing left to route through
		}
	}
	if p.KillSwitch != nil {
		next.KillSwitch = *p.KillSwitch
		if next.Kill() != model.KillSwitchOff {
			next.TUN = true
		}
	}
	if next.Kill() == model.KillSwitchPersistent && d.config().Mode.Kill() != model.KillSwitchPersistent && !p.Yes {
		return nil, rpc.Errorf(rpc.CodeConfirm, "pass yes (--yes) to confirm",
			"a persistent kill switch blocks all traffic outside Moley, even while Moley is stopped and after a reboot, until you turn it off")
	}
	res, summary, err := d.mutate(c, "mode.set", false, func(cfg *model.Config) (string, error) {
		cfg.Mode = next
		return fmt.Sprintf("mode tun=%v kill_switch=%s", next.TUN, next.Kill()), nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"tun": next.TUN, "kill_switch": next.Kill(), "rebuilt": res.Rebuilt, "summary": summary}, nil
}

type LimitParams struct {
	Limit int `json:"limit,omitempty"`
}

func listHistory(_ context.Context, d *Daemon, _ platform.Caller, p LimitParams) (any, error) {
	return d.history(or(p.Limit, 50))
}

// --- diagnose ----------------------------------------------------------------

type ProbeParams struct {
	URL  string `json:"url"`
	Exit string `json:"exit,omitempty"`
}

func probe(ctx context.Context, d *Daemon, _ platform.Caller, p ProbeParams) (any, error) {
	r, err := d.engine.Probe(ctx, p.URL, p.Exit)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "%v", err)
	}
	return r, nil
}

type WaitParams struct {
	Connected string `json:"connected,omitempty"` // profile id
	Healthy   string `json:"healthy,omitempty"`   // exit id
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

func wait(ctx context.Context, d *Daemon, _ platform.Caller, p WaitParams) (any, error) {
	if (p.Connected == "") == (p.Healthy == "") {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "give exactly one of connected or healthy")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(or(p.TimeoutMS, 30000))*time.Millisecond)
	defer cancel()
	cfg := d.config()
	if p.Connected != "" {
		if cfg.Profile(p.Connected) == nil {
			return nil, rpc.Errorf(rpc.CodeNotFound, "", "no profile %q", p.Connected)
		}
		st, err := d.engine.WaitConnected(ctx, p.Connected)
		if err != nil {
			return nil, rpc.Errorf(rpc.CodeCheckFailed, "see `moley logs`", "%v", err)
		}
		return st, nil
	}
	if !cfg.HasExit(p.Healthy) {
		return nil, rpc.Errorf(rpc.CodeNotFound, "", "no exit %q", p.Healthy)
	}
	for {
		r, ok := d.engine.Healthy(ctx, p.Healthy)
		if ok {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, rpc.Errorf(rpc.CodeCheckFailed, "see `moley logs`", "exit %q not healthy: %s", p.Healthy, or(r.Error, fmt.Sprintf("HTTP %d", r.Status)))
		case <-time.After(time.Second):
		}
	}
}

type ConnsParams struct {
	Host   string `json:"host,omitempty"`
	Closed bool   `json:"closed,omitempty"` // include recently closed
}

func listConns(_ context.Context, d *Daemon, _ platform.Caller, p ConnsParams) (any, error) {
	return orEmpty(d.engine.Conns(p.Host, p.Closed)), nil
}

type LogsParams struct {
	Since time.Time `json:"since,omitempty"`
	Limit int       `json:"limit,omitempty"`
}

func logs(_ context.Context, d *Daemon, _ platform.Caller, p LogsParams) (any, error) {
	return orEmpty(d.logs.Since(p.Since, or(p.Limit, 200))), nil
}

type MethodInfo struct {
	Method string            `json:"method"`
	Desc   string            `json:"desc"`
	Params map[string]string `json:"params"`
}

func stopDaemon(_ context.Context, d *Daemon, c platform.Caller, _ none) (any, error) {
	d.audit(AuditEntry{Method: "daemon.stop", Caller: c.String(), Summary: "stop"})
	d.stopOnce.Do(func() { close(d.stopped) })
	return map[string]any{"stopping": true}, nil
}

func listMethods(_ context.Context, _ *Daemon, _ platform.Caller, _ none) (any, error) {
	return Methods(), nil
}

// Methods describes the RPC surface (for `help --json`).
func Methods() []MethodInfo {
	var res []MethodInfo
	for _, name := range sortedKeys(methods) {
		m := methods[name]
		res = append(res, MethodInfo{Method: name, Desc: m.desc, Params: describe(m.params)})
	}
	return res
}

func describe(t reflect.Type) map[string]string {
	res := map[string]string{}
	if t.Kind() != reflect.Struct {
		return res
	}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		res[name] = f.Type.String()
	}
	return res
}

// --- helpers -----------------------------------------------------------------

func or[T comparable](v, d T) T {
	var zero T
	if v == zero {
		return d
	}
	return v
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
