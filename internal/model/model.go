// Package model holds Moley's user-facing configuration: profiles (imported
// connections), exits (what rules point at) and ordered rules. It has no
// dependency on the proxy core; internal/compile translates it.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Built-in exits that always exist.
const (
	ExitDirect = "direct"
	ExitBlock  = "block"
)

// Profile kinds. Config holds the core's options for that kind (sing-box
// outbound/endpoint JSON without "type" and "tag", or awg.Options).
const (
	KindWireGuard   = "wireguard"
	KindAmneziaWG   = "amneziawg"
	KindOpenVPN     = "openvpn"
	KindShadowsocks = "shadowsocks"
	KindVLESS       = "vless"
	KindVMess       = "vmess"
	KindTrojan      = "trojan"
	KindHysteria2   = "hysteria2"
	KindTUIC        = "tuic"
	KindSOCKS       = "socks"
	KindHTTP        = "http"
)

var kinds = []string{KindWireGuard, KindAmneziaWG, KindOpenVPN, KindShadowsocks, KindVLESS,
	KindVMess, KindTrojan, KindHysteria2, KindTUIC, KindSOCKS, KindHTTP}

// Group kinds for exits.
const (
	GroupManual  = "manual"  // user picks a member (sing-box selector)
	GroupFastest = "fastest" // lowest latency member (sing-box urltest)
)

type Config struct {
	Profiles []Profile `json:"profiles"`
	Exits    []Exit    `json:"exits"`
	Rules    []Rule    `json:"rules"`
	// Quick maps a host (domain suffix) to an exit. It is the extension's
	// one-click "route this site via X" and never triggers a rebuild.
	Quick       map[string]string `json:"quick,omitempty"`
	DefaultExit string            `json:"default_exit"`
	Settings    Settings          `json:"settings"`
	Mode        Mode              `json:"mode"`
}

// Mode is system-wide routing. It needs the privileged service: the
// per-user daemon routes the browser and `moley exec` only.
type Mode struct {
	// TUN routes every app on the machine through the rules, not just the
	// ones pointed at the proxy port.
	TUN bool `json:"tun,omitempty"`
	// KillSwitch blocks traffic that would leave outside Moley: "on" while
	// the daemon runs, "persistent" also while it is stopped and at boot.
	KillSwitch string `json:"kill_switch,omitempty"`
}

const (
	KillSwitchOff        = "off"
	KillSwitchOn         = "on"
	KillSwitchPersistent = "persistent"
)

// Kill reports the kill switch setting, "off" when unset.
func (m Mode) Kill() string { return or(m.KillSwitch, KillSwitchOff) }

type Settings struct {
	ProxyPort uint16 `json:"proxy_port,omitempty"` // mixed inbound, default 7890; hint inbound is ProxyPort+1
	// HealthURL must answer 2xx quickly; used by wait/test. IPURL returns
	// "ip=…" / "loc=…" lines (Cloudflare trace format).
	HealthURL string `json:"health_url,omitempty"`
	IPURL     string `json:"ip_url,omitempty"`
}

const (
	DefaultProxyPort = 7890
	DefaultHealthURL = "https://www.gstatic.com/generate_204"
	DefaultIPURL     = "https://www.cloudflare.com/cdn-cgi/trace"
)

func (s Settings) Port() uint16 {
	if s.ProxyPort == 0 {
		return DefaultProxyPort
	}
	return s.ProxyPort
}

func (s Settings) Health() string { return or(s.HealthURL, DefaultHealthURL) }
func (s Settings) IP() string     { return or(s.IPURL, DefaultIPURL) }

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"` // shown instead of the ID; free text
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"` // provenance, e.g. "file:work.ovpn"
	// Via dials this profile through another profile (chaining).
	Via string `json:"via,omitempty"`
	// AutoRule routes the routes and DNS domains the server pushes to this
	// profile (OpenVPN only).
	AutoRule bool `json:"auto_rule,omitempty"`
	// DNS lists resolvers reached through the tunnel (WireGuard/AmneziaWG
	// "DNS =" line). Domains routed to this profile resolve there.
	DNS    []string        `json:"dns,omitempty"`
	Config json.RawMessage `json:"config"`
}

// Exit is a named group of profiles. Every profile is also usable as an exit
// under its own ID, so explicit exits exist only for groups.
type Exit struct {
	ID       string   `json:"id"`
	Group    string   `json:"group"`
	Members  []string `json:"members"`
	Selected string   `json:"selected,omitempty"` // manual groups only
}

type Rule struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"` // shown instead of the ID; free text
	Exit  string `json:"exit"`
	Match Match  `json:"match"`
}

// Match fields are OR-ed: a connection matching any of them matches the rule.
type Match struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
	Port          []uint16 `json:"port,omitempty"`
	// RuleSet names remote lists: "geosite-<name>" or "geoip-<name>".
	RuleSet []string `json:"rule_set,omitempty"`
}

func (m Match) Empty() bool {
	return len(m.Domain)+len(m.DomainSuffix)+len(m.DomainKeyword)+len(m.DomainRegex)+
		len(m.IPCIDR)+len(m.ProcessName)+len(m.ProcessPath)+len(m.Port)+len(m.RuleSet) == 0
}

// AutoRuleID is the read-only rule generated for a profile with AutoRule.
func AutoRuleID(profileID string) string { return "auto-" + profileID }

const nameMax = 64 // display names of profiles and rules

var (
	idRe      =regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	ruleSetRe = regexp.MustCompile(`^geo(site|ip)-[a-z0-9!@._-]+$`)
)

func (c *Config) Profile(id string) *Profile {
	for i := range c.Profiles {
		if c.Profiles[i].ID == id {
			return &c.Profiles[i]
		}
	}
	return nil
}

func (c *Config) Exit(id string) *Exit {
	for i := range c.Exits {
		if c.Exits[i].ID == id {
			return &c.Exits[i]
		}
	}
	return nil
}

func (c *Config) Rule(id string) *Rule {
	for i := range c.Rules {
		if c.Rules[i].ID == id {
			return &c.Rules[i]
		}
	}
	return nil
}

// ExitIDs lists every valid rule target: built-ins, profiles, then groups.
func (c *Config) ExitIDs() []string {
	ids := []string{ExitDirect, ExitBlock}
	for _, p := range c.Profiles {
		ids = append(ids, p.ID)
	}
	for _, e := range c.Exits {
		ids = append(ids, e.ID)
	}
	return ids
}

func (c *Config) HasExit(id string) bool { return slices.Contains(c.ExitIDs(), id) }

// HasProcessRules reports whether any rule matches by program.
func (c *Config) HasProcessRules() bool {
	return slices.ContainsFunc(c.Rules, func(r Rule) bool { return len(r.Match.ProcessName)+len(r.Match.ProcessPath) > 0 })
}

// Validate checks referential integrity. It never inspects Config payloads;
// the core validates those when the config is compiled.
func (c *Config) Validate() error {
	seen := map[string]string{ExitDirect: "built-in", ExitBlock: "built-in"}
	claim := func(id, what string) error {
		if !idRe.MatchString(id) {
			return fmt.Errorf("%s id %q: use 1-48 chars of a-z, 0-9, '-' or '_'", what, id)
		}
		if prev, ok := seen[id]; ok {
			return fmt.Errorf("%s id %q is already used by a %s", what, id, prev)
		}
		seen[id] = what
		return nil
	}
	for _, p := range c.Profiles {
		if err := claim(p.ID, "profile"); err != nil {
			return err
		}
		if !slices.Contains(kinds, p.Kind) {
			return fmt.Errorf("profile %q: unknown kind %q", p.ID, p.Kind)
		}
		if utf8.RuneCountInString(p.Name) > nameMax {
			return fmt.Errorf("profile %q: the name is over %d characters", p.ID, nameMax)
		}
		if p.AutoRule && p.Kind != KindOpenVPN {
			return fmt.Errorf("profile %q: auto_rule needs an openvpn profile", p.ID)
		}
		if len(p.Config) == 0 {
			return fmt.Errorf("profile %q: missing config", p.ID)
		}
	}
	for _, p := range c.Profiles {
		if p.Via == "" {
			continue
		}
		if p.Via == p.ID || c.Profile(p.Via) == nil {
			return fmt.Errorf("profile %q: via %q is not another profile", p.ID, p.Via)
		}
	}
	for _, e := range c.Exits {
		if err := claim(e.ID, "exit"); err != nil {
			return err
		}
		if e.Group != GroupManual && e.Group != GroupFastest {
			return fmt.Errorf("exit %q: group must be %q or %q", e.ID, GroupManual, GroupFastest)
		}
		if len(e.Members) == 0 {
			return fmt.Errorf("exit %q: needs at least one member", e.ID)
		}
		for _, m := range e.Members {
			if m == e.ID || !c.HasExit(m) {
				return fmt.Errorf("exit %q: unknown member %q", e.ID, m)
			}
			if e.Group == GroupFastest && c.Profile(m) == nil {
				return fmt.Errorf("exit %q: fastest groups take profiles only, not %q", e.ID, m)
			}
		}
		if e.Selected != "" && !slices.Contains(e.Members, e.Selected) {
			return fmt.Errorf("exit %q: selected %q is not a member", e.ID, e.Selected)
		}
	}
	if err := c.checkGroupCycles(); err != nil {
		return err
	}
	for _, r := range c.Rules {
		if err := claim(r.ID, "rule"); err != nil {
			return err
		}
		if strings.HasPrefix(r.ID, "auto-") || strings.HasPrefix(r.ID, "quick-") || r.ID == "lan" || r.ID == "default" {
			return fmt.Errorf("rule %q: the auto- and quick- prefixes, lan and default are reserved", r.ID)
		}
		if utf8.RuneCountInString(r.Name) > nameMax {
			return fmt.Errorf("rule %q: the name is over %d characters", r.ID, nameMax)
		}
		if !c.HasExit(r.Exit) {
			return fmt.Errorf("rule %q: unknown exit %q", r.ID, r.Exit)
		}
		if r.Match.Empty() {
			return fmt.Errorf("rule %q: match is empty", r.ID)
		}
		if err := r.Match.validate(); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	for host, exit := range c.Quick {
		if NormalizeHost(host) != host || host == "" {
			return fmt.Errorf("quick pick %q: not a normalized host name", host)
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return fmt.Errorf("quick pick %q: quick picks take site names; route addresses with a rule's ip_cidr", host)
		}
		if !c.HasExit(exit) {
			return fmt.Errorf("quick pick %q: unknown exit %q", host, exit)
		}
	}
	switch c.Mode.Kill() {
	case KillSwitchOff:
	case KillSwitchOn, KillSwitchPersistent:
		if !c.Mode.TUN {
			return errors.New("mode.kill_switch: needs tun, so traffic has a way out through Moley")
		}
	default:
		return fmt.Errorf("mode.kill_switch: %q is not off, on or persistent", c.Mode.KillSwitch)
	}
	if c.Settings.ProxyPort == 65535 {
		return errors.New("settings.proxy_port: needs room for the hint port (proxy_port+1)")
	}
	if c.DefaultExit != "" && !c.HasExit(c.DefaultExit) {
		return fmt.Errorf("default_exit: unknown exit %q", c.DefaultExit)
	}
	return nil
}

func (c *Config) checkGroupCycles() error {
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(id string) error
	visit = func(id string) error {
		e := c.Exit(id)
		if e == nil {
			return nil
		}
		switch state[id] {
		case 1:
			return fmt.Errorf("exit %q: groups form a cycle", id)
		case 2:
			return nil
		}
		state[id] = 1
		for _, m := range e.Members {
			if err := visit(m); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, e := range c.Exits {
		if err := visit(e.ID); err != nil {
			return err
		}
	}
	return nil
}

func (m Match) validate() error {
	for _, s := range m.IPCIDR {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("ip_cidr %q is not a prefix or address", s)
			}
		}
	}
	for _, s := range m.DomainRegex {
		if _, err := regexp.Compile(s); err != nil {
			return fmt.Errorf("domain_regex %q: %w", s, err)
		}
	}
	for _, s := range m.RuleSet {
		if !ruleSetRe.MatchString(s) {
			return fmt.Errorf("rule_set %q: use geosite-<name> or geoip-<name>", s)
		}
	}
	return nil
}

// NormalizeHost lowercases a host and strips a trailing dot, port and
// leading "*." so it can be used as a domain suffix.
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, ok := strings.Cut(h, ":"); ok && !strings.Contains(h, "]") && strings.Count(h, ":") == 1 {
		h = host
	}
	h = strings.TrimPrefix(h, "*.")
	return strings.TrimSuffix(h, ".")
}
