// Package compile turns a Moley model into a sing-box configuration. It is a
// pure function: same model and env in, same bytes out.
//
// The output is split in two so routing edits stay cheap:
//   - Options: the sing-box config. If it changes, the engine rebuilds.
//   - Files: one local rule-set file per rule and per quick-pick exit.
//     sing-box watches these, so editing a match is a file write, not a
//     rebuild, and open connections survive.
package compile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"moley/internal/awg"
	"moley/internal/model"
)

// Inbound tags.
const (
	InboundMixed = "mixed" // browser and CLI: normal rules
	InboundHint  = "hint"  // proxy username = exit id forces that exit
	InboundTUN   = "tun"   // system mode: every app on the machine
)

// TUNName is the system-mode network interface.
const TUNName = "moley"

// DefaultOutbound is the selector everything no rule matches goes to. The
// engine picks the default exit in it at runtime, so connecting or
// disconnecting never changes Options and never rebuilds. (Not a valid
// exit id, so it can't clash with one.)
const DefaultOutbound = "moley:default"

// LANRuleID names the rule that keeps private addresses (printers, the
// router, DHCP) off the default exit; any earlier rule can still claim them.
const LANRuleID = "lan"

// Resolver labels (also DNS server tags).
const (
	ResolverLocal  = "local"  // the OS resolver
	ResolverRemote = "remote" // the proxy server resolves the name
	ResolverFake   = "fakeip" // system mode: apps get a placeholder address
)

// localNames resolve for real even in system mode: local networks, and
// the probes the OS uses to detect captive portals and set the clock.
var localNames = []string{
	"lan", "local", "localhost", "home.arpa",
	"msftconnecttest.com", "msftncsi.com", "time.windows.com", "pool.ntp.org", "time.google.com",
	"connectivitycheck.gstatic.com", "captive.apple.com", "detectportal.firefox.com", "nmcheck.gnome.org",
}

// HintUser is the proxy username that forces an exit on the hint inbound:
// the exit id itself. (No prefix: HTTP Basic auth can't carry a ':' in
// the username.)
func HintUser(exit string) string { return exit }

// QuickRuleID and the auto rule's learned list are rule-set tags too.
func QuickRuleID(exit string) string { return "quick-" + exit }

type Env struct {
	RulesDir  string // where rule-set files live
	CacheFile string // sing-box cache (remote rule-sets); empty disables
	Secret    string // password for the hint inbound
	LogLevel  string // sing-box level; default "info"
	// LogOutput is sing-box's own log sink. The engine sets os.DevNull and
	// reads logs through its platform writer instead.
	LogOutput string
}

type Output struct {
	Options []byte // sing-box JSON config
	// Files maps a file name in RulesDir to rule-set source JSON. A nil
	// value means "create empty if missing, never overwrite": the engine
	// owns those (auto rules learn from live traffic).
	Files map[string][]byte
	// RuleIDs names each route rule by index so the engine can report the
	// Moley rule a connection matched. Helper rules (resolve) are "".
	RuleIDs []string
	// Resolver says where names routed to each exit are resolved: "local",
	// "remote" (by the proxy server) or a tunnel DNS server tag.
	Resolver map[string]string
}

type (
	obj  = map[string]any
	list = []any
)

func Compile(cfg model.Config, env Env) (*Output, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	c := &compiler{cfg: cfg, env: env, out: &Output{Files: map[string][]byte{}, Resolver: map[string]string{}}}
	return c.run()
}

type compiler struct {
	cfg        model.Config
	env        Env
	out        *Output
	rules      list
	ruleSets   list
	remote     map[string]bool
	dnsServers list
	dnsRules   list
	directSets list // rule-sets whose traffic goes direct: real DNS in system mode
}

func (c *compiler) run() (*Output, error) {
	outbounds := list{obj{"type": "direct", "tag": model.ExitDirect}, obj{"type": "block", "tag": model.ExitBlock}}
	var endpoints list
	c.dnsServers = list{obj{"type": "local", "tag": ResolverLocal}}
	c.out.Resolver[model.ExitDirect] = ResolverLocal
	c.remote = map[string]bool{}

	for _, p := range c.cfg.Profiles {
		ob, endpoint, err := c.profile(p)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", p.ID, err)
		}
		if endpoint {
			endpoints = append(endpoints, ob)
		} else {
			outbounds = append(outbounds, ob)
		}
	}
	for _, e := range c.cfg.Exits {
		outbounds = append(outbounds, c.group(e))
	}
	// Block first: until the engine selects the default exit, nothing leaks.
	// Switching it closes open connections, so none stay on the old exit.
	members := list{model.ExitBlock}
	for _, id := range c.cfg.ExitIDs() {
		if id != model.ExitBlock {
			members = append(members, id)
		}
	}
	outbounds = append(outbounds, obj{"type": "selector", "tag": DefaultOutbound, "outbounds": members, "interrupt_exist_connections": true})

	// 0. System mode: learn each connection's name (TLS SNI, HTTP Host, or
	// the FakeIP it was given), and answer DNS ourselves.
	if c.cfg.SystemRouting() {
		c.helper(obj{"inbound": list{InboundTUN}, "action": "sniff"})
		c.helper(obj{"inbound": list{InboundTUN}, "protocol": list{"dns"}, "action": "hijack-dns"})
	}
	// 1. Hint inbound: the username names the exit. Sits above everything.
	var users list
	for _, id := range c.cfg.ExitIDs() {
		users = append(users, obj{"username": HintUser(id), "password": c.env.Secret})
		c.route(obj{"inbound": list{InboundHint}, "auth_user": list{HintUser(id)}}, id, "hint")
	}
	// 2. Quick picks, one pre-created rule per exit.
	byExit := map[string][]string{}
	for _, host := range sortedKeys(c.cfg.Quick) {
		byExit[c.cfg.Quick[host]] = append(byExit[c.cfg.Quick[host]], host)
	}
	for _, id := range c.cfg.ExitIDs() {
		tag := QuickRuleID(id)
		c.localSet(tag, RuleSetJSON(model.Match{DomainSuffix: byExit[id]}))
		c.route(obj{"rule_set": list{tag}}, id, tag)
		if id == model.ExitDirect {
			c.directSets = append(c.directSets, tag)
		}
	}
	// 3. Auto rules: what the OpenVPN server pushed (live), then what was
	// learned from earlier sessions so a down tunnel still fails closed.
	for _, p := range c.cfg.Profiles {
		if !p.AutoRule {
			continue
		}
		// No resolve step: the endpoint resolves these names itself, and the
		// DNS rule below sends them to the pushed resolver. When the tunnel
		// is down the dial then fails on the endpoint, visibly, instead of
		// at a resolve step before the connection is tracked.
		id := model.AutoRuleID(p.ID)
		c.addRule(obj{"preferred_by": list{p.ID}}, p.ID, id, false)
		c.localSet(id, nil)
		c.addRule(obj{"rule_set": list{id}}, p.ID, id, false)
		// DNS rules name the DNS server that follows the endpoint's push.
		c.dnsRules = append(c.dnsRules, obj{"preferred_by": list{c.out.Resolver[p.ID]}, "server": c.out.Resolver[p.ID]})
	}
	// 4. User rules, in order.
	for _, r := range c.cfg.Rules {
		tags := list{}
		local := r.Match
		local.RuleSet = nil
		if !local.Empty() {
			tag := "rule-" + r.ID
			c.localSet(tag, RuleSetJSON(local))
			tags = append(tags, tag)
		}
		for _, name := range r.Match.RuleSet {
			if !c.remote[name] {
				c.remote[name] = true
				c.ruleSets = append(c.ruleSets, remoteRuleSet(name))
			}
			tags = append(tags, name)
		}
		c.route(obj{"rule_set": tags}, r.Exit, r.ID)
		if r.Exit == model.ExitDirect {
			c.directSets = append(c.directSets, tags...)
		}
	}
	// 5. Private addresses stay on the LAN unless a rule above said otherwise.
	c.route(obj{"ip_is_private": true}, model.ExitDirect, LANRuleID)

	port :=c.cfg.Settings.Port()
	logLevel := c.env.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	inbounds := list{
		obj{"type": "mixed", "tag": InboundMixed, "listen": "127.0.0.1", "listen_port": port},
		obj{"type": "mixed", "tag": InboundHint, "listen": "127.0.0.1", "listen_port": port + 1, "users": users},
	}
	route := obj{
		"rules":    c.rules,
		"rule_set": orEmpty(c.ruleSets),
		"final":    DefaultOutbound,
		// Dials resolve for real; FakeIP is only ever handed to apps.
		"default_domain_resolver": obj{"server": ResolverLocal},
		// Process rules live in rule-set files the core can't see ahead of time.
		"find_process": c.cfg.HasProcessRules(),
	}
	if c.cfg.SystemRouting() {
		// Apps resolve names to placeholder addresses, so the real name is
		// known when they connect and routes exactly like the browser path.
		// Names that must work without Moley's routing resolve for real.
		// Both ranges are public space, so the LAN rule never claims a
		// placeholder address.
		c.dnsServers = append(c.dnsServers, obj{"type": "fakeip", "tag": ResolverFake,
			"inet4_range": "198.18.0.0/15", "inet6_range": "2001:2::/48"})
		c.dnsRules = append(c.dnsRules, obj{"domain_suffix": localNames, "server": ResolverLocal})
		if len(c.directSets) > 0 {
			c.dnsRules = append(c.dnsRules, obj{"rule_set": c.directSets, "server": ResolverLocal})
		}
		c.dnsRules = append(c.dnsRules, obj{"query_type": list{"A", "AAAA"}, "server": ResolverFake})
		inbounds = append(inbounds, obj{
			"type": "tun", "tag": InboundTUN, "interface_name": TUNName,
			"address": list{"172.23.251.1/30", "fdfe:6d6f:6c65::1/126"},
			"mtu":     9000, "auto_route": true, "strict_route": true, "stack": "mixed",
		})
		route["auto_detect_interface"] = true
	}
	opts := obj{
		"log":       obj{"level": logLevel, "output": c.env.LogOutput},
		"dns":       obj{"servers": c.dnsServers, "rules": orEmpty(c.dnsRules), "final": ResolverLocal},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
	}
	if len(endpoints) > 0 {
		opts["endpoints"] = endpoints
	}
	if c.env.CacheFile != "" {
		cache := obj{"enabled": true, "path": c.env.CacheFile}
		if c.cfg.SystemRouting() {
			cache["store_fakeip"] = true // apps keep their addresses across restarts
		}
		opts["experimental"] = obj{"cache_file": cache}
	}
	b, err := json.MarshalIndent(opts, "", "  ")
	if err != nil {
		return nil, err
	}
	c.out.Options = b
	return c.out, nil
}

// profile renders one profile as an outbound or endpoint and registers the
// resolver for names routed to it.
func (c *compiler) profile(p model.Profile) (ob obj, endpoint bool, err error) {
	ob = obj{}
	if err := json.Unmarshal(p.Config, &ob); err != nil {
		return nil, false, fmt.Errorf("config: %w", err)
	}
	ob["tag"] = p.ID
	if p.Via != "" {
		ob["detour"] = p.Via
	}
	c.out.Resolver[p.ID] = ResolverRemote
	switch p.Kind {
	case model.KindWireGuard:
		ob["type"], endpoint = "wireguard", true
		c.tunnelDNS(p)
	case model.KindAmneziaWG:
		ob["type"] = awg.Type
		ob["dns"] = p.DNS
		c.tunnelDNS(p)
	case model.KindOpenVPN:
		ob["type"], endpoint = "openvpn-client", true
		// Ahead of the profile's own filters: they match first.
		filters := list{}
		for _, text := range defaultRoutePushes {
			filters = append(filters, obj{"action": "ignore", "text": text})
		}
		if own, ok := ob["pull_filters"].([]any); ok {
			filters = append(filters, own...)
		}
		ob["pull_filters"] = filters
		tag := "pushed:" + p.ID
		c.dnsServers = append(c.dnsServers, obj{
			"type": "openvpn", "tag": tag, "endpoint": p.ID,
			"accept_default_resolvers": true, "accept_search_domain": true,
		})
		c.out.Resolver[p.ID] = tag
	default: // proxy protocols: sing-box type names match Moley kinds
		ob["type"] = p.Kind
	}
	return ob, endpoint, nil
}

// defaultRoutePushes are the pushed options (matched as line prefixes) that
// would claim the whole internet for an OpenVPN tunnel. Moley picks the
// default exit itself; taken as the server's networks they'd send every
// site through the VPN even while disconnected (block-ipv6 claims all of
// IPv6, which then fails in a tunnel without it).
var defaultRoutePushes = []string{
	"redirect-gateway", "block-ipv6",
	"route 0.0.0.0 0.0.0.0", "route 0.0.0.0 128.0.0.0", "route 128.0.0.0 128.0.0.0",
	"route-ipv6 ::/0", "route-ipv6 ::/1", "route-ipv6 8000::/1", "route-ipv6 2000::/3",
}

// tunnelDNS adds a resolver reached through the profile's tunnel. Without a
// configured DNS server, names fall back to the local resolver.
func (c *compiler) tunnelDNS(p model.Profile) {
	if len(p.DNS) == 0 {
		c.out.Resolver[p.ID] = ResolverLocal
		return
	}
	tag := "tunnel:" + p.ID
	c.dnsServers = append(c.dnsServers, obj{"type": "udp", "tag": tag, "server": p.DNS[0], "detour": p.ID})
	c.out.Resolver[p.ID] = tag
}

func (c *compiler) group(e model.Exit) obj {
	members := make(list, len(e.Members))
	resolver := ""
	for i, m := range e.Members {
		members[i] = m
		r := c.resolverOf(m)
		if i == 0 {
			resolver = r
		} else if r != resolver {
			resolver = "" // mixed: let each member resolve its own way
		}
	}
	if resolver != "" {
		c.out.Resolver[e.ID] = resolver
	}
	if e.Group == model.GroupFastest {
		return obj{"type": "urltest", "tag": e.ID, "outbounds": members, "url": c.cfg.Settings.Health(), "interval": "3m"}
	}
	// The selection is applied at runtime by the engine, so picking a
	// member never changes Options and never rebuilds.
	return obj{"type": "selector", "tag": e.ID, "outbounds": members}
}

func (c *compiler) resolverOf(exit string) string {
	if r, ok := c.out.Resolver[exit]; ok {
		return r
	}
	return ResolverRemote // block, or a group compiled later
}

// route appends a route rule. When the exit resolves names through a tunnel
// DNS server, a resolve rule goes first so the name never leaks to the
// local resolver.
func (c *compiler) route(match obj, exit, id string) { c.addRule(match, exit, id, true) }

// helper appends a non-routing rule (sniff, hijack-dns).
func (c *compiler) helper(rule obj) {
	c.rules = append(c.rules, rule)
	c.out.RuleIDs = append(c.out.RuleIDs, "")
}

func (c *compiler) addRule(match obj, exit, id string, resolve bool) {
	if r := c.out.Resolver[exit]; resolve && r != "" && r != ResolverLocal && r != ResolverRemote {
		c.rules = append(c.rules, with(match, obj{"action": "resolve", "server": r}))
		c.out.RuleIDs = append(c.out.RuleIDs, "")
	}
	c.rules = append(c.rules, with(match, obj{"action": "route", "outbound": exit}))
	c.out.RuleIDs = append(c.out.RuleIDs, id)
}

func (c *compiler) localSet(tag string, content []byte) {
	c.ruleSets = append(c.ruleSets, obj{"type": "local", "tag": tag, "format": "source",
		"path": filepath.Join(c.env.RulesDir, tag+".json")})
	c.out.Files[tag+".json"] = content
}

func with(a, b obj) obj {
	r := make(obj, len(a)+len(b))
	for k, v := range a {
		r[k] = v
	}
	for k, v := range b {
		r[k] = v
	}
	return r
}

// RuleSetJSON renders a match as a local rule-set file (sing-box source
// format). Each field becomes its own rule: rules in a rule-set are OR-ed,
// while fields inside one rule are AND-ed across groups (address, process,
// port), and a Moley match means "any of these". An empty match still
// yields a valid file (a rule that never matches), so the route rule can
// exist before anything is added to it.
func RuleSetJSON(m model.Match) []byte {
	var rules list
	add := func(k string, v []string) {
		if len(v) > 0 {
			rules = append(rules, obj{k: v})
		}
	}
	add("domain", m.Domain)
	add("domain_suffix", m.DomainSuffix)
	add("domain_keyword", m.DomainKeyword)
	add("domain_regex", m.DomainRegex)
	add("ip_cidr", m.IPCIDR)
	add("process_name", m.ProcessName)
	add("process_path", m.ProcessPath)
	if len(m.Port) > 0 {
		rules = append(rules, obj{"port": m.Port})
	}
	if len(rules) == 0 {
		rules = list{obj{"domain": []string{"never.invalid"}}}
	}
	b, _ := json.Marshal(obj{"version": 3, "rules": rules})
	return b
}

func remoteRuleSet(name string) obj {
	repo := "sing-geosite"
	if strings.HasPrefix(name, "geoip-") {
		repo = "sing-geoip"
	}
	return obj{
		"type":            "remote",
		"tag":             name,
		"format":          "binary",
		"url":             fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/%s/rule-set/%s.srs", repo, name),
		"download_detour": model.ExitDirect,
		"update_interval": "168h",
	}
}

func orEmpty(l list) list {
	if l == nil {
		return list{}
	}
	return l
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
