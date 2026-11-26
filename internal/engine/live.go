package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"golang.org/x/net/proxy"

	"moley/internal/compile"
	"moley/internal/model"
)

// ProfileState is a profile's live tunnel state.
type ProfileState struct {
	ID    string `json:"id"`
	State string `json:"state"` // connected | connecting | auth-pending | error | ready | stopped
	Error string `json:"error,omitempty"`
	// OpenVPN only:
	Server string       `json:"server,omitempty"`
	Since  *time.Time   `json:"since,omitempty"`
	IPv4   []string     `json:"ipv4,omitempty"`
	DNS    []netip.Addr `json:"dns,omitempty"`
}

// State reports one profile's state. Only OpenVPN has a session; other
// kinds are "ready" while the engine runs (use a probe to check them).
func (e *Engine) State(id string) ProfileState {
	inst, _, cfg := e.current()
	st := ProfileState{ID: id, State: "stopped"}
	if inst == nil || cfg.Profile(id) == nil {
		return st
	}
	ep, ok := inst.box.Endpoint().Get(id)
	if !ok {
		st.State = "ready"
		return st
	}
	ov, ok := ep.(adapter.OpenVPNEndpoint)
	if !ok {
		st.State = "ready"
		return st
	}
	s := ov.OpenVPNStatus()
	st.State, st.Error = s.State, s.Error
	if s.Challenge != nil {
		st.Error = s.Challenge.Message
	}
	if t := s.TunnelInfo; t != nil {
		st.Server, st.DNS = t.Server, t.DNS
		since := t.ConnectedSince
		st.Since = &since
		for _, p := range t.IPv4 {
			st.IPv4 = append(st.IPv4, p.String())
		}
	}
	return st
}

// WaitConnected blocks until the profile is connected (OpenVPN) or the
// engine is running it (other kinds), or ctx ends.
func (e *Engine) WaitConnected(ctx context.Context, id string) (ProfileState, error) {
	for {
		st := e.State(id)
		if st.State == "connected" || st.State == "ready" {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, fmt.Errorf("profile %q is %s: %w", id, st.State, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Conn is one routed connection, live or recently closed.
type Conn struct {
	ID      string     `json:"id"`
	Inbound string     `json:"inbound"`
	Network string     `json:"network"`
	Host    string     `json:"host"`
	Port    uint16     `json:"port"`
	Rule    string     `json:"rule"` // Moley rule id, or "default"
	Exit    string     `json:"exit"` // exit the rule picked
	Chain   []string   `json:"chain"`
	Up      int64      `json:"up"`
	Down    int64      `json:"down"`
	Start   time.Time  `json:"start"`
	End     *time.Time `json:"end,omitempty"`
	srcPort uint16
}

// Conns lists live connections, then recently closed ones, newest first.
// host filters by exact host or any subdomain of it.
func (e *Engine) Conns(host string, closed bool) []Conn {
	inst, _, _ := e.current()
	if inst == nil || inst.traffic == nil {
		return nil
	}
	host = model.NormalizeHost(host)
	var res []Conn
	add := func(ms []*trafficcontrol.TrackerMetadata) {
		for _, m := range ms {
			c := inst.conn(m)
			if host == "" || c.Host == host || strings.HasSuffix(c.Host, "."+host) {
				res = append(res, c)
			}
		}
	}
	add(inst.traffic.Connections())
	if closed {
		for _, c := range e.recent.list() {
			if host == "" || c.Host == host || strings.HasSuffix(c.Host, "."+host) {
				res = append(res, c)
			}
		}
	}
	slices.SortStableFunc(res, func(a, b Conn) int { return b.Start.Compare(a.Start) })
	return res
}

func (i *instance) conn(m *trafficcontrol.TrackerMetadata) Conn {
	md := m.Metadata
	host := hostOf(md)
	if host == "" {
		host = md.Destination.AddrString()
	}
	// Unmatched traffic goes through the default selector (the chain's last,
	// outermost hop); report the exit it picked, as if the route had named it.
	exit, chain := md.RouteOutbound, m.Chain
	if exit == compile.DefaultOutbound {
		chain = chain[:max(len(chain)-1, 0)]
		exit = ""
		if len(chain) > 0 {
			exit = chain[len(chain)-1]
		}
	}
	c := Conn{
		ID: m.ID.String(), Inbound: md.Inbound, Network: md.Network,
		Host: host, Port: md.Destination.Port, Rule: "default", Exit: exit,
		Chain: chain, Up: m.Upload.Load(), Down: m.Download.Load(), Start: m.CreatedAt,
		srcPort: md.Source.Port,
	}
	if m.Rule != nil {
		if id, ok := i.ruleID(m.Rule); ok {
			c.Rule = id
		}
	}
	if !m.ClosedAt.IsZero() {
		end := m.ClosedAt
		c.End = &end
	}
	return c
}

// ProbeResult is what one real request through the engine did.
type ProbeResult struct {
	URL      string   `json:"url"`
	Status   int      `json:"status,omitempty"`
	Rule     string   `json:"rule"`
	Exit     string   `json:"exit"`
	Chain    []string `json:"chain,omitempty"`
	Resolver string   `json:"resolver"`
	MS       int64    `json:"ms"`
	Error    string   `json:"error,omitempty"`
	body     []byte
}

// Probe makes a real request through the local proxy inbound, then reads
// the connection tracker to report which rule and exit it used. target is
// an http(s) URL (an HTTP GET) or tcp://host:port (a TCP connect, nothing
// sent: for databases, SSH and the like). With exit set it goes through the
// hint inbound and forces that exit.
func (e *Engine) Probe(ctx context.Context, target, exit string) (ProbeResult, error) {
	inst, out, cfg := e.current()
	if inst == nil {
		return ProbeResult{}, errors.New("engine is not running")
	}
	if exit != "" && !cfg.HasExit(exit) {
		return ProbeResult{}, fmt.Errorf("unknown exit %q", exit)
	}
	u, err := url.Parse(target)
	web := err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
	tcp := err == nil && u.Scheme == "tcp" && u.Hostname() != "" && u.Port() != "" && (u.Path == "" || u.Path == "/")
	if !web && !tcp {
		return ProbeResult{}, fmt.Errorf("probe needs an http(s) URL or tcp://host:port, got %q", target)
	}
	// SOCKS5, like the browser path: the hostname goes to the engine
	// unresolved, and a failed exit is a connect error, not a 502 page.
	port := int(cfg.Settings.Port())
	proxyAddr, auth := "127.0.0.1:"+strconv.Itoa(port), (*proxy.Auth)(nil)
	if exit != "" {
		proxyAddr = "127.0.0.1:" + strconv.Itoa(port+1)
		auth = &proxy.Auth{User: compile.HintUser(exit), Password: e.env.Secret}
	}
	// The tracker knows the connection by the port it came from.
	localPort := make(chan uint16, 1)
	socks, err := proxy.SOCKS5("tcp", proxyAddr, auth, sourceDialer{localPort})
	if err != nil {
		return ProbeResult{}, err
	}
	dial := socks.(proxy.ContextDialer).DialContext
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	res := ProbeResult{URL: target}
	start := time.Now()
	if web {
		res.Status, res.body, err = get(ctx, dial, target)
	} else {
		var c net.Conn
		if c, err = dial(ctx, "tcp", u.Host); err == nil {
			c.Close()
		}
	}
	res.MS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
	}
	select {
	case p := <-localPort:
		if c, ok := e.findBySource(p); ok {
			res.Rule, res.Exit, res.Chain = c.Rule, c.Exit, c.Chain
			res.Resolver = out.Resolver[c.Exit]
			if res.Resolver == "" && len(c.Chain) > 0 {
				res.Resolver = out.Resolver[c.Chain[len(c.Chain)-1]]
			}
		}
		if err != nil {
			// SOCKS can only say "general failure"; the core logged why.
			if reason := e.connError(p); reason != "" {
				res.Error = dnsBlockHint(u.Hostname(), reason)
			}
		}
	default:
	}
	return res, nil
}

// dialAddr is the address in a dial error: "dial tcp 127.0.0.1:443: …".
var dialAddr = regexp.MustCompile(`dial \w+ \[?([0-9A-Fa-f.:]+?)\]?:\d+: `)

// dnsBlockHint names the usual cause when a site's name resolved to a
// loopback or unspecified address: the network's DNS hides it.
func dnsBlockHint(host, reason string) string {
	m := dialAddr.FindStringSubmatch(reason)
	if m == nil || host == "localhost" {
		return reason
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return reason
	}
	if ip, err := netip.ParseAddr(m[1]); err != nil || !(ip.IsLoopback() || ip.IsUnspecified()) {
		return reason
	}
	return fmt.Sprintf("%s resolved to %s, so DNS is likely blocking it: %s", host, m[1], reason)
}

// connError waits briefly for the core to log why it failed a connection:
// it may answer the client before it logs.
func (e *Engine) connError(srcPort uint16) string {
	for range 20 {
		if reason := e.logs.ConnError(srcPort); reason != "" {
			return reason
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ""
}

// get fetches target over dial: one request, no redirects, the start of the body.
func get(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), target string) (int, []byte, error) {
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "moley-probe")
	resp, err := (&http.Client{Transport: tr, CheckRedirect: noRedirect}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, body, err
}

// sourceDialer dials the proxy and reports the local port it dialed from.
type sourceDialer struct{ port chan<- uint16 }

func (s sourceDialer) Dial(network, addr string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, addr)
}

func (s sourceDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err == nil {
		select {
		case s.port <- uint16(c.LocalAddr().(*net.TCPAddr).Port):
		default:
		}
	}
	return c, err
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// findBySource finds the connection the proxy accepted from a local port.
// The tracker sees it before the outbound dial, so a short wait suffices.
func (e *Engine) findBySource(port uint16) (Conn, bool) {
	for range 50 {
		for _, c := range e.Conns("", true) {
			if c.srcPort == port && (c.Inbound == compile.InboundMixed || c.Inbound == compile.InboundHint) {
				return c, true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return Conn{}, false
}

// ExitInfo is the result of testing an exit: health plus public IP.
type ExitInfo struct {
	Exit    string `json:"exit"`
	OK      bool   `json:"ok"`
	MS      int64  `json:"ms"`
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Test fetches the IP-echo URL through exit and reports latency and the
// exit's public address.
func (e *Engine) Test(ctx context.Context, exit string) (ExitInfo, error) {
	_, _, cfg := e.current()
	r, err := e.Probe(ctx, cfg.Settings.IP(), exit)
	if err != nil {
		return ExitInfo{}, err
	}
	info := ExitInfo{Exit: exit, MS: r.MS, Error: r.Error, OK: r.Error == "" && r.Status/100 == 2}
	if info.Error == "" && !info.OK {
		info.Error = fmt.Sprintf("HTTP %d", r.Status)
	}
	for _, line := range strings.Split(string(r.body), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ip":
			info.IP = v
		case "loc":
			info.Country = v
		}
	}
	return info, nil
}

// Healthy runs one health probe through exit.
func (e *Engine) Healthy(ctx context.Context, exit string) (ProbeResult, bool) {
	_, _, cfg := e.current()
	r, err := e.Probe(ctx, cfg.Settings.Health(), exit)
	return r, err == nil && r.Error == "" && r.Status >= 200 && r.Status < 400
}

// AutoRule describes an auto rule: the live push and what has been learned.
type AutoRule struct {
	ID       string       `json:"id"`
	Profile  string       `json:"profile"`
	Live     bool         `json:"live"` // the push is in effect (connected)
	Resolver string       `json:"resolver"`
	DNS      []netip.Addr `json:"dns,omitempty"`
	Learned  model.Match  `json:"learned"` // keeps routing here while the tunnel is down
}

func (e *Engine) AutoRule(profile string) (AutoRule, error) {
	_, out, cfg := e.current()
	p := cfg.Profile(profile)
	if p == nil || !p.AutoRule {
		return AutoRule{}, fmt.Errorf("no auto rule for profile %q", profile)
	}
	st := e.State(profile)
	ar := AutoRule{ID: model.AutoRuleID(profile), Profile: profile, Live: st.State == "connected", DNS: st.DNS}
	if out != nil {
		ar.Resolver = out.Resolver[profile]
	}
	ar.Learned, _ = readLearned(filepath.Join(e.env.RulesDir, ar.ID+".json"))
	return ar, nil
}

// watch follows the instance's connection events. Closed connections go
// into the engine's own history (sing-box drops its closed list on every
// GC). Connections matched by an auto rule's live push teach the auto
// rule: the pushed domain (the shortest suffix the endpoint still claims)
// or the IP is written to its rule-set, so if the tunnel drops, those
// hosts still route to it and fail closed instead of leaking out direct.
func (e *Engine) watch(inst *instance) {
	if inst.traffic == nil {
		return
	}
	sub, done, err := inst.traffic.SubscribeEvents()
	if err != nil {
		return
	}
	defer inst.traffic.UnSubscribeEvents(sub)
	for {
		select {
		case <-inst.stop:
			return
		case <-done:
			return
		case ev := <-sub:
			if ev.Metadata == nil {
				continue
			}
			switch ev.Type {
			case trafficcontrol.ConnectionEventClosed:
				c := inst.conn(ev.Metadata)
				e.recent.add(c)
				e.usage.add(c)
			case trafficcontrol.ConnectionEventNew:
				if ev.Metadata.Rule == nil {
					continue
				}
				id, _ := inst.ruleID(ev.Metadata.Rule)
				if strings.HasPrefix(id, "auto-") && strings.Contains(ev.Metadata.Rule.String(), "preferred_by") {
					e.remember(inst, strings.TrimPrefix(id, "auto-"), ev.Metadata.Metadata)
				}
			}
		}
	}
}

// Usage is bytes carried, up and down.
type Usage struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// usage totals closed connections per exit, across rebuilds.
type usage struct {
	mu     sync.Mutex
	closed map[string]Usage
}

func (u *usage) add(c Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed == nil {
		u.closed = map[string]Usage{}
	}
	x := u.closed[c.exitID()]
	x.Up += c.Up
	x.Down += c.Down
	u.closed[c.exitID()] = x
}

// exitID is the exit a rule picked for the connection (a group, not the
// member it chose).
func (c Conn) exitID() string {
	if len(c.Chain) > 0 {
		return c.Chain[0]
	}
	return c.Exit
}

// Usage returns the bytes each exit has carried since the engine started,
// and how many connections are open. Counters only grow, so a reader gets
// rates from the difference between two calls.
func (e *Engine) Usage() (perExit map[string]Usage, open int) {
	live := e.Conns("", false)
	e.usage.mu.Lock()
	perExit = make(map[string]Usage, len(e.usage.closed))
	for k, v := range e.usage.closed {
		perExit[k] = v
	}
	e.usage.mu.Unlock()
	for _, c := range live {
		x := perExit[c.exitID()]
		x.Up += c.Up
		x.Down += c.Down
		perExit[c.exitID()] = x
	}
	return perExit, len(live)
}

// history keeps the most recent closed connections.
type history struct {
	mu    sync.Mutex
	conns []Conn
}

const historySize = 512

func (h *history) add(c Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.conns) == historySize {
		h.conns = slices.Delete(h.conns, 0, 1)
	}
	h.conns = append(h.conns, c)
}

func (h *history) list() []Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.conns)
}

func (e *Engine) remember(inst *instance, profile string, md adapter.InboundContext) {
	ob, ok := inst.box.Outbound().Outbound(profile)
	if !ok {
		if ep, found := inst.box.Endpoint().Get(profile); found {
			ob, ok = ep, true
		}
	}
	pref, isPref := ob.(adapter.OutboundWithPreferredRoutes)
	if !ok || !isPref {
		return
	}
	path := filepath.Join(e.env.RulesDir, model.AutoRuleID(profile)+".json")
	e.learn.Lock()
	defer e.learn.Unlock()
	learned, _ := readLearned(path)
	switch host := model.NormalizeHost(hostOf(md)); {
	case host != "":
		suffix := host
		for labels := strings.Split(host, "."); len(labels) > 1; {
			labels = labels[1:]
			parent := strings.Join(labels, ".")
			if !strings.Contains(parent, ".") || !pref.PreferredDomain(&md, parent) {
				break
			}
			suffix = parent
		}
		if slices.Contains(learned.DomainSuffix, suffix) {
			return
		}
		learned.DomainSuffix = append(learned.DomainSuffix, suffix)
		slices.Sort(learned.DomainSuffix)
	case md.Destination.IsIP():
		ip := md.Destination.Addr.String()
		if slices.Contains(learned.IPCIDR, ip) {
			return
		}
		learned.IPCIDR = append(learned.IPCIDR, ip)
		slices.Sort(learned.IPCIDR)
	default:
		return
	}
	if err := writeAtomic(path, compile.RuleSetJSON(learned)); err != nil {
		e.logs.Error("auto rule: " + err.Error())
		return
	}
	e.logs.Info(fmt.Sprintf("auto rule %s learned %v %v", model.AutoRuleID(profile), learned.DomainSuffix, learned.IPCIDR))
}

// Forget clears what profile's auto rule learned. sing-box reloads the
// rule-set on its own; the live push keeps working.
func (e *Engine) Forget(profile string) error {
	_, _, cfg := e.current()
	if p := cfg.Profile(profile); p == nil || !p.AutoRule {
		return fmt.Errorf("no auto rule for profile %q", profile)
	}
	e.learn.Lock()
	defer e.learn.Unlock()
	return writeAtomic(filepath.Join(e.env.RulesDir, model.AutoRuleID(profile)+".json"), compile.RuleSetJSON(model.Match{}))
}

func readLearned(path string) (model.Match, error) {
	var f struct {
		Rules []model.Match `json:"rules"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return model.Match{}, err
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Rules) == 0 {
		return model.Match{}, err
	}
	var m model.Match // one rule per field; merge them back
	for _, r := range f.Rules {
		m.DomainSuffix = append(m.DomainSuffix, r.DomainSuffix...)
		m.IPCIDR = append(m.IPCIDR, r.IPCIDR...)
	}
	return m, nil
}

// Body is the start of the response body (up to 64 KiB).
func (r ProbeResult) Body() string { return string(r.body) }

// hostOf is the name a connection asked for: the sniffed domain, or the
// FQDN the client sent (kept even after a resolve rule filled in the IP).
func hostOf(md adapter.InboundContext) string {
	if md.Domain != "" {
		return md.Domain
	}
	return md.Destination.Fqdn
}
