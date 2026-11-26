package engine_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"moley/internal/compile"
	"moley/internal/engine"
	"moley/internal/importer"
	"moley/internal/model"
	"moley/internal/teststack"
)

// TestEngine drives real tunnels from the local stack through the engine
// and asserts, by the source IP the echo server sees, which exit carried
// each request.
func TestEngine(t *testing.T) {
	stack, err := teststack.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	dir := t.TempDir()
	logs := engine.NewLogs(testWriter{t}, false)
	e, err := engine.New(dir, "s3cret-s3cret-s3cret-s3cret-0000", logs)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	cfg := model.Config{
		DefaultExit: model.ExitDirect,
		Settings:    model.Settings{ProxyPort: freePort(t), HealthURL: stack.HealthURL(), IPURL: stack.PublicTraceURL()},
	}
	add := func(id, name, data string) {
		res, err := importer.Parse(name, []byte(data))
		if err != nil {
			t.Fatalf("import %s: %v", name, err)
		}
		if len(res.Warnings) > 0 {
			t.Logf("import %s warnings: %v", name, res.Warnings)
		}
		p := res.Profiles[0]
		p.ID = id
		cfg.Profiles = append(cfg.Profiles, p)
	}
	add("sq1", "work.ovpn", stack.OVPN)
	add("wg", "wg.conf", stack.WG)
	add("awg", "awg.conf", stack.AWG)
	add("ss", "", stack.SSLink)
	if !cfg.Profile("sq1").AutoRule {
		t.Fatal("openvpn import should enable auto_rule")
	}

	res, err := e.Apply(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rebuilt {
		t.Fatal("first apply must build")
	}
	ctx := context.Background()
	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if st, err := e.WaitConnected(wctx, "sq1"); err != nil {
		t.Fatalf("openvpn: %v (%+v)", err, st)
	}
	port := portOf(stack.EchoAddr)
	ipOf := func(url, exit string) (string, engine.ProbeResult) {
		r, err := e.Probe(ctx, url, exit)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(r.Body(), "\n") {
			if v, ok := strings.CutPrefix(line, "ip="); ok {
				return v, r
			}
		}
		return "", r
	}

	t.Run("exit IPs", func(t *testing.T) {
		if ip, r := ipOf(stack.TraceURL(), model.ExitDirect); ip != teststack.IPDirect {
			t.Errorf("direct: %q %+v", ip, r)
		}
		for exit, want := range map[string]string{
			"sq1": teststack.IPOpenVPN, "wg": teststack.IPWireGuard, "ss": teststack.IPShadowsocks,
		} {
			info, err := e.Test(ctx, exit)
			if err != nil || !info.OK || info.IP != want || info.Country != "T1" {
				t.Errorf("exit %s: got %+v err %v, want ip %s", exit, info, err, want)
			}
		}
		if ip, r := ipOf("http://"+teststack.AWGServerIP+"/trace", "awg"); ip != "10.66.0.2" {
			t.Errorf("awg: %q %+v", ip, r)
		}
	})

	t.Run("split tunnel from pushed routes", func(t *testing.T) {
		// Pushed search domain: resolved by the pushed DNS, through the tunnel.
		ip, r := ipOf("http://"+teststack.IntranetHost+":"+port+"/", "")
		if ip != teststack.IPOpenVPN || r.Rule != "auto-sq1" || r.Exit != "sq1" || r.Resolver != "pushed:sq1" {
			t.Fatalf("intranet by name: ip %q %+v", ip, r)
		}
		// Pushed route.
		ip, r = ipOf("http://"+teststack.IntranetIP+":"+port+"/", "")
		if ip != teststack.IPOpenVPN || r.Rule != "auto-sq1" || r.Exit != "sq1" {
			t.Fatalf("intranet by IP: ip %q %+v", ip, r)
		}
		// Everything else stays direct although the server pushed
		// redirect-gateway. (The echo server is on loopback, so the rule
		// that keeps private addresses local is what matches.)
		if ip, r := ipOf(stack.TraceURL(), ""); ip != teststack.IPDirect || r.Rule != "lan" || r.Exit != "direct" {
			t.Fatalf("public traffic: ip %q %+v", ip, r)
		}
		// Learning runs off the connection events, so give it a moment.
		var ar engine.AutoRule
		for range 50 {
			if ar, _ = e.AutoRule("sq1"); contains(ar.Learned.DomainSuffix, teststack.SearchDomain) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ar.Live || len(ar.DNS) == 0 || !contains(ar.Learned.DomainSuffix, teststack.SearchDomain) {
			t.Fatalf("auto rule: %+v", ar)
		}
	})

	t.Run("hot edits keep connections", func(t *testing.T) {
		// Match fields are OR-ed: the process name doesn't narrow the IP match.
		cfg.Rules = []model.Rule{{ID: "pub", Exit: "ss", Match: model.Match{
			IPCIDR: []string{teststack.PublicIP + "/32"}, ProcessName: []string{"nothing-like-this.exe"}}}}
		if res, err := e.Apply(cfg); err != nil || !res.Rebuilt {
			t.Fatalf("adding a rule is structural: %+v %v", res, err)
		}
		if ip, r := ipOf(stack.PublicTraceURL(), ""); ip != teststack.IPShadowsocks || r.Rule != "pub" {
			t.Fatalf("rule pub → ss: ip %q %+v", ip, r)
		}
		// From here on nothing may rebuild: a held connection must survive.
		held := holdConn(t, cfg.Settings.ProxyPort+1, "wg", teststack.PublicIP+":"+port)
		defer held.Close()

		cfg.Rules[0].Match.IPCIDR = []string{"198.18.0.99/32"}
		if res, err := e.Apply(cfg); err != nil || res.Rebuilt {
			t.Fatalf("editing a match must be hot: %+v %v", res, err)
		}
		if _, r := ipOf(stack.PublicTraceURL(), ""); r.Rule != "default" {
			t.Fatalf("edited rule still matched: %+v", r)
		}
		cfg.Quick = map[string]string{teststack.EchoHost: "ss"}
		if res, err := e.Apply(cfg); err != nil || res.Rebuilt {
			t.Fatalf("quick pick must be hot: %+v %v", res, err)
		}
		if ip, r := ipOf("http://"+teststack.EchoHost+":"+port+"/trace", ""); ip != teststack.IPShadowsocks || r.Rule != "quick-ss" {
			t.Fatalf("quick pick echo.test → ss: ip %q %+v", ip, r)
		}
		if _, err := held.Write([]byte("GET /trace HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatalf("held connection dropped by a hot edit: %v", err)
		}
		buf := make([]byte, 512)
		_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := held.Read(buf); err != nil || !strings.Contains(string(buf[:n]), "ip="+teststack.IPWireGuard) {
			t.Fatalf("held connection: %q %v", buf[:n], err)
		}
	})

	t.Run("switching the default exit is hot", func(t *testing.T) {
		cfg.Quick, cfg.Rules = nil, nil
		if _, err := e.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		// A connection that names its exit isn't the default's to close.
		held := holdConn(t, cfg.Settings.ProxyPort+1, "wg", teststack.PublicIP+":"+port)
		defer held.Close()
		for _, c := range []struct{ exit, ip string }{
			{"ss", teststack.IPShadowsocks}, {"sq1", teststack.IPOpenVPN}, {model.ExitBlock, ""}, {model.ExitDirect, ""},
		} {
			cfg.DefaultExit = c.exit
			if res, err := e.Apply(cfg); err != nil || res.Rebuilt {
				t.Fatalf("default → %s must be hot: %+v %v", c.exit, res, err)
			}
			ip, r := ipOf(stack.PublicTraceURL(), "")
			if r.Rule != "default" || r.Exit != c.exit || slices.Contains(r.Chain, compile.DefaultOutbound) {
				t.Fatalf("default → %s: reported %+v", c.exit, r)
			}
			if c.ip != "" && ip != c.ip {
				t.Fatalf("default → %s: ip %q %+v", c.exit, ip, r)
			}
			if c.exit == model.ExitBlock && r.Error == "" {
				t.Fatalf("default → block let a request through: %+v", r)
			}
		}
		if _, err := held.Write([]byte("GET /trace HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatalf("held connection dropped by a default switch: %v", err)
		}
		buf := make([]byte, 512)
		_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := held.Read(buf); err != nil || !strings.Contains(string(buf[:n]), "ip="+teststack.IPWireGuard) {
			t.Fatalf("held connection: %q %v", buf[:n], err)
		}
	})

	t.Run("groups", func(t *testing.T) {
		cfg.Quick = nil
		cfg.Rules = nil
		cfg.Exits = []model.Exit{{ID: "pick", Group: model.GroupManual, Members: []string{"wg", "ss"}, Selected: "wg"}}
		cfg.DefaultExit = "pick"
		if _, err := e.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		if ip, r := ipOf(stack.PublicTraceURL(), ""); ip != teststack.IPWireGuard || r.Exit != "pick" {
			t.Fatalf("pick=wg: ip %q %+v", ip, r)
		}
		cfg.Exits[0].Selected = "ss"
		if res, err := e.Apply(cfg); err != nil || res.Rebuilt {
			t.Fatalf("selecting must be hot: %+v %v", res, err)
		}
		if ip, r := ipOf(stack.PublicTraceURL(), ""); ip != teststack.IPShadowsocks {
			t.Fatalf("pick=ss: ip %q %+v", ip, r)
		}
	})

	t.Run("fail closed when the tunnel is down", func(t *testing.T) {
		cfg.DefaultExit = model.ExitDirect
		cfg.Exits = nil
		// Point the profile at a dead port: it never connects.
		var c map[string]any
		_ = json.Unmarshal(cfg.Profile("sq1").Config, &c)
		c["server_port"] = freePort(t)
		cfg.Profile("sq1").Config, _ = json.Marshal(c)
		if _, err := e.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		r, err := e.Probe(ctx, "http://"+teststack.IntranetHost+":"+port+"/", "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Rule != "auto-sq1" || r.Exit != "sq1" || r.Error == "" {
			t.Fatalf("intranet with tunnel down must fail via sq1, got %+v", r)
		}
	})

	t.Run("check rejects bad config without touching the engine", func(t *testing.T) {
		bad := cfg.Clone()
		bad.Profiles[1].Config = json.RawMessage(`{"private_key":"nope","address":["x"]}`)
		if err := e.Check(bad); err == nil {
			t.Fatal("expected an error")
		}
		if _, err := e.Apply(bad); err == nil {
			t.Fatal("apply of a bad config must fail")
		}
		if !e.Running() {
			t.Fatal("engine must keep running")
		}
	})

	if _, err := os.Stat(filepath.Join(dir, "rules", "auto-sq1.json")); err != nil {
		t.Fatal(err)
	}
}

func probe(t *testing.T, e *engine.Engine, url, exit string) string {
	t.Helper()
	r, err := e.Probe(context.Background(), url, exit)
	if err != nil || r.Error != "" {
		t.Fatalf("probe %s via %s: %+v %v", url, exit, r, err)
	}
	return r.Body()
}

// holdConn opens a keep-alive HTTP connection through the hint inbound via
// exit, using a raw CONNECT tunnel.
func holdConn(t *testing.T, hintPort uint16, exit, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", "127.0.0.1:"+itoa(int(hintPort)))
	if err != nil {
		t.Fatal(err)
	}
	auth := basic(exit, "s3cret-s3cret-s3cret-s3cret-0000")
	_, _ = c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n"))
	buf := make([]byte, 256)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("CONNECT: %q %v", buf[:n], err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return c
}
