package engine_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"moley/internal/compile"
	"moley/internal/engine"
	"moley/internal/model"
)

// TestSystemMode checks the system-mode config the core would run: a TUN
// inbound that answers DNS with FakeIP, except for names routed direct and
// local names, and that the core accepts it. (Starting it needs admin; the
// Linux container test does that.)
func TestSystemMode(t *testing.T) {
	cfg := model.Config{
		DefaultExit: model.ExitBlock,
		Rules: []model.Rule{
			{ID: "bank", Exit: model.ExitDirect, Match: model.Match{DomainSuffix: []string{"bank.example"}}},
			{ID: "chat", Exit: model.ExitBlock, Match: model.Match{ProcessName: []string{"chat.exe"}}},
		},
		Quick: map[string]string{"news.example": model.ExitDirect},
		Mode:  model.Mode{TUN: true, KillSwitch: model.KillSwitchOn},
	}
	e, err := engine.New(t.TempDir(), "s3cret-s3cret-s3cret-s3cret-0000", engine.NewLogs(testWriter{t}, false))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Check(cfg); err != nil {
		t.Fatalf("core rejected system mode: %v", err)
	}
	out, err := compile.Compile(cfg, compile.Env{RulesDir: t.TempDir(), CacheFile: "cache.db"})
	if err != nil {
		t.Fatal(err)
	}
	var opts struct {
		Inbounds []map[string]any `json:"inbounds"`
		DNS      struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
		Route struct {
			Rules       []map[string]any `json:"rules"`
			FindProcess bool             `json:"find_process"`
			AutoDetect  bool             `json:"auto_detect_interface"`
		} `json:"route"`
		Experimental struct {
			CacheFile map[string]any `json:"cache_file"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(out.Options, &opts); err != nil {
		t.Fatal(err)
	}
	tun := opts.Inbounds[len(opts.Inbounds)-1]
	if tun["type"] != "tun" || tun["interface_name"] != compile.TUNName || tun["strict_route"] != true || tun["auto_route"] != true {
		t.Errorf("tun inbound: %v", tun)
	}
	if !opts.Route.AutoDetect || !opts.Route.FindProcess {
		t.Errorf("route: auto_detect_interface %v, find_process %v", opts.Route.AutoDetect, opts.Route.FindProcess)
	}
	if opts.Route.Rules[0]["action"] != "sniff" || opts.Route.Rules[1]["action"] != "hijack-dns" {
		t.Errorf("first rules should sniff and answer DNS: %v", opts.Route.Rules[:2])
	}
	last := opts.Route.Rules[len(opts.Route.Rules)-1]
	if last["ip_is_private"] != true || last["outbound"] != model.ExitDirect || out.RuleIDs[len(out.RuleIDs)-1] != compile.LANRuleID {
		t.Errorf("last rule should keep the LAN local: %v", last)
	}
	if r := opts.Route.Rules[len(opts.Route.Rules)-2]; r["action"] != "resolve" || r["server"] != compile.ResolverLocal || r["domain_regex"] == nil {
		t.Errorf("the LAN's names should resolve with the OS just before: %v", r)
	}
	if !slices.ContainsFunc(opts.DNS.Servers, func(s map[string]any) bool { return s["type"] == "fakeip" }) {
		t.Errorf("no fakeip server: %v", opts.DNS.Servers)
	}
	// Local names resolve with the OS, names routed direct over DNS over
	// HTTPS, and everything else gets FakeIP.
	rules := opts.DNS.Rules
	if n := len(rules); n != 3 || rules[0]["server"] != compile.ResolverLocal || rules[1]["server"] != compile.ResolverDoH || rules[2]["server"] != compile.ResolverFake {
		t.Fatalf("dns rules: %v", rules)
	}
	direct, _ := json.Marshal(rules[len(rules)-2]["rule_set"])
	if string(direct) != `["quick-direct","rule-bank"]` {
		t.Errorf("direct names: %s", direct)
	}
	if opts.Experimental.CacheFile["store_fakeip"] != true {
		t.Errorf("cache_file: %v", opts.Experimental.CacheFile)
	}

	// Disconnected, the adapter is down; a hold brings it back without
	// changing where anything goes.
	off := cfg.Clone()
	off.DefaultExit, off.Mode = model.ExitDirect, model.Mode{TUN: true}
	for _, held := range []bool{false, true} {
		out, err := compile.Compile(off, compile.Env{RulesDir: t.TempDir(), Held: held})
		if err != nil {
			t.Fatal(err)
		}
		if up := strings.Contains(string(out.Options), `"type": "tun"`); up != held {
			t.Errorf("disconnected, held %v: tun inbound %v", held, up)
		}
	}

	// Validation: a kill switch needs the tunnel to let anything out.
	bad := cfg.Clone()
	bad.Mode.TUN = false
	if err := bad.Validate(); err == nil {
		t.Error("kill switch without tun should be rejected")
	}
	bad.Mode = model.Mode{TUN: true, KillSwitch: "sometimes"}
	if err := bad.Validate(); err == nil {
		t.Error("unknown kill switch mode should be rejected")
	}
}
