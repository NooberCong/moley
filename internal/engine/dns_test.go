package engine_test

import (
	"encoding/json"
	"testing"

	"moley/internal/compile"
	"moley/internal/engine"
	"moley/internal/model"
)

// TestDirectDNS checks how settings.direct_dns compiles: DNS over HTTPS by
// default (a server given by name is looked up with the OS first), the OS
// resolver with "system", and anything else rejected.
func TestDirectDNS(t *testing.T) {
	e, err := engine.New(t.TempDir(), "s3cret-s3cret-s3cret-s3cret-0000", engine.NewLogs(testWriter{t}, false))
	if err != nil {
		t.Fatal(err)
	}
	type server = map[string]any
	for _, tc := range []struct {
		setting  string
		resolver string
		doh      server // nil: no DoH server
	}{
		{"", compile.ResolverDoH, server{"type": "https", "tag": "doh", "server": "1.1.1.1", "path": "/dns-query"}},
		{"https://dns.example:8443/q", compile.ResolverDoH, server{"type": "https", "tag": "doh", "server": "dns.example",
			"server_port": 8443.0, "path": "/q", "domain_resolver": compile.ResolverLocal}},
		{model.DirectDNSSystem, compile.ResolverLocal, nil},
	} {
		cfg := model.Config{Settings: model.Settings{DirectDNS: tc.setting}}
		if err := e.Check(cfg); err != nil {
			t.Fatalf("%q: core rejected it: %v", tc.setting, err)
		}
		out, err := compile.Compile(cfg, compile.Env{RulesDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		var opts struct {
			DNS struct {
				Servers []server `json:"servers"`
				Final   string   `json:"final"`
			} `json:"dns"`
			Route struct {
				Rules    []server `json:"rules"`
				Resolver server   `json:"default_domain_resolver"`
			} `json:"route"`
		}
		if err := json.Unmarshal(out.Options, &opts); err != nil {
			t.Fatal(err)
		}
		if out.Resolver[model.ExitDirect] != tc.resolver || opts.DNS.Final != tc.resolver || opts.Route.Resolver["server"] != tc.resolver {
			t.Errorf("%q: direct resolves with %q, final %q, dials %v; want %q", tc.setting,
				out.Resolver[model.ExitDirect], opts.DNS.Final, opts.Route.Resolver, tc.resolver)
		}
		var doh server
		for _, s := range opts.DNS.Servers {
			if s["tag"] == compile.ResolverDoH {
				doh = s
			}
		}
		if got, want := jsonOf(doh), jsonOf(tc.doh); got != want {
			t.Errorf("%q: doh server %s, want %s", tc.setting, got, want)
		}
		// The LAN's names always resolve with the OS, just before the LAN rule.
		if r := opts.Route.Rules[len(opts.Route.Rules)-2]; r["action"] != "resolve" || r["server"] != compile.ResolverLocal {
			t.Errorf("%q: LAN names: %v", tc.setting, r)
		}
	}
	for _, bad := range []string{"1.1.1.1", "http://1.1.1.1/dns-query", "https:///dns-query", "tls://1.1.1.1", "https://1.1.1.1/dns-query?x=1"} {
		cfg := model.Config{Settings: model.Settings{DirectDNS: bad}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("direct_dns %q should be rejected", bad)
		}
	}
}

func jsonOf(v any) string { b, _ := json.Marshal(v); return string(b) }
