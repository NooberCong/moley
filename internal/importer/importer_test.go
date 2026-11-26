package importer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	sjson "github.com/sagernet/sing/common/json"

	"moley/internal/model"
)

// fakeKey returns a random base64 WireGuard-style key. Tests never use real
// credentials.
func fakeKey(t testing.TB) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func fakeHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// decodeStrict round-trips a Config through sing-box's own JSON decoder,
// rejecting unknown fields, so a misspelled field name fails the test.
func decodeStrict[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := sjson.UnmarshalContextDisallowUnknownFields(context.Background(), raw, &v); err != nil {
		t.Fatalf("config does not decode as %T: %v\n%s", v, err, raw)
	}
	return v
}

func mustParse(t *testing.T, name, input string) Result {
	t.Helper()
	res, err := Parse(name, []byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := model.Config{Profiles: res.Profiles}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("profiles do not validate: %v", err)
	}
	for _, p := range res.Profiles {
		if strings.Contains(string(p.Config), `"type":"`+p.Kind+`"`) || strings.Contains(string(p.Config), `"tag"`) {
			t.Errorf("config of %s still has type/tag: %s", p.ID, p.Config)
		}
	}
	return res
}

// assertNoSecrets fails if any warning or error text contains one of secrets.
func assertNoSecrets(t *testing.T, texts []string, secrets ...string) {
	t.Helper()
	for _, text := range texts {
		for _, s := range secrets {
			if s != "" && strings.Contains(text, s) {
				t.Errorf("message leaks secret material: %q", text)
			}
		}
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Work VPN", "work-vpn"},
		{"🇩🇪 Germany #1", "germany-1"},
		{"--a__b--", "a__b"},
		{"_x", "p-_x"},
		{"日本", ""},
		{strings.Repeat("ab", 40), strings.Repeat("ab", 24)},
		{"a" + strings.Repeat("-", 47) + "b", "a-b"},
	}
	for _, tt := range tests {
		if got := slugify(tt.in); got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAssignIDsDeduplicates(t *testing.T) {
	long := strings.Repeat("x", 60)
	ps := []model.Profile{
		{ID: "Node", Kind: "vless"}, {ID: "node", Kind: "vless"}, {ID: "NODE", Kind: "vless"},
		{ID: "", Kind: "trojan"}, {ID: "日本", Kind: "trojan"},
		{ID: long, Kind: "ss"}, {ID: long, Kind: "ss"},
	}
	assignIDs(ps)
	want := []string{"node", "node-2", "node-3", "trojan", "trojan-2", strings.Repeat("x", 48), strings.Repeat("x", 46) + "-2"}
	for i, p := range ps {
		if p.ID != want[i] {
			t.Errorf("profile %d: ID %q, want %q", i, p.ID, want[i])
		}
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct{ name, input, wantErr string }{
		{"empty", "  \n ", "empty"},
		{"clash", "port: 7890\nproxies:\n  - name: a\n    type: ss\n", "not supported yet"},
		{"singbox", `{"outbounds":[{"type":"direct"}]}`, "not supported yet"},
		{"singbox endpoints", `{"endpoints":[]}`, "not supported yet"},
		{"garbage", "hello world", "unrecognized"},
		{"no good links", "foo://x\nvless://", "no share link"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("", []byte(tt.input))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	key := fakeKey(f)
	f.Add("", []byte("[Interface]\nPrivateKey = "+key+"\nAddress = 10.0.0.2/32\nJc = 4\nH1 = 1-2\n[Peer]\nPublicKey = "+key+"\nEndpoint = [2001:db8::1]:51820\n"))
	f.Add("a.ovpn", []byte("client\ndev tun\nremote vpn.example.com 1194 udp\n<ca>\nx\n</ca>\n<tls-auth>\ny\n</tls-auth>\nkey-direction 1\n"))
	f.Add("", []byte("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#a\nvmess://eyJhZGQiOiJhIiwicG9ydCI6NDQzfQ==\n"))
	f.Add("", []byte("vless://u@h:443?security=reality&pbk=k&type=ws&path=%2F%3Fed%3D1#x\nhy2://p@h?obfs=salamander\n"))
	f.Add("", []byte(base64.StdEncoding.EncodeToString([]byte("trojan://p@h:443#t\ntuic://u:p@h:1\n"))))
	f.Add("", []byte("<ca>\n"))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		_, _ = Parse(name, data) // must not panic
	})
}
