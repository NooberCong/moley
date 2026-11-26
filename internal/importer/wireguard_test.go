package importer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

	"moley/internal/awg"
	"moley/internal/model"
)

func TestWireGuard(t *testing.T) {
	priv, pub, psk := fakeKey(t), fakeKey(t), fakeKey(t)
	conf := `[Interface]
# laptop
PrivateKey = ` + priv + `
Address = 10.8.0.2/24, fd00::2/128
DNS = 10.8.0.1, fd00::1, corp.example
MTU = 1380
PostUp = iptables -A FORWARD -i %i -j ACCEPT
Table = off

[Peer]
PublicKey = ` + pub + `
PresharedKey = ` + psk + `
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[Peer]
PublicKey = ` + pub + `
Endpoint = [2001:db8::1]:443
AllowedIPs = 10.9.0.1
`
	res := mustParse(t, `C:\Users\me\Downloads\Home Office.conf`, conf)
	if len(res.Profiles) != 1 {
		t.Fatalf("got %d profiles", len(res.Profiles))
	}
	p := res.Profiles[0]
	if p.Kind != model.KindWireGuard || p.ID != "home-office" || p.Source != "file:Home Office.conf" {
		t.Errorf("profile header = %q %q %q", p.Kind, p.ID, p.Source)
	}
	if strings.Join(p.DNS, ",") != "10.8.0.1,fd00::1" {
		t.Errorf("DNS = %v", p.DNS)
	}
	if bytes.Contains(p.Config, []byte(`"system"`)) {
		t.Errorf("system must be omitted: %s", p.Config)
	}
	opts := decodeStrict[option.WireGuardEndpointOptions](t, p.Config)
	if opts.PrivateKey != priv || opts.MTU != 1380 || len(opts.Address) != 2 || opts.Address[0].String() != "10.8.0.2/24" {
		t.Errorf("interface = %+v", opts)
	}
	if len(opts.Peers) != 2 {
		t.Fatalf("peers = %d", len(opts.Peers))
	}
	p0, p1 := opts.Peers[0], opts.Peers[1]
	if p0.Address != "vpn.example.com" || p0.Port != 51820 || p0.PublicKey != pub || p0.PreSharedKey != psk ||
		len(p0.AllowedIPs) != 2 || p0.PersistentKeepaliveInterval != 25 {
		t.Errorf("peer 0 = %+v", p0)
	}
	if p1.Address != "2001:db8::1" || p1.Port != 443 || p1.AllowedIPs[0].String() != "10.9.0.1/32" {
		t.Errorf("peer 1 = %+v", p1)
	}
	wantWarn := []string{"corp.example", "postup", "table"}
	for _, w := range wantWarn {
		if !strings.Contains(strings.Join(res.Warnings, "\n"), w) {
			t.Errorf("no warning mentioning %q in %q", w, res.Warnings)
		}
	}
	assertNoSecrets(t, res.Warnings, priv, pub, psk)
}

func TestAmneziaWG2(t *testing.T) {
	priv, pub := fakeKey(t), fakeKey(t)
	conf := `[Interface]
PrivateKey = ` + priv + `
Address = 10.66.66.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 68
s3 = 22
S4 = 8
H1 = 100000-100100
H2 = 200000-200100
H3 = 300000
H4 = 400000-400100
I1 = <b 0xc2000000011f><r 16><t>
I2 = <r 32>

[Peer]
PublicKey = ` + pub + `
Endpoint = [2001:db8::7]:4443
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = off
`
	res := mustParse(t, "", conf)
	p := res.Profiles[0]
	if p.Kind != model.KindAmneziaWG || p.ID != "amneziawg" || p.Source != "paste" {
		t.Errorf("profile header = %q %q %q", p.Kind, p.ID, p.Source)
	}
	if len(p.DNS) != 1 || p.DNS[0] != "1.1.1.1" {
		t.Errorf("DNS = %v", p.DNS)
	}
	dec := json.NewDecoder(bytes.NewReader(p.Config))
	dec.DisallowUnknownFields()
	var opts awg.Options
	if err := dec.Decode(&opts); err != nil {
		t.Fatalf("config does not decode as awg.Options: %v", err)
	}
	if opts.DNS != nil || opts.PrivateKey != priv || opts.Jc != 4 || opts.Jmin != 40 || opts.Jmax != 70 ||
		opts.S1 != 15 || opts.S2 != 68 || opts.S3 != 22 || opts.S4 != 8 {
		t.Errorf("options = %+v", opts)
	}
	if opts.H1 != "100000-100100" || opts.H3 != "300000" || opts.I1 != "<b 0xc2000000011f><r 16><t>" || opts.I2 != "<r 32>" {
		t.Errorf("headers = %q %q %q %q", opts.H1, opts.H3, opts.I1, opts.I2)
	}
	if len(opts.Peers) != 1 || opts.Peers[0].Endpoint != "[2001:db8::7]:4443" || opts.Peers[0].PersistentKeepalive != 0 ||
		opts.Peers[0].AllowedIPs[0] != "0.0.0.0/0" || opts.Address[0] != "10.66.66.2/32" {
		t.Errorf("peers = %+v", opts.Peers)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings %q", res.Warnings)
	}
}

func TestWireGuardErrors(t *testing.T) {
	key := fakeKey(t)
	tests := []struct{ name, conf, wantErr string }{
		{"no key", "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = a:1\n", "PrivateKey"},
		{"no peer", "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n", "[Peer]"},
		{"bad endpoint", "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = nohost\n", "Endpoint"},
		{"masked key", "[Interface]\nPrivateKey = *****\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = a:1\n", "private key is hidden"},
		{"bad peer key", "[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = " + key[:20] + "\nEndpoint = a:1\n", "public key isn't a WireGuard key"},
		{"bad jc","[Interface]\nPrivateKey = " + key + "\nAddress = 10.0.0.2/32\nJc = many\n[Peer]\nPublicKey = " + key + "\nEndpoint = a:1\n", "jc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("x.conf", []byte(tt.conf))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			assertNoSecrets(t, []string{err.Error()}, key)
		})
	}
}

func TestWireGuardStrayKeyLineNotEchoed(t *testing.T) {
	priv, pub := fakeKey(t), fakeKey(t)
	conf := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.0.0.2/32\n" + pub + "\n" +
		"[Peer]\nPublicKey = " + pub + "\nEndpoint = a.example:1\n"
	res := mustParse(t, "", conf)
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings = %q", res.Warnings)
	}
	// The stray key ends with "=", so it is split into an odd "key": the
	// warning must not echo any of it.
	assertNoSecrets(t, res.Warnings, strings.ToLower(strings.TrimRight(pub, "=")), pub)
}
