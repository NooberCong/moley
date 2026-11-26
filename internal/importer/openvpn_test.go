package importer

import (
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"moley/internal/model"
)

func fakePEM(t *testing.T, label string) string {
	t.Helper()
	body := fakeKey(t) + fakeKey(t)
	return "-----BEGIN " + label + "-----\n" + body[:64] + "\n" + body[64:] + "\n-----END " + label + "-----"
}

func fakeStaticKey(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	for range 16 {
		b.WriteString(fakeHex(t, 16) + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----")
	return b.String()
}

// An OpenVPN Access Server style client profile, plus a few directives Moley
// does not understand.
func accessServerProfile(ca, cert, key, tlsCrypt string) string {
	return `# Automatically generated OpenVPN client config file
# OVPN_ACCESS_SERVER_PROFILE=user@vpn.example.com/AUTOLOGIN
setenv FORWARD_COMPATIBLE 1
client
server-poll-timeout 4
nobind
remote vpn.example.com 1194 udp
remote vpn.example.com 1194 udp
remote vpn.example.com 443 tcp
remote vpn-backup.example.com 1194 udp
dev tun
dev-type tun
remote-cert-tls server
tls-version-min 1.2
reneg-sec 604800
tun-mtu 1420
verb 3
push-peer-info
cipher AES-256-CBC
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verify-x509-name "vpn.example.com" name
keepalive 10 120
mssfix 1400
comp-lzo no
route-nopull
dhcp-option DNS 10.0.0.1
fast-io
management 127.0.0.1 7505
frobnicate yes
<ca>
` + ca + `
</ca>
<cert>
` + cert + `
</cert>
<key>
` + key + `
</key>
<tls-crypt>
` + tlsCrypt + `
</tls-crypt>
## -----BEGIN RSA SIGNATURE-----
## DIGEST:sha256
`
}

func TestOpenVPNAccessServer(t *testing.T) {
	ca, cert, key, tlsCrypt := fakePEM(t, "CERTIFICATE"), fakePEM(t, "CERTIFICATE"), fakePEM(t, "PRIVATE KEY"), fakeStaticKey(t)
	res := mustParse(t, "/home/me/client.ovpn", accessServerProfile(ca, cert, key, tlsCrypt))
	p := res.Profiles[0]
	if p.Kind != model.KindOpenVPN || !p.AutoRule || p.ID != "client" || p.Source != "file:client.ovpn" {
		t.Errorf("profile header = %+v", p)
	}
	opts := decodeStrict[option.OpenVPNClientEndpointOptions](t, p.Config)
	if opts.Server != "" || len(opts.Servers) != 4 {
		t.Fatalf("server %q, servers %+v", opts.Server, opts.Servers)
	}
	s2 := opts.Servers[2]
	if s2.Server != "vpn.example.com" || s2.ServerPort != 443 || s2.Network != "tcp" || opts.Servers[3].Network != "udp" {
		t.Errorf("servers = %+v", opts.Servers)
	}
	if opts.Cipher != "" || opts.DataCiphersFallback != "AES-256-CBC" || opts.Auth != "SHA256" ||
		strings.Join(opts.DataCiphers, ":") != "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305" {
		t.Errorf("ciphers: cipher %q fallback %q auth %q data %v", opts.Cipher, opts.DataCiphersFallback, opts.Auth, opts.DataCiphers)
	}
	if opts.RenegotiateInterval.Build() != 604800*time.Second || opts.PingInterval.Build() != 10*time.Second ||
		opts.PingRestart.Build() != 120*time.Second || opts.MTU != 1420 || opts.MSSFix != 1400 || opts.CompressionLZO != "no" {
		t.Errorf("timing/data = %+v", opts)
	}
	// The server's default-route pushes are filtered when the profile is
	// compiled, not stored here.
	if opts.RedirectGateway || !opts.RouteNoPull || len(opts.PullFilters) != 0 {
		t.Errorf("routing: redirect %v nopull %v filters %+v", opts.RedirectGateway, opts.RouteNoPull, opts.PullFilters)
	}
	tls := opts.TLS
	if tls == nil {
		t.Fatal("no tls")
	}
	if strings.Join(tls.Certificate, "\n") != ca || strings.Join(tls.ClientCertificate, "\n") != cert || strings.Join(tls.ClientKey, "\n") != key {
		t.Error("PEM material does not round-trip")
	}
	if tls.ServerName != "vpn.example.com" || tls.ServerNameType != "name" || tls.RemoteCertificateTLS != "server" || tls.VersionMin != "1.2" {
		t.Errorf("tls = %+v", tls)
	}
	if tls.ControlWrap == nil || tls.ControlWrap.Type != "tls_crypt" || tls.ControlWrap.Direction != "" ||
		!strings.Contains(strings.Join(tls.ControlWrap.Key, "\n"), "BEGIN OpenVPN Static key V1") {
		t.Errorf("control wrap = %+v", tls.ControlWrap)
	}

	warnings := strings.Join(res.Warnings, "\n")
	for _, w := range []string{`"dhcp-option"`, `"management"`, `"frobnicate"`} {
		if !strings.Contains(warnings, w) {
			t.Errorf("no warning for %s in %q", w, res.Warnings)
		}
	}
	for _, quiet := range []string{"setenv", "client", "nobind", "verb", "push-peer-info", "server-poll-timeout", "fast-io"} {
		if strings.Contains(warnings, `"`+quiet+`"`) {
			t.Errorf("%s should be accepted silently", quiet)
		}
	}
	if len(res.Warnings) != 3 {
		t.Errorf("warnings = %q", res.Warnings)
	}
	assertNoSecrets(t, res.Warnings, ca, cert, key, tlsCrypt)
}

func TestOpenVPNVariants(t *testing.T) {
	ca := fakePEM(t, "CERTIFICATE")
	tlsAuth := fakeStaticKey(t)
	base := "client\ndev tun0\n<ca>\n" + ca + "\n</ca>\n"
	tests := []struct {
		name  string
		extra string
		check func(t *testing.T, o option.OpenVPNClientEndpointOptions, warnings []string)
	}{
		{
			name:  "single remote, tls-auth client direction, creds needed",
			extra: "proto tcp-client\nport 443\nremote vpn.example.com\nkey-direction 1\nauth-user-pass\ncompress lz4-v2\nreneg-sec 0\n<tls-auth>\n" + tlsAuth + "\n</tls-auth>\n",
			check: func(t *testing.T, o option.OpenVPNClientEndpointOptions, w []string) {
				if o.Server != "vpn.example.com" || o.ServerPort != 443 || o.Network != "tcp" || len(o.Servers) != 0 {
					t.Errorf("server = %q %d %q", o.Server, o.ServerPort, o.Network)
				}
				if o.TLS.ControlWrap.Type != "tls_auth" || o.TLS.ControlWrap.Direction != "client" {
					t.Errorf("wrap = %+v", o.TLS.ControlWrap)
				}
				if o.Compression != "lz4-v2" || !o.RenegotiateDisabled || o.RouteNoPull {
					t.Errorf("compression %q reneg-disabled %v nopull %v", o.Compression, o.RenegotiateDisabled, o.RouteNoPull)
				}
				if len(w) != 1 || !strings.Contains(w[0], "username/password") {
					t.Errorf("warnings = %q", w)
				}
			},
		},
		{
			name:  "inline creds, tls-crypt-v2, verify-x509 default subject, routes",
			extra: "remote 192.0.2.1 1194\nremote-random\nverify-x509-name 'CN=vpn server'\nroute 10.1.0.0 255.255.0.0\nroute-ipv6 fd00:1::/64\nmssfix 0\npull-filter ignore \"dhcp-option\"\nauth-user-pass\n<auth-user-pass>\nalice\nhunter2\n</auth-user-pass>\n<tls-crypt-v2>\n" + fakePEM(t, "OpenVPN tls-crypt-v2 client key") + "\n</tls-crypt-v2>\n",
			check: func(t *testing.T, o option.OpenVPNClientEndpointOptions, w []string) {
				if o.ServerPort != 1194 || o.Network != "udp" || !o.RemoteRandom {
					t.Errorf("server = %d %q random %v", o.ServerPort, o.Network, o.RemoteRandom)
				}
				if o.TLS.ServerName != "CN=vpn server" || o.TLS.ServerNameType != "subject" || o.TLS.ControlWrap.Type != "tls_crypt_v2" {
					t.Errorf("tls = %+v", o.TLS)
				}
				if len(o.Routes) != 2 || o.Routes[0].String() != "10.1.0.0/16" || o.Routes[1].String() != "fd00:1::/64" || !o.MSSFixDisabled {
					t.Errorf("routes %v mssfix-disabled %v", o.Routes, o.MSSFixDisabled)
				}
				if o.Username != "alice" || o.Password != "hunter2" || len(o.PullFilters) != 1 || o.PullFilters[0].Text != "dhcp-option" {
					t.Errorf("creds/filters = %q %+v", o.Username, o.PullFilters)
				}
				if len(w) != 0 {
					t.Errorf("warnings = %q", w)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustParse(t, "", base+tt.extra)
			if res.Profiles[0].ID != "openvpn" || res.Profiles[0].Source != "paste" {
				t.Errorf("id %q source %q", res.Profiles[0].ID, res.Profiles[0].Source)
			}
			tt.check(t, decodeStrict[option.OpenVPNClientEndpointOptions](t, res.Profiles[0].Config), res.Warnings)
		})
	}
}

func TestOpenVPNErrors(t *testing.T) {
	ca := fakePEM(t, "CERTIFICATE")
	inlineCA := "<ca>\n" + ca + "\n</ca>\n"
	tests := []struct{ name, conf, wantErr string }{
		{"tap", "client\ndev tap\nremote a 1194\n" + inlineCA, "tap"},
		{"file ref", "client\ndev tun\nremote a 1194\nca ca.crt\n", `"ca.crt"`},
		{"no remote", "client\ndev tun\n" + inlineCA, "no remote"},
		{"no ca", "client\ndev tun\nremote a 1194\n", "<ca>"},
		{"unclosed", "client\ndev tun\nremote a\n<ca>\n" + ca + "\n", "not closed"},
		{"static key", "dev tun\nremote a\nsecret static.key\n", "static-key"},
		{"cert without key", "client\ndev tun\nremote a\n" + inlineCA + "<cert>\n" + fakePEM(t, "CERTIFICATE") + "\n</cert>\n", "<cert> and <key>"},
		{"bad proto", "client\ndev tun\nproto sctp\nremote a\n" + inlineCA, "protocol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("x.ovpn", []byte(tt.conf))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			assertNoSecrets(t, []string{err.Error()}, ca)
		})
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`remote a 1194 udp`, []string{"remote", "a", "1194", "udp"}},
		{`verify-x509-name "CN=a b" subject`, []string{"verify-x509-name", "CN=a b", "subject"}},
		{`static-challenge 'Enter "PIN"' 1`, []string{"static-challenge", `Enter "PIN"`, "1"}},
		{`setenv X a\ b # trailing`, []string{"setenv", "X", "a b"}},
	}
	for _, tt := range tests {
		got, err := splitArgs(tt.in)
		if err != nil || strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("splitArgs(%q) = %q, %v", tt.in, got, err)
		}
	}
}
