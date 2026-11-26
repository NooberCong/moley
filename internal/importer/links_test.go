package importer

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

	"moley/internal/model"
)

const fakeUUID = "3f1c2b8e-9a4d-4c6e-8f0b-1d2e3a4b5c6d"

func TestShareLinks(t *testing.T) {
	ssPass := fakeHex(t, 8)
	ss2022Key := fakeKey(t)
	realityPub := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(fakeHex(t, 16))), "=")
	vmessJSON, _ := json.Marshal(map[string]any{
		"v": "2", "ps": "VMess WS", "add": "vm.example.com", "port": "443", "id": fakeUUID, "aid": 0,
		"scy": "auto", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ray", "tls": "tls", "sni": "", "fp": "chrome",
	})

	tests := []struct {
		name  string
		link  string
		kind  string
		id    string
		check func(t *testing.T, raw []byte)
	}{
		{
			name: "ss sip002 base64 userinfo with plugin",
			link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:"+ssPass)) + "@198.51.100.7:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS%20Tokyo",
			kind: model.KindShadowsocks, id: "ss-tokyo",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.ShadowsocksOutboundOptions](t, raw)
				if o.Server != "198.51.100.7" || o.ServerPort != 8388 || o.Method != "chacha20-ietf-poly1305" || o.Password != ssPass ||
					o.Plugin != "obfs-local" || o.PluginOptions != "obfs=http;obfs-host=example.com" {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "ss 2022 plain userinfo",
			link: "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape(ss2022Key) + "@[2001:db8::5]:443#ss22",
			kind: model.KindShadowsocks, id: "ss22",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.ShadowsocksOutboundOptions](t, raw)
				if o.Server != "2001:db8::5" || o.Method != "2022-blake3-aes-256-gcm" || o.Password != ss2022Key {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "ss legacy fully base64",
			link: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:"+ssPass+"@ss.example.com:8389")) + "#Legacy",
			kind: model.KindShadowsocks, id: "legacy",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.ShadowsocksOutboundOptions](t, raw)
				if o.Server != "ss.example.com" || o.ServerPort != 8389 || o.Method != "aes-256-gcm" || o.Password != ssPass {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "vless reality vision",
			link: "vless://" + fakeUUID + "@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=firefox&pbk=" + realityPub + "&sid=6ba85179e30d4fc2&type=tcp#🇳🇱 NL Reality",
			kind: model.KindVLESS, id: "nl-reality",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.VLESSOutboundOptions](t, raw)
				if o.UUID != fakeUUID || o.Flow != "xtls-rprx-vision" || o.Transport != nil || o.TLS == nil {
					t.Fatalf("%+v", o)
				}
				if !o.TLS.Enabled || o.TLS.ServerName != "www.example.com" || o.TLS.UTLS.Fingerprint != "firefox" ||
					!o.TLS.Reality.Enabled || o.TLS.Reality.PublicKey != realityPub || o.TLS.Reality.ShortID != "6ba85179e30d4fc2" {
					t.Errorf("tls %+v", o.TLS)
				}
			},
		},
		{
			name: "vless tls ws with early data",
			link: "vless://" + fakeUUID + "@vl.example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048&alpn=h2,http/1.1#ws",
			kind: model.KindVLESS, id: "ws",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.VLESSOutboundOptions](t, raw)
				ws := o.Transport.WebsocketOptions
				if o.Transport.Type != "ws" || ws.Path != "/ws" || ws.MaxEarlyData != 2048 || ws.Headers["Host"][0] != "cdn.example.com" {
					t.Errorf("transport %+v", o.Transport)
				}
				if o.TLS.ServerName != "cdn.example.com" || len(o.TLS.ALPN) != 2 || o.TLS.UTLS != nil {
					t.Errorf("tls %+v", o.TLS)
				}
			},
		},
		{
			name: "vless grpc",
			link: "vless://" + fakeUUID + "@g.example.com:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc",
			kind: model.KindVLESS, id: "vless-g-example-com",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.VLESSOutboundOptions](t, raw)
				if o.Transport.Type != "grpc" || o.Transport.GRPCOptions.ServiceName != "svc" {
					t.Errorf("transport %+v", o.Transport)
				}
			},
		},
		{
			name: "vmess v2rayN",
			link: "vmess://" + base64.StdEncoding.EncodeToString(vmessJSON),
			kind: model.KindVMess, id: "vmess-ws",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.VMessOutboundOptions](t, raw)
				if o.Server != "vm.example.com" || o.ServerPort != 443 || o.UUID != fakeUUID || o.Security != "auto" ||
					o.Transport.Type != "ws" || o.Transport.WebsocketOptions.Path != "/ray" || !o.TLS.Enabled ||
					o.TLS.ServerName != "cdn.example.com" || o.TLS.UTLS.Fingerprint != "chrome" {
					t.Errorf("%+v / %+v", o, o.TLS)
				}
			},
		},
		{
			name: "trojan default tls",
			link: "trojan://" + ssPass + "@tr.example.com:443?sni=tr.example.com&allowInsecure=1#Trojan",
			kind: model.KindTrojan, id: "trojan",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.TrojanOutboundOptions](t, raw)
				if o.Password != ssPass || !o.TLS.Enabled || !o.TLS.Insecure || o.TLS.ServerName != "tr.example.com" {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "hysteria2 salamander",
			link: "hysteria2://" + ssPass + "@hy.example.com:8443/?sni=real.example.com&insecure=1&obfs=salamander&obfs-password=" + ssPass + "x#HY2",
			kind: model.KindHysteria2, id: "hy2",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.Hysteria2OutboundOptions](t, raw)
				if o.Password != ssPass || o.ServerPort != 8443 || o.TLS.ServerName != "real.example.com" || !o.TLS.Insecure ||
					o.Obfs == nil || o.Obfs.Type != "salamander" || o.Obfs.Password != ssPass+"x" {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "hy2 alias default port",
			link: "hy2://" + ssPass + "@hy.example.com#h",
			kind: model.KindHysteria2, id: "h",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.Hysteria2OutboundOptions](t, raw)
				if o.ServerPort != 443 || o.Obfs != nil {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "tuic",
			link: "tuic://" + fakeUUID + ":" + ssPass + "@tuic.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic.example.com&udp_relay_mode=native#TUIC",
			kind: model.KindTUIC, id: "tuic",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.TUICOutboundOptions](t, raw)
				if o.UUID != fakeUUID || o.Password != ssPass || o.CongestionControl != "bbr" || o.UDPRelayMode != "native" ||
					o.TLS.ALPN[0] != "h3" || o.TLS.ServerName != "tuic.example.com" {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "socks5 plain",
			link: "socks5://bob:" + ssPass + "@192.0.2.10:1080#Office SOCKS",
			kind: model.KindSOCKS, id: "office-socks",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.SOCKSOutboundOptions](t, raw)
				if o.Username != "bob" || o.Password != ssPass || o.Version != "5" || o.ServerPort != 1080 {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "socks v2rayN base64 userinfo",
			link: "socks://" + base64.StdEncoding.EncodeToString([]byte("bob:"+ssPass)) + "@192.0.2.10:1081",
			kind: model.KindSOCKS, id: "socks-192-0-2-10",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.SOCKSOutboundOptions](t, raw)
				if o.Username != "bob" || o.Password != ssPass {
					t.Errorf("%+v", o)
				}
			},
		},
		{
			name: "https proxy",
			link: "https://carol:" + ssPass + "@proxy.example.com#Corp",
			kind: model.KindHTTP, id: "corp",
			check: func(t *testing.T, raw []byte) {
				o := decodeStrict[option.HTTPOutboundOptions](t, raw)
				if o.ServerPort != 443 || o.Username != "carol" || o.Password != ssPass || o.TLS == nil || !o.TLS.Enabled {
					t.Errorf("%+v", o)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustParse(t, "", tt.link)
			if len(res.Profiles) != 1 || len(res.Warnings) != 0 {
				t.Fatalf("profiles %d, warnings %q", len(res.Profiles), res.Warnings)
			}
			p := res.Profiles[0]
			if p.Kind != tt.kind || p.ID != tt.id || p.Source != "link" {
				t.Errorf("profile header = %q %q %q", p.Kind, p.ID, p.Source)
			}
			tt.check(t, p.Config)
		})
	}
}

func TestSubscriptionBody(t *testing.T) {
	pass := fakeHex(t, 8)
	lines := strings.Join([]string{
		"trojan://" + pass + "@a.example.com:443#Node",
		"vless://" + fakeUUID + "@b.example.com:443?security=tls&type=xhttp#Bad",
		"",
		"hy2://" + pass + "@c.example.com:443#Node",
		"wireguard://" + pass + "@d.example.com:51820#WG",
		"not a link " + pass,
		"https://sub.example.com/api/v1/client/subscribe?token=" + pass,
		"http://192.0.2.1:3128",
	}, "\r\n")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		body := enc.EncodeToString([]byte(lines))
		// Subscription servers often wrap at 76 columns.
		if len(body) > 76 {
			body = body[:76] + "\n" + body[76:]
		}
		res := mustParse(t, "", body)
		var ids []string
		for _, p := range res.Profiles {
			ids = append(ids, p.ID)
		}
		if strings.Join(ids, ",") != "node,node-2,http-192-0-2-1" {
			t.Errorf("ids = %v", ids)
		}
		if len(res.Warnings) != 4 {
			t.Errorf("warnings = %q", res.Warnings)
		}
		for _, w := range []string{"line 2: vless: unsupported transport", "line 5: wireguard: unsupported scheme", "line 6: not a share link", "line 7: https:"} {
			if !strings.Contains(strings.Join(res.Warnings, "\n"), w) {
				t.Errorf("missing warning %q in %q", w, res.Warnings)
			}
		}
		assertNoSecrets(t, res.Warnings, pass, fakeUUID)
	}
}

func TestBadLinksNeverLeak(t *testing.T) {
	pass := fakeHex(t, 12)
	links := []string{
		"ss://" + pass + "@host:notaport",
		"ss://" + pass,
		"vless://" + pass + "@h:443?security=xtls",
		"vless://" + pass + "@h:443?security=reality",
		"vmess://" + pass,
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"h","port":"x","id":"`+pass+`"}`)),
		"trojan://" + pass + "@%zz",
		"hy2://" + pass + "@h:443?obfs=" + pass,
		"tuic://" + pass + "@:1",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:"+pass)) + "@h:1?plugin=kcptun%3Bkey%3D" + pass,
	}
	_, err := Parse("", []byte(strings.Join(links, "\n")))
	if err == nil {
		t.Fatal("expected an error: no line is valid")
	}
	assertNoSecrets(t, []string{err.Error()}, pass)
	if strings.Count(err.Error(), "line ") != len(links) {
		t.Errorf("want one message per line: %v", err)
	}
}
