// Package teststack runs real VPN and proxy servers on loopback so tests
// exercise actual tunnels, not mocks:
//
//   - an echo server that reports the caller's IP (Cloudflare trace format)
//   - an OpenVPN server that pushes a route (10.99.0.0/16), a DNS server
//     and a search domain (corp.test), like a corporate VPN
//   - a WireGuard server, a Shadowsocks server and an AmneziaWG server
//
// Each server leaves through its own loopback source address, so the echo
// server's answer proves which exit carried a request:
// direct 127.0.0.1, OpenVPN 127.0.0.2, WireGuard 127.0.0.3, Shadowsocks 127.0.0.4.
// AmneziaWG serves the echo handler inside its tunnel at 10.66.0.1.
package teststack

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"golang.org/x/crypto/curve25519"
)

const (
	IntranetHost = "wiki.corp.test" // resolvable only through the OpenVPN DNS
	EchoHost     = "echo.test"      // resolvable by the proxy servers (→ PublicIP)
	IntranetIP   = "10.99.0.10"     // inside the pushed route
	SearchDomain = "corp.test"
	PushedRoute  = "10.99.0.0/16"
	PushedDNS    = "10.8.0.53" // not the server's own tunnel IP, so it is routed
	AWGServerIP  = "10.66.0.1"
	// PublicIP stands in for an Internet address in requests sent through
	// a tunnel: tunnel servers map it to the echo server on loopback. (A
	// loopback destination itself is dropped by userspace TCP/IP stacks.)
	PublicIP      = "198.18.0.10"
	IPDirect      = "127.0.0.1"
	IPOpenVPN     = "127.0.0.2"
	IPWireGuard   = "127.0.0.3"
	IPShadowsocks = "127.0.0.4"
)

type Stack struct {
	EchoAddr string // host:port of the echo server
	OVPN     string // client .ovpn
	WG       string // client WireGuard .conf
	AWG      string // client AmneziaWG .conf
	SSLink   string // ss:// share link

	OpenVPNPort int // UDP port, e.g. to block it
	box         *box.Box
	echo        *http.Server
	awg         *device.Device
	awgHTTP     *http.Server
}

// TraceURL is the echo endpoint in Cloudflare trace format, reached directly.
func (s *Stack) TraceURL() string { return "http://" + s.EchoAddr + "/trace" }

// PublicTraceURL is the echo endpoint as reached through any tunnel.
func (s *Stack) PublicTraceURL() string {
	_, port, _ := net.SplitHostPort(s.EchoAddr)
	return "http://" + PublicIP + ":" + port + "/trace"
}

// HealthURL answers 204, reached through any tunnel.
func (s *Stack) HealthURL() string {
	_, port, _ := net.SplitHostPort(s.EchoAddr)
	return "http://" + PublicIP + ":" + port + "/generate_204"
}

func (s *Stack) Close() {
	s.box.Close()
	s.echo.Close()
	s.awgHTTP.Close()
	s.awg.Close()
}

// Echo answers /trace with the caller's IP, /generate_204 with 204, and
// requests for the intranet host with a marker body.
func Echo(id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		switch {
		case r.URL.Path == "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.Host, IntranetHost) || strings.HasPrefix(r.Host, IntranetIP):
			fmt.Fprintf(w, "intranet\nip=%s\n", host)
		default:
			fmt.Fprintf(w, "fl=%s\nip=%s\nloc=T1\n", id, host)
		}
	})
}

func Start() (*Stack, error) {
	s := &Stack{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.EchoAddr = ln.Addr().String()
	s.echo = &http.Server{Handler: Echo("echo")}
	go s.echo.Serve(ln)

	ovpnPort, wgPort, ssPort, awgPort := freeUDP(), freeUDP(), freeTCP(), freeUDP()
	// sing-box's WireGuard client can't send to a loopback peer on Windows
	// (WSAEFAULT), so its server listens on the LAN address.
	lan := lanIP()
	s.OpenVPNPort = ovpnPort
	ca, caKey := newCA()
	srvCert, srvKey := newLeaf(ca, caKey, "server", x509.ExtKeyUsageServerAuth)
	cliCert, cliKey := newLeaf(ca, caKey, "client", x509.ExtKeyUsageClientAuth)
	tlsCrypt := staticKey()
	wgSrvPriv, wgSrvPub := wgKeys()
	wgCliPriv, wgCliPub := wgKeys()
	ssPass := base64.StdEncoding.EncodeToString(random(16))

	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		// A log writer makes sing-box open a cache file (default ./cache.db).
		"experimental": map[string]any{"cache_file": map[string]any{
			"enabled": true, "path": filepath.Join(os.TempDir(), fmt.Sprintf("moley-teststack-%d.db", os.Getpid())),
		}},
		"dns": map[string]any{
			"servers": []any{map[string]any{"type": "hosts", "tag": "corp", "predefined": map[string]any{IntranetHost: IntranetIP, EchoHost: PublicIP}}},
			"final":   "corp",
		},
		"endpoints": []any{
			map[string]any{
				"type": "openvpn-server", "tag": "ovpn-in", "listen": "127.0.0.1", "listen_port": ovpnPort,
				"network": "udp", "address": []string{"10.8.0.1/24"},
				"tls": map[string]any{
					"certificate": lines(srvCert), "key": lines(srvKey), "client_certificate": lines(ca),
					"verify_client_certificate": "require",
					"control_wrap":              map[string]any{"type": "tls_crypt", "key": lines(tlsCrypt)},
				},
				"data_ciphers": []string{"AES-256-GCM"},
				"push": map[string]any{
					"routes": []string{PushedRoute}, "dns": []string{PushedDNS}, "search_domains": []string{SearchDomain},
					// Like a typical Access Server profile; Moley must ignore it.
					"redirect_gateway": true, "redirect_gateway_flags": []string{"def1"},
				},
			},
			map[string]any{
				"type": "wireguard", "tag": "wg-in", "listen_port": wgPort, "address": []string{"10.7.0.1/24"},
				"private_key": wgSrvPriv,
				"peers":       []any{map[string]any{"public_key": wgCliPub, "allowed_ips": []string{"10.7.0.2/32"}}},
			},
		},
		"inbounds": []any{map[string]any{
			"type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": ssPort,
			"method": "2022-blake3-aes-128-gcm", "password": ssPass,
		}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "out-ovpn", "inet4_bind_address": IPOpenVPN},
			map[string]any{"type": "direct", "tag": "out-wg", "inet4_bind_address": IPWireGuard},
			map[string]any{"type": "direct", "tag": "out-ss", "inet4_bind_address": IPShadowsocks},
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{"inbound": []string{"ovpn-in"}, "ip_cidr": []string{PushedDNS + "/32"}, "port": 53, "action": "hijack-dns"},
				map[string]any{"inbound": []string{"ovpn-in"}, "ip_cidr": []string{IntranetIP + "/32"}, "action": "route", "outbound": "out-ovpn", "override_address": "127.0.0.1"},
				map[string]any{"inbound": []string{"ovpn-in"}, "ip_cidr": []string{PublicIP + "/32"}, "action": "route", "outbound": "out-ovpn", "override_address": "127.0.0.1"},
				map[string]any{"inbound": []string{"ovpn-in"}, "action": "route", "outbound": "out-ovpn"},
				map[string]any{"inbound": []string{"wg-in"}, "ip_cidr": []string{PublicIP + "/32"}, "action": "route", "outbound": "out-wg", "override_address": "127.0.0.1"},
				map[string]any{"inbound": []string{"wg-in"}, "action": "route", "outbound": "out-wg"},
				map[string]any{"inbound": []string{"ss-in"}, "domain": []string{EchoHost}, "action": "route", "outbound": "out-ss", "override_address": "127.0.0.1"},
				map[string]any{"inbound": []string{"ss-in"}, "ip_cidr": []string{PublicIP + "/32"}, "action": "route", "outbound": "out-ss", "override_address": "127.0.0.1"},
				map[string]any{"inbound": []string{"ss-in"}, "action": "route", "outbound": "out-ss"},
			},
			"final":                   "out-ss",
			"default_domain_resolver": "corp",
		},
	}
	raw, _ := json.Marshal(cfg)
	ctx := include.Context(context.Background())
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("server options: %w", err)
	}
	s.box, err = box.New(box.Options{Options: opts, Context: ctx, PlatformLogWriter: quiet{}})
	if err != nil {
		return nil, fmt.Errorf("server box: %w", err)
	}
	if err := s.box.Start(); err != nil {
		return nil, fmt.Errorf("server start: %w", err)
	}

	if err := s.startAWG(awgPort); err != nil {
		s.box.Close()
		return nil, err
	}

	s.OVPN = fmt.Sprintf(`client
dev tun
proto udp
remote 127.0.0.1 %d
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
verb 3
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
<tls-crypt>
%s</tls-crypt>
`, ovpnPort, ca, cliCert, cliKey, tlsCrypt)
	s.WG = fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.7.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0\n",
		wgCliPriv, wgSrvPub, lan, wgPort)
	s.SSLink = fmt.Sprintf("ss://%s@127.0.0.1:%d#test-ss",
		base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+ssPass)), ssPort)
	return s, nil
}

// startAWG runs an AmneziaWG 2.0 server whose tunnel address serves Echo.
func (s *Stack) startAWG(port int) error {
	srvPriv, srvPub := wgKeys()
	cliPriv, cliPub := wgKeys()
	obf := "jc=4\njmin=40\njmax=70\ns1=15\ns2=18\ns3=20\ns4=10\nh1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n"
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(AWGServerIP)}, nil, 1420)
	if err != nil {
		return err
	}
	s.awg = device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg-server: "))
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n%spublic_key=%s\nallowed_ip=10.66.0.2/32\n",
		hexKey(srvPriv), port, obf, hexKey(cliPub))
	if err := s.awg.IpcSet(uapi); err != nil {
		return fmt.Errorf("awg server: %w", err)
	}
	if err := s.awg.Up(); err != nil {
		return err
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(AWGServerIP), Port: 80})
	if err != nil {
		return err
	}
	s.awgHTTP = &http.Server{Handler: Echo("awg")}
	go s.awgHTTP.Serve(ln)
	s.AWG = fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.66.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
S3 = 20
S4 = 10
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
`, cliPriv, srvPub, port)
	return nil
}

type quiet struct{}

func (quiet) WriteMessage(log.Level, string) {}

func lines(pemText string) []string { return strings.Split(strings.TrimSpace(pemText), "\n") }

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func wgKeys() (priv, pub string) {
	k := random(32)
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, _ := curve25519.X25519(k, curve25519.Basepoint)
	return base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(p)
}

func hexKey(b64 string) string {
	b, _ := base64.StdEncoding.DecodeString(b64)
	return hex.EncodeToString(b)
}

func staticKey() string {
	h := hex.EncodeToString(random(256))
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

func newCA() (string, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "moley-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

func newLeaf(caPEM string, caKey *ecdsa.PrivateKey, cn string, eku x509.ExtKeyUsage) (cert, key string) {
	block, _ := pem.Decode([]byte(caPEM))
	ca, _ := x509.ParseCertificate(block.Bytes)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

func freeUDP() int {
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func freeTCP() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// lanIP is this machine's outbound interface address (no packet is sent).
func lanIP() string {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}
