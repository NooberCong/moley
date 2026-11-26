package importer

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/youmark/pkcs8"

	"moley/internal/model"
)

const defaultOpenVPNPort = 1194

type ovpnRemote struct {
	host    string
	port    uint16 // 0 means "use the port directive"
	network string // "" means "use the proto directive"
}

// ovpnParser collects directives; build() resolves the order-dependent ones
// (port/proto defaults, cipher fallback, key-direction) at the end.
type ovpnParser struct {
	keyPassword  string
	opts         option.OpenVPNClientEndpointOptions
	tls          option.OpenVPNOutboundTLSOptions
	remotes      []ovpnRemote
	network      string
	port         uint16
	cipher       string
	keyDirection string // OpenVPN's "0"/"1", applies to tls-auth only
	wrapType     string
	wrapKey      []string
	needsCreds   bool
	warned       map[string]bool
	res          Result
}

// ovpnSilent are directives that only matter to an OS client (or are
// defaults here) and are accepted without a warning.
var ovpnSilent = map[string]bool{
	"client": true, "tls-client": true, "pull": true, "nobind": true,
	"persist-key": true, "persist-tun": true, "persist-remote-ip": true, "persist-local-ip": true,
	"resolv-retry": true, "verb": true, "mute": true, "mute-replay-warnings": true,
	"auth-nocache": true, "setenv": true, "setenv-safe": true, "script-security": true,
	"up": true, "down": true, "route-up": true, "ipchange": true,
	"block-outside-dns": true, "redirect-gateway": true, "route-delay": true,
	"register-dns": true, "ip-win32": true, "route-method": true, "windows-driver": true,
	"dev-node": true, "float": true, "push-peer-info": true, "ignore-unknown-option": true,
	"server-poll-timeout": true, "connect-retry": true, "connect-retry-max": true,
	"connect-timeout": true, "sndbuf": true, "rcvbuf": true, "fast-io": true,
	"remap-usr1": true, "tun-ipv6": true, "key-method": true, "lport": true,
	"user": true, "group": true, "auth-token-user": true,
}

func parseOpenVPN(text string, opts Options) (Result, error) {
	p := &ovpnParser{port: defaultOpenVPNPort, warned: map[string]bool{}, keyPassword: opts.KeyPassword}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if tag, ok := blockStart(line); ok {
			end := "</" + tag + ">"
			var body []string
			for i++; i < len(lines) && strings.TrimSpace(lines[i]) != end; i++ {
				body = append(body, lines[i])
			}
			if i == len(lines) {
				return Result{}, fmt.Errorf("openvpn line %d: <%s> is not closed", lineNo, tag)
			}
			if err := p.block(tag, body); err != nil {
				return Result{}, fmt.Errorf("openvpn line %d: %w", lineNo, err)
			}
			continue
		}
		args, err := splitArgs(line)
		if err != nil {
			return Result{}, fmt.Errorf("openvpn line %d: %w", lineNo, err)
		}
		name := strings.TrimPrefix(args[0], "--")
		if err := p.directive(name, args[1:]); err != nil {
			return Result{}, fmt.Errorf("openvpn line %d: %s: %w", lineNo, name, err)
		}
	}
	return p.build()
}

func blockStart(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' || line[len(line)-1] != '>' || line[1] == '/' {
		return "", false
	}
	tag := line[1 : len(line)-1]
	return tag, directiveName.MatchString(tag)
}

// block handles inline <tag>…</tag> material. Material is stored one line
// per list entry; sing-box joins the entries with "\n".
func (p *ovpnParser) block(tag string, body []string) error {
	material := materialLines(body)
	switch tag {
	case "ca":
		p.tls.Certificate = material
	case "cert":
		p.tls.ClientCertificate = material
	case "key":
		key, err := decryptKey(body, p.keyPassword)
		if err != nil {
			return err
		}
		p.tls.ClientKey = materialLines(key)
	case "tls-auth", "tls-crypt", "tls-crypt-v2":
		p.wrapType = strings.ReplaceAll(tag, "-", "_")
		p.wrapKey = material
	case "auth-user-pass":
		if len(material) < 2 {
			return errors.New("<auth-user-pass> needs a username line and a password line")
		}
		p.opts.Username, p.opts.Password = material[0], material[1]
	case "peer-fingerprint":
		p.tls.PeerFingerprint = append(p.tls.PeerFingerprint, material...)
	case "dh":
		// Server-only; harmless in client profiles.
	case "secret":
		return errors.New("static-key (secret) profiles are not supported yet")
	case "pkcs12":
		return errors.New("PKCS#12 bundles are not supported; export the certificate and key as PEM <cert>/<key> blocks")
	case "connection":
		return errors.New("<connection> blocks are not supported yet; use remote lines")
	default:
		p.warn(fmt.Sprintf("openvpn: inline block <%s> ignored", tag))
	}
	return nil
}

func materialLines(body []string) badoption.Listable[string] {
	var out []string
	for _, l := range body {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (p *ovpnParser) directive(name string, args []string) error {
	switch name {
	case "remote":
		return p.remote(args)
	case "proto":
		if len(args) < 1 {
			return errors.New("missing protocol")
		}
		network, err := ovpnNetwork(args[0])
		if err != nil {
			return err
		}
		p.network = network
	case "port", "rport":
		port, err := portArg(args)
		if err != nil {
			return err
		}
		p.port = port
	case "dev", "dev-type":
		if len(args) < 1 {
			return errors.New("missing device")
		}
		if strings.HasPrefix(args[0], "tap") {
			return errors.New("tap (layer 2) profiles are not supported; only dev tun")
		}
		if !strings.HasPrefix(args[0], "tun") {
			return errors.New("unsupported device type; only dev tun")
		}
	case "remote-random":
		p.opts.RemoteRandom = true
	case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "secret":
		return p.fileReference(name, args)
	case "key-direction":
		if len(args) < 1 || (args[0] != "0" && args[0] != "1") {
			return errors.New("expected 0 or 1")
		}
		p.keyDirection = args[0]
	case "cipher":
		if len(args) < 1 {
			return errors.New("missing cipher")
		}
		p.cipher = args[0]
	case "data-ciphers", "ncp-ciphers":
		if len(args) < 1 {
			return errors.New("missing cipher list")
		}
		p.opts.DataCiphers = strings.Split(args[0], ":")
	case "data-ciphers-fallback":
		if len(args) < 1 {
			return errors.New("missing cipher")
		}
		p.opts.DataCiphersFallback = args[0]
	case "auth":
		if len(args) < 1 {
			return errors.New("missing digest")
		}
		p.opts.Auth = args[0]
	case "tls-version-min":
		if len(args) < 1 {
			return errors.New("missing version")
		}
		p.tls.VersionMin = args[0] // "or-highest" is OpenVPN's default behaviour anyway
	case "tls-version-max":
		if len(args) < 1 {
			return errors.New("missing version")
		}
		p.tls.VersionMax = args[0]
	case "tls-cipher":
		if len(args) < 1 {
			return errors.New("missing cipher list")
		}
		p.tls.Cipher = args[0]
	case "tls-groups":
		if len(args) < 1 {
			return errors.New("missing group list")
		}
		p.tls.Groups = args[0]
	case "tls-cert-profile":
		if len(args) < 1 {
			return errors.New("missing profile")
		}
		p.tls.CertificateProfile = args[0]
	case "verify-x509-name":
		if len(args) < 1 {
			return errors.New("missing name")
		}
		p.tls.ServerName = args[0]
		// OpenVPN defaults to matching the whole subject; sing-box would
		// default to "name", so always spell the type out.
		p.tls.ServerNameType = "subject"
		if len(args) > 1 {
			p.tls.ServerNameType = args[1]
		}
	case "remote-cert-tls":
		if len(args) < 1 {
			return errors.New("missing server or client")
		}
		p.tls.RemoteCertificateTLS = args[0]
	case "remote-cert-eku":
		if len(args) < 1 {
			return errors.New("missing EKU")
		}
		p.tls.RemoteCertificateEKU = args[0]
	case "remote-cert-ku":
		p.tls.RemoteCertificateKU = args
	case "ns-cert-type":
		if len(args) < 1 {
			return errors.New("missing server or client")
		}
		p.tls.NSCertificateType = args[0]
	case "peer-fingerprint":
		p.tls.PeerFingerprint = append(p.tls.PeerFingerprint, args...)
	case "auth-user-pass":
		// A credentials file argument is not read; build() warns instead.
		p.needsCreds = true
	case "auth-retry":
		if len(args) < 1 {
			return errors.New("missing mode")
		}
		p.opts.AuthRetry = args[0]
	case "static-challenge":
		if len(args) < 1 {
			return errors.New("missing challenge text")
		}
		p.opts.StaticChallenge = args[0]
		p.opts.StaticChallengeEcho = len(args) > 1 && args[1] == "1"
	case "comp-lzo":
		p.opts.CompressionLZO = "adaptive" // OpenVPN's meaning of a bare comp-lzo
		if len(args) > 0 {
			p.opts.CompressionLZO = args[0]
		}
	case "compress":
		return p.compress(args)
	case "allow-compression":
		if len(args) < 1 {
			return errors.New("missing mode")
		}
		p.opts.AllowCompression = args[0]
	case "tun-mtu":
		v, err := uintArg(args, 0, 65535)
		if err != nil {
			return err
		}
		p.opts.MTU = uint32(v)
	case "mssfix":
		return p.mssfix(args)
	case "fragment":
		v, err := uintArg(args, 0, 65535)
		if err != nil {
			return err
		}
		p.opts.Fragment = uint32(v)
	case "replay-window":
		v, err := uintArg(args, 0, 65535)
		if err != nil {
			return err
		}
		p.opts.ReplayWindow = uint32(v)
		if len(args) > 1 {
			t, err := secondsArg(args[1:])
			if err != nil {
				return err
			}
			p.opts.ReplayWindowTime = t
		}
	case "ping":
		t, err := secondsArg(args)
		if err != nil {
			return err
		}
		p.opts.PingInterval = t
	case "ping-restart":
		return p.pingRestart(args)
	case "keepalive":
		// Client side of "keepalive interval timeout" is ping + ping-restart.
		if len(args) < 2 {
			return errors.New("expected interval and timeout")
		}
		t, err := secondsArg(args)
		if err != nil {
			return err
		}
		p.opts.PingInterval = t
		return p.pingRestart(args[1:])
	case "reneg-sec":
		v, err := uintArg(args, 0, 1<<31)
		if err != nil {
			return err
		}
		p.opts.RenegotiateDisabled = v == 0
		p.opts.RenegotiateInterval = badoption.Duration(time.Duration(v) * time.Second)
	case "reneg-bytes":
		v, err := uintArg(args, 0, 1<<62)
		if err != nil {
			return err
		}
		p.opts.RenegotiateBytes = v
	case "reneg-pkts":
		v, err := uintArg(args, 0, 1<<62)
		if err != nil {
			return err
		}
		p.opts.RenegotiatePackets = v
	case "hand-window":
		t, err := secondsArg(args)
		if err != nil {
			return err
		}
		p.opts.HandshakeWindow = t
	case "tls-timeout":
		t, err := secondsArg(args)
		if err != nil {
			return err
		}
		p.opts.TLSTimeout = t
	case "explicit-exit-notify":
		p.opts.ExplicitExitNotify = 1
		if len(args) > 0 {
			v, err := uintArg(args, 0, 255)
			if err != nil {
				return err
			}
			p.opts.ExplicitExitNotify = uint32(v)
		}
	case "topology":
		if len(args) < 1 {
			return errors.New("missing topology")
		}
		p.opts.Topology = args[0]
	case "route-nopull":
		p.opts.RouteNoPull = true
	case "pull-filter":
		if len(args) < 2 {
			return errors.New("expected action and text")
		}
		p.opts.PullFilters = append(p.opts.PullFilters, option.OpenVPNPullFilterOptions{Action: args[0], Text: args[1]})
	case "route":
		return p.route(args)
	case "route-ipv6":
		if len(args) < 1 {
			return errors.New("missing prefix")
		}
		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			return errors.New("not an IPv6 prefix")
		}
		p.opts.Routes = append(p.opts.Routes, prefix)
	default:
		if !ovpnSilent[name] {
			p.warn(fmt.Sprintf("openvpn: directive %s ignored", describeKey(name)))
		}
	}
	return nil
}

func (p *ovpnParser) warn(msg string) {
	if !p.warned[msg] {
		p.warned[msg] = true
		p.res.Warnings = append(p.res.Warnings, msg)
	}
}

func (p *ovpnParser) remote(args []string) error {
	if len(args) < 1 {
		return errors.New("missing host")
	}
	r := ovpnRemote{host: args[0]}
	if len(args) > 1 {
		port, err := portArg(args[1:])
		if err != nil {
			return err
		}
		r.port = port
	}
	if len(args) > 2 {
		network, err := ovpnNetwork(args[2])
		if err != nil {
			return err
		}
		r.network = network
	}
	p.remotes = append(p.remotes, r)
	return nil
}

func (p *ovpnParser) fileReference(name string, args []string) error {
	switch {
	case name == "secret":
		return errors.New("static-key (secret) profiles are not supported yet")
	case len(args) == 0:
		return errors.New("missing file name")
	case args[0] != "[inline]":
		return fmt.Errorf("refers to file %q; paste its contents inline as <%s>…</%s>", args[0], name, name)
	}
	// "tls-auth [inline] 1" carries the key direction.
	if name == "tls-auth" && len(args) > 1 {
		return p.directive("key-direction", args[1:2])
	}
	return nil
}

func (p *ovpnParser) compress(args []string) error {
	if len(args) == 0 {
		p.opts.Compression = "stub" // bare "compress": framing only, no compression
		return nil
	}
	switch args[0] {
	case "lz4", "lz4-v2", "stub", "stub-v2":
		p.opts.Compression = args[0]
	case "lzo":
		p.opts.CompressionLZO = "yes"
	default:
		return errors.New("unsupported compression algorithm")
	}
	return nil
}

func (p *ovpnParser) mssfix(args []string) error {
	if len(args) == 0 {
		return nil // bare mssfix uses the default, which is already on
	}
	v, err := uintArg(args, 0, 65535)
	if err != nil {
		return err
	}
	if v == 0 {
		p.opts.MSSFixDisabled = true
		return nil
	}
	p.opts.MSSFix = uint32(v)
	if len(args) > 1 {
		p.opts.MSSFixMode = args[1]
	}
	return nil
}

func (p *ovpnParser) pingRestart(args []string) error {
	t, err := secondsArg(args)
	if err != nil {
		return err
	}
	p.opts.PingRestart = t
	p.opts.PingRestartDisabled = t == 0
	return nil
}

func (p *ovpnParser) route(args []string) error {
	if len(args) < 1 {
		return errors.New("missing network")
	}
	addr, err := netip.ParseAddr(args[0])
	if err != nil || !addr.Is4() {
		// Hostnames and keywords like vpn_gateway need the OS client.
		p.warn("openvpn: route with a non-IPv4 network ignored")
		return nil
	}
	bits := 32
	if len(args) > 1 && args[1] != "default" {
		mask, err := netip.ParseAddr(args[1])
		if err != nil || !mask.Is4() {
			return errors.New("invalid netmask")
		}
		ones, ok := maskBits(mask)
		if !ok {
			return errors.New("netmask is not contiguous")
		}
		bits = ones
	}
	p.opts.Routes = append(p.opts.Routes, netip.PrefixFrom(addr, bits).Masked())
	return nil
}

func maskBits(mask netip.Addr) (int, bool) {
	b := mask.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for v&(1<<31) != 0 {
		ones++
		v <<= 1
	}
	return ones, v == 0
}

func (p *ovpnParser) build() (Result, error) {
	if len(p.remotes) == 0 {
		return Result{}, errors.New("openvpn: no remote server")
	}
	if len(p.tls.Certificate) == 0 && len(p.tls.PeerFingerprint) == 0 {
		return Result{}, errors.New("openvpn: no inline <ca> certificate")
	}
	if (len(p.tls.ClientCertificate) == 0) != (len(p.tls.ClientKey) == 0) {
		return Result{}, errors.New("openvpn: <cert> and <key> must be given together")
	}

	if len(p.remotes) == 1 {
		r := p.resolveRemote(p.remotes[0])
		p.opts.Server, p.opts.ServerPort, p.opts.Network = r.Server, r.ServerPort, r.Network
	} else {
		for _, r := range p.remotes {
			p.opts.Servers = append(p.opts.Servers, p.resolveRemote(r))
		}
	}

	// In TLS mode sing-box rejects "cipher"; OpenVPN uses it as the fallback
	// for servers that cannot negotiate data-ciphers.
	if p.cipher != "" && p.opts.DataCiphersFallback == "" {
		p.opts.DataCiphersFallback = p.cipher
	}

	if p.wrapType != "" {
		wrap := &option.OpenVPNControlWrapOptions{Type: p.wrapType, Key: p.wrapKey}
		if p.wrapType == "tls_auth" {
			switch p.keyDirection {
			case "0":
				wrap.Direction = "server"
			case "1":
				wrap.Direction = "client"
			}
		}
		p.tls.ControlWrap = wrap
	}
	p.opts.TLS = &p.tls

	if p.needsCreds && p.opts.Username == "" {
		p.warn("openvpn: server needs username/password (auth-user-pass); set them on the profile")
	}

	raw, err := marshalConfig(p.opts)
	if err != nil {
		return Result{}, err
	}
	p.res.Profiles = []model.Profile{{Kind: model.KindOpenVPN, AutoRule: true, Config: raw}}
	return p.res, nil
}

func (p *ovpnParser) resolveRemote(r ovpnRemote) option.OpenVPNRemoteOptions {
	out := option.OpenVPNRemoteOptions{
		ServerOptions: option.ServerOptions{Server: r.host, ServerPort: r.port},
		Network:       r.network,
	}
	if out.ServerPort == 0 {
		out.ServerPort = p.port
	}
	if out.Network == "" {
		out.Network = p.network
	}
	if out.Network == "" {
		out.Network = "udp" // OpenVPN's default proto
	}
	return out
}

// ovpnNetwork maps OpenVPN proto names onto sing-box network values.
func ovpnNetwork(proto string) (string, error) {
	switch proto {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return proto, nil
	case "tcp-client":
		return "tcp", nil
	case "tcp4-client":
		return "tcp4", nil
	case "tcp6-client":
		return "tcp6", nil
	}
	return "", errors.New("unsupported protocol (expected udp or tcp)")
}

func portArg(args []string) (uint16, error) {
	v, err := uintArg(args, 1, 65535)
	return uint16(v), err
}

func uintArg(args []string, lo, hi uint64) (uint64, error) {
	if len(args) < 1 {
		return 0, errors.New("missing number")
	}
	v, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil || v < lo || v > hi {
		return 0, errors.New("invalid number")
	}
	return v, nil
}

func secondsArg(args []string) (badoption.Duration, error) {
	v, err := uintArg(args, 0, 1<<31)
	return badoption.Duration(time.Duration(v) * time.Second), err
}

// splitArgs splits an OpenVPN config line into words, honouring double and
// single quotes and backslash escapes as OpenVPN does.
func splitArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != '\'' && c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			inWord = true
		case quote != 0:
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
			inWord = true
		case c == ' ' || c == '\t':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '#' || c == ';':
			if !inWord {
				i = len(line) // trailing comment
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("empty line")
	}
	return args, nil
}

// ErrKeyEncrypted means the <key> needs a password (see Options).
var ErrKeyEncrypted = errors.New("the private key is encrypted: import it with its password (moley import --key-password-stdin)")

// decryptKey returns the <key> block as an unencrypted PKCS#8 PEM. sing-box
// has no key-password option, so encrypted keys (PKCS#8 "ENCRYPTED PRIVATE
// KEY" or legacy "Proc-Type: 4,ENCRYPTED") are decrypted at import.
func decryptKey(body []string, password string) ([]string, error) {
	block, _ := pem.Decode([]byte(strings.Join(body, "\n")))
	if block == nil {
		return body, nil // let the core report malformed material
	}
	var der []byte
	switch {
	case block.Type == "ENCRYPTED PRIVATE KEY":
		if password == "" {
			return nil, ErrKeyEncrypted
		}
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
		if err != nil {
			return nil, errors.New("the private key password is wrong, or the key format is unsupported")
		}
		if der, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
			return nil, err
		}
	case x509.IsEncryptedPEMBlock(block): //nolint:staticcheck // legacy OpenSSL keys still exist
		if password == "" {
			return nil, ErrKeyEncrypted
		}
		raw, err := x509.DecryptPEMBlock(block, []byte(password)) //nolint:staticcheck
		if err != nil {
			return nil, errors.New("the private key password is wrong")
		}
		return pemLines(&pem.Block{Type: block.Type, Bytes: raw}), nil
	default:
		return body, nil
	}
	return pemLines(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func pemLines(b *pem.Block) []string {
	return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(b))), "\n")
}
