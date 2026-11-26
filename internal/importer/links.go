package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"moley/internal/model"
)

// parseLinks parses one share link per line. A bad line becomes a warning
// (line number and scheme only) and parsing continues; it is an error only
// when no line yields a profile.
func parseLinks(text string) (Result, error) {
	var res Result
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		scheme := linkScheme(line)
		profile, err := parseLink(scheme, line)
		if err != nil {
			label := scheme
			if label == "" {
				label = "not a share link"
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: %s: %v", n+1, label, err))
			continue
		}
		profile.Source = "link"
		res.Profiles = append(res.Profiles, profile)
	}
	if len(res.Profiles) == 0 {
		return Result{}, fmt.Errorf("no share link could be imported: %s", strings.Join(res.Warnings, "; "))
	}
	return res, nil
}

// linkScheme returns the lowercased scheme, or "" when it does not look like
// one (so nothing else from the line ends up in a warning).
func linkScheme(line string) string {
	scheme, _, ok := strings.Cut(line, "://")
	scheme = strings.ToLower(scheme)
	if !ok || len(scheme) > 16 || !directiveName.MatchString(scheme) {
		return ""
	}
	return scheme
}

func parseLink(scheme, line string) (model.Profile, error) {
	var kind, name string
	var cfg any
	var err error
	switch scheme {
	case "ss":
		kind = model.KindShadowsocks
		cfg, name, err = parseShadowsocks(line)
	case "vless":
		kind = model.KindVLESS
		cfg, name, err = parseVLESS(line)
	case "vmess":
		kind = model.KindVMess
		cfg, name, err = parseVMess(line)
	case "trojan":
		kind = model.KindTrojan
		cfg, name, err = parseTrojan(line)
	case "hysteria2", "hy2":
		kind = model.KindHysteria2
		cfg, name, err = parseHysteria2(line)
	case "tuic":
		kind = model.KindTUIC
		cfg, name, err = parseTUIC(line)
	case "socks", "socks5":
		kind = model.KindSOCKS
		cfg, name, err = parseSOCKS(line)
	case "http", "https":
		kind = model.KindHTTP
		cfg, name, err = parseHTTPProxy(line)
	case "":
		err = errors.New("ignored")
	default:
		err = errors.New("unsupported scheme")
	}
	if err != nil {
		return model.Profile{}, err
	}
	raw, err := marshalConfig(cfg)
	if err != nil {
		return model.Profile{}, errors.New("could not encode options")
	}
	return model.Profile{ID: name, Kind: kind, Config: raw}, nil
}

// parseURL never returns url.Parse's error, which quotes the whole link.
func parseURL(line string) (*url.URL, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, errors.New("malformed URL")
	}
	return u, nil
}

// server returns host and port; defaultPort 0 means the port is required.
func server(u *url.URL, defaultPort uint16) (option.ServerOptions, error) {
	host := u.Hostname()
	if host == "" {
		return option.ServerOptions{}, errors.New("missing host")
	}
	if u.Port() == "" {
		if defaultPort == 0 {
			return option.ServerOptions{}, errors.New("missing port")
		}
		return option.ServerOptions{Server: host, ServerPort: defaultPort}, nil
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return option.ServerOptions{}, errors.New("invalid port")
	}
	return option.ServerOptions{Server: host, ServerPort: uint16(port)}, nil
}

// linkName is the #fragment, or kind-host as a stable fallback ID hint.
func linkName(u *url.URL, kind string) string {
	if u.Fragment != "" {
		return u.Fragment
	}
	return kind + "-" + u.Hostname()
}

// userinfo returns the whole userinfo ("user" or "user:pass") unescaped.
func userinfo(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	if pass, ok := u.User.Password(); ok {
		return u.User.Username() + ":" + pass
	}
	return u.User.Username()
}

func isTrue(v string) bool { return v == "1" || strings.EqualFold(v, "true") }

func parseShadowsocks(line string) (any, string, error) {
	body, frag, _ := strings.Cut(line[len("ss://"):], "#")
	if !strings.Contains(body, "@") {
		return parseLegacyShadowsocks(body, frag)
	}
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	srv, err := server(u, 0)
	if err != nil {
		return nil, "", err
	}
	opts := option.ShadowsocksOutboundOptions{ServerOptions: srv}
	if u.User == nil {
		return nil, "", errors.New("missing method and password")
	}
	if pass, ok := u.User.Password(); ok {
		// SIP002 allows plain percent-encoded "method:password" (2022 ciphers).
		opts.Method, opts.Password = u.User.Username(), pass
	} else {
		decoded, ok := decodeBase64(u.User.Username())
		if !ok {
			return nil, "", errors.New("userinfo is not base64")
		}
		opts.Method, opts.Password, _ = strings.Cut(decoded, ":")
	}
	if opts.Method == "" {
		return nil, "", errors.New("missing method")
	}
	if plugin := u.Query().Get("plugin"); plugin != "" {
		name, pluginOpts, _ := strings.Cut(plugin, ";")
		switch name {
		case "obfs-local", "simple-obfs":
			opts.Plugin = "obfs-local"
		case "v2ray-plugin":
			opts.Plugin = name
		default:
			return nil, "", errors.New("unsupported plugin")
		}
		opts.PluginOptions = pluginOpts
	}
	return opts, linkName(u, model.KindShadowsocks), nil
}

// parseLegacyShadowsocks handles ss://base64(method:password@host:port)#tag.
func parseLegacyShadowsocks(body, frag string) (any, string, error) {
	body, _, _ = strings.Cut(body, "?")
	decoded, ok := decodeBase64(strings.TrimSuffix(body, "/"))
	if !ok {
		return nil, "", errors.New("body is not base64")
	}
	at := strings.LastIndex(decoded, "@")
	if at < 0 {
		return nil, "", errors.New("missing server")
	}
	method, password, _ := strings.Cut(decoded[:at], ":")
	host, port, err := splitHostPort(decoded[at+1:])
	if err != nil {
		return nil, "", err
	}
	if method == "" {
		return nil, "", errors.New("missing method")
	}
	name, err := url.PathUnescape(frag)
	if err != nil {
		name = frag
	}
	if name == "" {
		name = model.KindShadowsocks + "-" + host
	}
	return option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{Server: host, ServerPort: port},
		Method:        method,
		Password:      password,
	}, name, nil
}

// stream holds the TLS and transport settings shared by vless, vmess and
// trojan links (query parameters, or vmess JSON fields).
type stream struct {
	security    string // "", "none", "tls", "reality"
	sni         string
	fingerprint string
	alpn        string
	insecure    bool
	publicKey   string
	shortID     string
	network     string // "", "tcp", "ws", "grpc", "http", "h2", "httpupgrade", "quic"
	host        string
	path        string
	serviceName string
	headerType  string
}

func streamFromQuery(q url.Values) stream {
	return stream{
		security:    strings.ToLower(q.Get("security")),
		sni:         q.Get("sni"),
		fingerprint: q.Get("fp"),
		alpn:        q.Get("alpn"),
		insecure:    isTrue(q.Get("allowInsecure")) || isTrue(q.Get("insecure")),
		publicKey:   q.Get("pbk"),
		shortID:     q.Get("sid"),
		network:     strings.ToLower(q.Get("type")),
		host:        q.Get("host"),
		path:        q.Get("path"),
		serviceName: q.Get("serviceName"),
		headerType:  q.Get("headerType"),
	}
}

func (s stream) tls() (*option.OutboundTLSOptions, error) {
	switch s.security {
	case "", "none":
		return nil, nil
	case "tls", "reality":
	default:
		return nil, errors.New("unsupported security")
	}
	t := &option.OutboundTLSOptions{Enabled: true, ServerName: s.sni, Insecure: s.insecure}
	if t.ServerName == "" && s.host != "" && s.network != "grpc" {
		t.ServerName = s.host // v2rayN falls back to the Host header for SNI
	}
	if s.alpn != "" {
		t.ALPN = splitList(s.alpn)
	}
	fingerprint := s.fingerprint
	if s.security == "reality" {
		if s.publicKey == "" {
			return nil, errors.New("reality link has no public key (pbk)")
		}
		t.Reality = &option.OutboundRealityOptions{Enabled: true, PublicKey: s.publicKey, ShortID: s.shortID}
		if fingerprint == "" {
			fingerprint = "chrome" // sing-box requires uTLS for REALITY
		}
	}
	if fingerprint != "" {
		t.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint}
	}
	return t, nil
}

func (s stream) transport() (*option.V2RayTransportOptions, error) {
	switch s.network {
	case "", "tcp", "raw":
		if s.headerType != "" && s.headerType != "none" {
			return nil, errors.New("unsupported tcp header type")
		}
		return nil, nil
	case "ws":
		ws := option.V2RayWebsocketOptions{Path: s.path}
		// Xray puts early data in the path ("/ws?ed=2048").
		if path, query, ok := strings.Cut(s.path, "?"); ok {
			if q, err := url.ParseQuery(query); err == nil && q.Get("ed") != "" {
				if ed, err := strconv.ParseUint(q.Get("ed"), 10, 32); err == nil {
					ws.Path = path
					ws.MaxEarlyData = uint32(ed)
					ws.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				}
			}
		}
		if s.host != "" {
			ws.Headers = badoption.HTTPHeader{"Host": {s.host}}
		}
		return &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: ws}, nil
	case "grpc":
		return &option.V2RayTransportOptions{Type: "grpc", GRPCOptions: option.V2RayGRPCOptions{ServiceName: s.serviceName}}, nil
	case "http", "h2":
		h := option.V2RayHTTPOptions{Path: s.path}
		if s.host != "" {
			h.Host = splitList(s.host)
		}
		return &option.V2RayTransportOptions{Type: "http", HTTPOptions: h}, nil
	case "httpupgrade":
		return &option.V2RayTransportOptions{Type: "httpupgrade", HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Host: s.host, Path: s.path}}, nil
	case "quic":
		return &option.V2RayTransportOptions{Type: "quic"}, nil
	}
	return nil, errors.New("unsupported transport")
}

func parseVLESS(line string) (any, string, error) {
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	srv, err := server(u, 0)
	if err != nil {
		return nil, "", err
	}
	opts := option.VLESSOutboundOptions{ServerOptions: srv, UUID: u.User.Username(), Flow: u.Query().Get("flow")}
	if opts.UUID == "" {
		return nil, "", errors.New("missing uuid")
	}
	s := streamFromQuery(u.Query())
	if opts.TLS, err = s.tls(); err != nil {
		return nil, "", err
	}
	if opts.Transport, err = s.transport(); err != nil {
		return nil, "", err
	}
	return opts, linkName(u, model.KindVLESS), nil
}

func parseTrojan(line string) (any, string, error) {
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	srv, err := server(u, 443)
	if err != nil {
		return nil, "", err
	}
	opts := option.TrojanOutboundOptions{ServerOptions: srv, Password: userinfo(u)}
	if opts.Password == "" {
		return nil, "", errors.New("missing password")
	}
	s := streamFromQuery(u.Query())
	if s.security == "" {
		s.security = "tls" // trojan is TLS unless the link says otherwise
	}
	if opts.TLS, err = s.tls(); err != nil {
		return nil, "", err
	}
	if opts.Transport, err = s.transport(); err != nil {
		return nil, "", err
	}
	return opts, linkName(u, model.KindTrojan), nil
}

// parseVMess handles the v2rayN format: vmess://base64(JSON).
func parseVMess(line string) (any, string, error) {
	body, _, _ := strings.Cut(line[len("vmess://"):], "#")
	decoded, ok := decodeBase64(body)
	if !ok {
		return nil, "", errors.New("body is not base64")
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(decoded), &fields); err != nil {
		return nil, "", errors.New("body is not v2rayN JSON")
	}
	get := func(key string) string {
		switch v := fields[key].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	port, err := strconv.ParseUint(get("port"), 10, 16)
	if err != nil || port == 0 {
		return nil, "", errors.New("invalid port")
	}
	opts := option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{Server: get("add"), ServerPort: uint16(port)},
		UUID:          get("id"),
		Security:      get("scy"),
	}
	if opts.Server == "" || opts.UUID == "" {
		return nil, "", errors.New("missing address or id")
	}
	if opts.Security == "" {
		opts.Security = "auto"
	}
	if aid := get("aid"); aid != "" {
		n, err := strconv.Atoi(aid)
		if err != nil || n < 0 {
			return nil, "", errors.New("invalid alterId")
		}
		opts.AlterId = n
	}
	s := stream{
		security:    strings.ToLower(get("tls")),
		sni:         get("sni"),
		fingerprint: get("fp"),
		alpn:        get("alpn"),
		insecure:    isTrue(get("allowInsecure")),
		network:     strings.ToLower(get("net")),
		host:        get("host"),
		path:        get("path"),
		serviceName: get("path"), // v2rayN stores the gRPC service name in "path"
		headerType:  get("type"),
	}
	if opts.TLS, err = s.tls(); err != nil {
		return nil, "", err
	}
	if opts.Transport, err = s.transport(); err != nil {
		return nil, "", err
	}
	name := get("ps")
	if name == "" {
		name = model.KindVMess + "-" + opts.Server
	}
	return opts, name, nil
}

func parseHysteria2(line string) (any, string, error) {
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	srv, err := server(u, 443)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	opts := option.Hysteria2OutboundOptions{
		ServerOptions: srv,
		Password:      userinfo(u),
	}
	opts.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: q.Get("sni"), Insecure: isTrue(q.Get("insecure"))}
	if alpn := q.Get("alpn"); alpn != "" {
		opts.TLS.ALPN = splitList(alpn)
	}
	switch obfs := q.Get("obfs"); obfs {
	case "", "none":
	case "salamander":
		opts.Obfs = &option.Hysteria2Obfs{Type: "salamander", Password: q.Get("obfs-password")}
	default:
		return nil, "", errors.New("unsupported obfs")
	}
	return opts, linkName(u, model.KindHysteria2), nil
}

func parseTUIC(line string) (any, string, error) {
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	srv, err := server(u, 0)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	opts := option.TUICOutboundOptions{ServerOptions: srv, UDPRelayMode: q.Get("udp_relay_mode")}
	if u.User != nil {
		opts.UUID = u.User.Username()
		opts.Password, _ = u.User.Password()
	}
	if opts.UUID == "" {
		return nil, "", errors.New("missing uuid")
	}
	opts.CongestionControl = q.Get("congestion_control")
	if opts.CongestionControl == "" {
		opts.CongestionControl = q.Get("congestion-control")
	}
	opts.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: q.Get("sni"),
		Insecure:   isTrue(q.Get("allow_insecure")) || isTrue(q.Get("insecure")) || isTrue(q.Get("allowInsecure")),
	}
	if alpn := q.Get("alpn"); alpn != "" {
		opts.TLS.ALPN = splitList(alpn)
	}
	return opts, linkName(u, model.KindTUIC), nil
}

func parseSOCKS(line string) (any, string, error) {
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	srv, err := server(u, 1080)
	if err != nil {
		return nil, "", err
	}
	opts := option.SOCKSOutboundOptions{ServerOptions: srv, Version: "5"}
	if u.User != nil {
		if pass, ok := u.User.Password(); ok {
			opts.Username, opts.Password = u.User.Username(), pass
		} else if decoded, ok := decodeBase64(u.User.Username()); ok && strings.Contains(decoded, ":") {
			// v2rayN form: socks://base64(user:pass)@host:port
			opts.Username, opts.Password, _ = strings.Cut(decoded, ":")
		} else {
			opts.Username = u.User.Username()
		}
	}
	return opts, linkName(u, model.KindSOCKS), nil
}

// parseHTTPProxy accepts http(s)://[user:pass@]host[:port][#name]. A URL with
// a path or query is a web page or subscription URL, not a proxy.
func parseHTTPProxy(line string) (any, string, error) {
	u, err := parseURL(line)
	if err != nil {
		return nil, "", err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, "", errors.New("URL with a path looks like a web or subscription URL, not a proxy; fetch it and import the body")
	}
	defaultPort := uint16(80)
	if u.Scheme == "https" {
		defaultPort = 443
	}
	srv, err := server(u, defaultPort)
	if err != nil {
		return nil, "", err
	}
	opts := option.HTTPOutboundOptions{ServerOptions: srv}
	if u.User != nil {
		opts.Username = u.User.Username()
		opts.Password, _ = u.User.Password()
	}
	if u.Scheme == "https" {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return opts, linkName(u, model.KindHTTP), nil
}
