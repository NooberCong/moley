package importer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"

	"moley/internal/awg"
	"moley/internal/model"
)

// wgConf is a wg-quick file reduced to the keys Moley uses. Values are kept
// as text until we know whether the target is WireGuard or AmneziaWG.
type wgConf struct {
	privateKey string
	addresses  []netip.Prefix
	dns        []string
	mtu        int
	listenPort int
	awg        map[string]string // lowercased AmneziaWG key -> raw value
	peers      []wgPeer
}

type wgPeer struct {
	publicKey    string
	presharedKey string
	host         string
	port         uint16
	allowedIPs   []netip.Prefix
	keepalive    int
}

// awgKeys are the [Interface] keys that make a config AmneziaWG.
var awgKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
}

// wgIgnoredKeys are wg-quick keys that only make sense for an OS interface.
var wgIgnoredKeys = map[string]bool{
	"table": true, "fwmark": true, "saveconfig": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

func parseWireGuard(text string) (Result, error) {
	var res Result
	conf := wgConf{awg: map[string]string{}}
	section := ""
	for n, line := range strings.Split(text, "\n") {
		lineNo := n + 1
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				conf.peers = append(conf.peers, wgPeer{})
			default:
				res.Warnings = append(res.Warnings, fmt.Sprintf("wireguard line %d: ignored unknown section", lineNo))
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("wireguard line %d: not a key = value line, ignored", lineNo))
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		var err error
		switch section {
		case "interface":
			err = conf.setInterfaceKey(key, value, &res)
		case "peer":
			err = conf.peers[len(conf.peers)-1].set(key, value, &res)
		default:
			continue // inside an unknown section, already warned
		}
		if err != nil {
			return Result{}, fmt.Errorf("wireguard line %d: %w", lineNo, err)
		}
	}
	if err := conf.validate(); err != nil {
		return Result{}, err
	}

	profile := model.Profile{Kind: model.KindWireGuard, DNS: conf.dns}
	var cfg any = conf.singBoxOptions()
	if len(conf.awg) > 0 {
		profile.Kind = model.KindAmneziaWG
		awgOpts, err := conf.awgOptions(&res)
		if err != nil {
			return Result{}, err
		}
		cfg = awgOpts
	}
	raw, err := marshalConfig(cfg)
	if err != nil {
		return Result{}, err
	}
	profile.Config = raw
	res.Profiles = []model.Profile{profile}
	return res, nil
}

func (c *wgConf) setInterfaceKey(key, value string, res *Result) error {
	switch {
	case key == "privatekey":
		c.privateKey = value
	case key == "address":
		for _, s := range splitList(value) {
			p, err := parsePrefixOrAddr(s)
			if err != nil {
				return fmt.Errorf("Address: %w", err)
			}
			c.addresses = append(c.addresses, p)
		}
	case key == "dns":
		for _, s := range splitList(value) {
			if _, err := netip.ParseAddr(s); err == nil {
				c.dns = append(c.dns, s)
			} else {
				res.Warnings = append(res.Warnings, fmt.Sprintf("wireguard: DNS search domain %q ignored", s))
			}
		}
	case key == "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 65535 {
			return errors.New("MTU: not a valid MTU")
		}
		c.mtu = mtu
	case key == "listenport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return errors.New("ListenPort: not a port number")
		}
		c.listenPort = int(port)
	case awgKeys[key]:
		c.awg[key] = value
	case wgIgnoredKeys[key]:
		res.Warnings = append(res.Warnings, fmt.Sprintf("wireguard: %s ignored (Moley manages routing itself)", key))
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf("wireguard: unknown [Interface] key %s ignored", describeKey(key)))
	}
	return nil
}

func (p *wgPeer) set(key, value string, res *Result) error {
	switch key {
	case "publickey":
		p.publicKey = value
	case "presharedkey":
		p.presharedKey = value
	case "endpoint":
		host, port, err := splitHostPort(value)
		if err != nil {
			return fmt.Errorf("Endpoint: %w", err)
		}
		p.host, p.port = host, port
	case "allowedips":
		for _, s := range splitList(value) {
			prefix, err := parsePrefixOrAddr(s)
			if err != nil {
				return fmt.Errorf("AllowedIPs: %w", err)
			}
			p.allowedIPs = append(p.allowedIPs, prefix)
		}
	case "persistentkeepalive":
		if strings.EqualFold(value, "off") {
			p.keepalive = 0
			return nil
		}
		v, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return errors.New("PersistentKeepalive: not a number of seconds")
		}
		p.keepalive = int(v)
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf("wireguard: unknown [Peer] key %s ignored", describeKey(key)))
	}
	return nil
}

// wgKey checks a key is 32 bytes of base64, as the core needs. A key of
// asterisks is a placeholder: providers (Proton VPN) mask it when the
// config is downloaded again after the key was first shown.
func wgKey(what, key string) error {
	if strings.Trim(key, "*") == "" {
		return fmt.Errorf("wireguard: the %s is hidden (%s): download the config again with its key, or create a new one", what, key)
	}
	if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 32 {
		return fmt.Errorf("wireguard: the %s isn't a WireGuard key (44 characters of base64)", what)
	}
	return nil
}

func (c *wgConf) validate() error {
	if c.privateKey == "" {
		return errors.New("wireguard: [Interface] has no PrivateKey")
	}
	if err := wgKey("private key", c.privateKey); err != nil {
		return err
	}
	if len(c.addresses) == 0 {
		return errors.New("wireguard: [Interface] has no Address")
	}
	if len(c.peers) == 0 {
		return errors.New("wireguard: no [Peer] section")
	}
	for i, p := range c.peers {
		if p.publicKey == "" {
			return fmt.Errorf("wireguard: peer %d has no PublicKey", i+1)
		}
		if err := wgKey(fmt.Sprintf("peer %d's public key", i+1), p.publicKey); err != nil {
			return err
		}
		if p.presharedKey != "" {
			if err := wgKey(fmt.Sprintf("peer %d's preshared key", i+1), p.presharedKey); err != nil {
				return err
			}
		}
		if p.host == "" {
			return fmt.Errorf("wireguard: peer %d has no Endpoint", i+1)
		}
	}
	return nil
}

func (c *wgConf) singBoxOptions() option.WireGuardEndpointOptions {
	opts := option.WireGuardEndpointOptions{
		Address:    c.addresses,
		PrivateKey: c.privateKey,
		MTU:        uint32(c.mtu),
		ListenPort: uint16(c.listenPort),
	}
	for _, p := range c.peers {
		opts.Peers = append(opts.Peers, option.WireGuardPeer{
			Address:                     p.host,
			Port:                        p.port,
			PublicKey:                   p.publicKey,
			PreSharedKey:                p.presharedKey,
			AllowedIPs:                  p.allowedIPs,
			PersistentKeepaliveInterval: uint16(p.keepalive),
		})
	}
	return opts
}

// awgOptions builds the AmneziaWG options. DNS stays empty: compile fills it
// from Profile.DNS.
func (c *wgConf) awgOptions(res *Result) (awg.Options, error) {
	opts := awg.Options{
		PrivateKey: c.privateKey,
		MTU:        c.mtu,
		H1:         c.awg["h1"], H2: c.awg["h2"], H3: c.awg["h3"], H4: c.awg["h4"],
		I1: c.awg["i1"], I2: c.awg["i2"], I3: c.awg["i3"], I4: c.awg["i4"], I5: c.awg["i5"],
	}
	for _, a := range c.addresses {
		opts.Address = append(opts.Address, a.String())
	}
	ints := []struct {
		key string
		dst *int
	}{
		{"jc", &opts.Jc}, {"jmin", &opts.Jmin}, {"jmax", &opts.Jmax},
		{"s1", &opts.S1}, {"s2", &opts.S2}, {"s3", &opts.S3}, {"s4", &opts.S4},
	}
	for _, f := range ints {
		v, ok := c.awg[f.key]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return awg.Options{}, fmt.Errorf("amneziawg: %s is not a non-negative integer", f.key)
		}
		*f.dst = n
	}
	if c.listenPort != 0 {
		res.Warnings = append(res.Warnings, "amneziawg: ListenPort ignored")
	}
	for _, p := range c.peers {
		peer := awg.Peer{
			PublicKey:           p.publicKey,
			PresharedKey:        p.presharedKey,
			Endpoint:            net.JoinHostPort(p.host, strconv.Itoa(int(p.port))),
			PersistentKeepalive: p.keepalive,
		}
		for _, a := range p.allowedIPs {
			peer.AllowedIPs = append(peer.AllowedIPs, a.String())
		}
		opts.Peers = append(opts.Peers, peer)
	}
	return opts, nil
}

func splitList(value string) []string {
	var out []string
	for _, s := range strings.Split(value, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parsePrefixOrAddr accepts "10.0.0.2/32" or a bare "10.0.0.2" (host prefix),
// as wg-quick does.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("%q is not an IP prefix", s)
}

// splitHostPort parses "host:port" and "[v6]:port". The error never echoes
// the input.
func splitHostPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", 0, errors.New("expected host:port")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("invalid port")
	}
	return host, uint16(port), nil
}
