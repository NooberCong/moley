package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Type = "amneziawg"

// Register adds the outbound to a core outbound registry.
func Register(registry *outbound.Registry) {
	outbound.Register(registry, Type, New)
}

type Outbound struct {
	outbound.Adapter
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
	options   Options
	dev       *device.Device
	net       *netstack.Net
}

var _ adapter.Lifecycle = (*Outbound)(nil)

func New(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	if _, err := uapiConfig(options, nil); err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:   outbound.NewAdapter(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		options:   options,
	}, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	var local, dns []netip.Addr
	for _, a := range o.options.Address {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("address %q: %w", a, err)
		}
		local = append(local, p.Addr())
	}
	for _, d := range o.options.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, a)
		}
	}
	mtu := o.options.MTU
	if mtu == 0 {
		mtu = 1420
	}
	tunDev, tnet, err := netstack.CreateNetTUN(local, dns, mtu)
	if err != nil {
		return err
	}
	// Peer endpoints are resolved once with the system resolver (the
	// tunnel's own DNS isn't reachable yet). A failed lookup only disables
	// that peer, logged, so one unresolvable profile never stops the engine.
	cfg, err := uapiConfig(o.options, func(host string) (netip.Addr, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			o.logger.Error("amneziawg: resolve peer ", host, ": ", err)
			return netip.Addr{}, false
		}
		return ips[0].Unmap(), true
	})
	if err != nil {
		tunDev.Close()
		return err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { o.logger.Error(fmt.Sprintf(f, a...)) },
	})
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return err
	}
	o.dev, o.net = dev, tnet
	scope.Add(func() error { dev.Close(); return nil })
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if o.net == nil {
		return nil, errors.New("amneziawg is not started")
	}
	o.logger.InfoContext(ctx, "outbound ", network, " connection to ", dest)
	addrs, err := o.resolve(ctx, dest)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, a := range addrs {
		c, err := o.net.DialContext(ctx, N.NetworkName(network), netip.AddrPortFrom(a, dest.Port).String())
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (o *Outbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	if o.net == nil {
		return nil, errors.New("amneziawg is not started")
	}
	return o.net.ListenUDPAddrPort(netip.AddrPort{})
}

func (o *Outbound) resolve(ctx context.Context, dest M.Socksaddr) ([]netip.Addr, error) {
	if !dest.IsDomain() {
		return []netip.Addr{dest.Addr}, nil
	}
	return o.dnsRouter.Lookup(ctx, dest.Fqdn, adapter.DNSQueryOptions{})
}

// uapiConfig renders the device configuration. With a nil resolve it only
// validates (endpoint hosts are not looked up).
func uapiConfig(o Options, resolve func(host string) (netip.Addr, bool)) (string, error) {
	var b strings.Builder
	key := func(name, v string) error {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("%s is not a base64 32-byte key", name)
		}
		fmt.Fprintf(&b, "%s=%s\n", name, hex.EncodeToString(raw))
		return nil
	}
	if err := key("private_key", o.PrivateKey); err != nil {
		return "", err
	}
	if len(o.Address) == 0 {
		return "", errors.New("address is required")
	}
	for _, kv := range []struct {
		k string
		v int
	}{{"jc", o.Jc}, {"jmin", o.Jmin}, {"jmax", o.Jmax}, {"s1", o.S1}, {"s2", o.S2}, {"s3", o.S3}, {"s4", o.S4}} {
		if kv.v != 0 {
			fmt.Fprintf(&b, "%s=%d\n", kv.k, kv.v)
		}
	}
	for _, kv := range []struct{ k, v string }{{"h1", o.H1}, {"h2", o.H2}, {"h3", o.H3}, {"h4", o.H4},
		{"i1", o.I1}, {"i2", o.I2}, {"i3", o.I3}, {"i4", o.I4}, {"i5", o.I5}} {
		if kv.v != "" {
			fmt.Fprintf(&b, "%s=%s\n", kv.k, kv.v)
		}
	}
	if len(o.Peers) == 0 {
		return "", errors.New("at least one peer is required")
	}
	for i, p := range o.Peers {
		if err := key("public_key", p.PublicKey); err != nil {
			return "", fmt.Errorf("peer %d: %w", i, err)
		}
		if p.PresharedKey != "" {
			if err := key("preshared_key", p.PresharedKey); err != nil {
				return "", fmt.Errorf("peer %d: %w", i, err)
			}
		}
		host, port, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			return "", fmt.Errorf("peer %d endpoint: %w", i, err)
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", fmt.Errorf("peer %d endpoint port %q", i, port)
		}
		if resolve != nil {
			addr, err := netip.ParseAddr(host)
			ok := err == nil
			if !ok {
				addr, ok = resolve(host)
			}
			if ok {
				fmt.Fprintf(&b, "endpoint=%s\n", net.JoinHostPort(addr.String(), port))
			}
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		allowed := p.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		for _, a := range allowed {
			if _, err := netip.ParsePrefix(a); err != nil {
				return "", fmt.Errorf("peer %d allowed_ips %q: %w", i, a, err)
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String(), nil
}
