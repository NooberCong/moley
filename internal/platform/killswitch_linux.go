package platform

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// CanRouteSystem says whether this process may create the TUN interface
// and firewall rules: root, or CAP_NET_ADMIN (the systemd unit grants it).
func CanRouteSystem() error {
	if os.Geteuid() == 0 || hasCapNetAdmin() {
		return nil
	}
	return errors.New("system mode needs the Moley service: sudo systemctl enable --now moley")
}

func hasCapNetAdmin() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && caps&(1<<12) != 0 // CAP_NET_ADMIN
		}
	}
	return false
}

var killSwitch struct {
	sync.Mutex
	mode string
}

// SetKillSwitch loads an nftables table that drops output that doesn't
// leave through Moley: everything but this daemon's own sockets, loopback,
// the local network, DHCP, NDP and iface. "on" holds while the daemon runs; "persistent" is
// restored at boot by moley-killswitch.service until turned off.
func SetKillSwitch(mode, iface string) error {
	killSwitch.Lock()
	defer killSwitch.Unlock()
	marker := persistentMarker()
	switch mode {
	case "off":
		if err := nft("table inet moley\ndelete table inet moley\n"); err != nil {
			return err
		}
		killSwitch.mode = mode
		return removeIfExists(marker)
	case "on", "persistent":
		if err := nft(killSwitchRules(iface, os.Geteuid())); err != nil {
			return err
		}
		killSwitch.mode = mode
		if mode == "on" {
			return removeIfExists(marker)
		}
		if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
			return err
		}
		return os.WriteFile(marker, nil, 0o644)
	}
	return fmt.Errorf("kill switch: unknown mode %q", mode)
}

// ReleaseKillSwitch is for a daemon that is stopping: the "on" block
// lifts, a persistent one stays (without the daemon's permits).
func ReleaseKillSwitch() {
	killSwitch.Lock()
	defer killSwitch.Unlock()
	switch killSwitch.mode {
	case "on":
		_ = nft("table inet moley\ndelete table inet moley\n")
	case "persistent":
		_ = nft(killSwitchRules("", -1))
	}
}

// RestoreKillSwitch loads the persistent block at boot if it is on. It
// runs before the network comes up (moley-killswitch.service).
func RestoreKillSwitch() (bool, error) {
	if _, err := os.Stat(persistentMarker()); err != nil {
		return false, nil
	}
	return true, nft(killSwitchRules("", -1))
}

// killSwitchRules renders the table. Without an interface and uid it is
// the block that holds while the daemon is stopped.
func killSwitchRules(iface string, uid int) string {
	var b strings.Builder
	b.WriteString("table inet moley\ndelete table inet moley\ntable inet moley {\n")
	b.WriteString("  chain output {\n    type filter hook output priority filter; policy drop;\n")
	b.WriteString("    oifname \"lo\" accept\n")
	if iface != "" {
		fmt.Fprintf(&b, "    oifname %q accept\n", iface)
	}
	if uid >= 0 {
		fmt.Fprintf(&b, "    meta skuid %d accept\n", uid) // the daemon's sockets carry the tunnels
	}
	// The local network stays reachable (the router, printers); Moley
	// routes private addresses direct too.
	b.WriteString("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n")
	b.WriteString("    ip6 daddr { fc00::/7, fe80::/10 } accept\n")
	b.WriteString("    udp sport 68 udp dport 67 accept\n")
	b.WriteString("    udp sport 546 udp dport 547 accept\n")
	b.WriteString("    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
	b.WriteString("  }\n}\n")
	return b.String()
}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kill switch: nft: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func persistentMarker() string { return filepath.Join(SystemDataDir(), "killswitch-persistent") }
