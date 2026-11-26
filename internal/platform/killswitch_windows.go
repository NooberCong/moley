package platform

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"moley/internal/platform/wfp"
)

// CanRouteSystem says whether this process may create the TUN interface
// and the kill switch's firewall filters: it must run elevated (the
// service runs as LocalSystem).
func CanRouteSystem() error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return errors.New("system mode needs the Moley service: run `moley service install` as administrator")
}

var killSwitch struct {
	sync.Mutex
	session *wfp.Session
}

// SetKillSwitch makes the firewall block traffic that doesn't leave
// through Moley: everything but this process, loopback, DHCP and iface.
// "on" holds while the daemon runs; "persistent" also while it is
// stopped and across reboots. Call it again after iface is recreated.
func SetKillSwitch(mode, iface string) error {
	killSwitch.Lock()
	defer killSwitch.Unlock()
	if mode == "off" {
		killSwitch.session.Close()
		killSwitch.session = nil
		return wfp.RemovePersistent()
	}
	luid, err := interfaceLUID(iface)
	if err != nil {
		return err
	}
	persistent := mode == "persistent"
	if persistent {
		if err := wfp.EnsurePersistent(); err != nil {
			return fmt.Errorf("kill switch: %w", err)
		}
	}
	// The new filters go in before the old ones go, so nothing slips out.
	next, err := wfp.Enable(luid, persistent)
	if err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	killSwitch.session.Close()
	killSwitch.session = next
	if !persistent {
		return wfp.RemovePersistent()
	}
	return nil
}

// ReleaseKillSwitch is for a daemon that is stopping: the "on" block
// lifts, a persistent one stays.
func ReleaseKillSwitch() {
	killSwitch.Lock()
	defer killSwitch.Unlock()
	killSwitch.session.Close()
	killSwitch.session = nil
}

var procConvertInterfaceAliasToLuid = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceAliasToLuid")

func interfaceLUID(alias string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, err
	}
	var luid uint64
	if r, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&luid))); r != 0 {
		return 0, fmt.Errorf("kill switch: no interface %q: %w", alias, windows.Errno(r))
	}
	return luid, nil
}

// RestoreKillSwitch does nothing on Windows: the firewall keeps the
// persistent block across reboots itself.
func RestoreKillSwitch() (bool, error) { return false, nil }
