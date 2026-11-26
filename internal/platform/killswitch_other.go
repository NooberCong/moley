//go:build !windows && !linux

package platform

import "errors"

func CanRouteSystem() error {
	return errors.New("system mode is not supported on this OS yet")
}

func SetKillSwitch(mode, iface string) error {
	if mode == "off" {
		return nil
	}
	return CanRouteSystem()
}

func ReleaseKillSwitch() {}

func RestoreKillSwitch() (bool, error) { return false, nil }
