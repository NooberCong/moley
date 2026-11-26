package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func hideConsole(*exec.Cmd) {}

var errCancelled = errors.New("cancelled")

// elevate runs exe with args as root through polkit (pkexec), which asks
// for the password in a desktop dialog.
func elevate(exe string, args ...string) error {
	out, err := exec.Command("pkexec", append([]string{exe}, args...)...).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) && (ee.ExitCode() == 126 || ee.ExitCode() == 127) {
		return errCancelled // dismissed, or not authorized
	}
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func autostartFile() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "autostart", "moley.desktop")
}

func autostartEntry() string {
	exe, _ := os.Executable()
	if appimage := os.Getenv("APPIMAGE"); appimage != "" {
		exe = appimage // the AppImage, not its mount point
	}
	return "[Desktop Entry]\nType=Application\nName=Moley\nExec=\"" + exe + "\" --hidden\nIcon=moley\nX-GNOME-Autostart-enabled=true\n"
}

func autostartEnabled() bool {
	b, err := os.ReadFile(autostartFile())
	return err == nil && string(b) == autostartEntry()
}

func setAutostart(on bool) error {
	if !on {
		if err := os.Remove(autostartFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(autostartFile()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(autostartFile(), []byte(autostartEntry()), 0o644)
}

func runInstaller(string) error { return errors.New("installers are for Windows") }

// trayIconSize is the size the tray icon is drawn at; desktops scale it.
func trayIconSize() int { return 32 }

// ensureToastIcon is for Windows; desktop notifications use the app's icon.
func ensureToastIcon() {}
