package platform

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// ServiceName is the systemd unit name (and the Windows service name).
const ServiceName = "moley"

var (
	//go:embed systemd/moley.service
	unitService string
	//go:embed systemd/moley-killswitch.service
	unitKillSwitch string
)

// Units renders the systemd units for exe (packages ship them too).
func Units(exe string) map[string]string {
	return map[string]string{
		"moley.service":            strings.ReplaceAll(unitService, "@EXE@", exe),
		"moley-killswitch.service": strings.ReplaceAll(unitKillSwitch, "@EXE@", exe),
	}
}

// RunService reports false: systemd runs the service in the foreground
// and stops it with SIGTERM, which the caller already handles.
func RunService(func(context.Context) error) (bool, error) { return false, nil }

// InstallService sets up the system service: the moley user and group,
// the units (unless a package installed them) and starts it. The users in
// allow join the moley group, which may use the control socket.
func InstallService(exe string, allow []string) error {
	if os.Geteuid() != 0 {
		return errors.New("run it with sudo")
	}
	if uid := firstEnv("SUDO_UID", "PKEXEC_UID"); uid != "" {
		if c, err := net.Dial("unix", "/run/user/"+uid+"/moley.sock"); err == nil {
			c.Close()
			return errors.New("your own Moley daemon is running and holds the proxy port: run `moley stop` first")
		}
	}
	if err := run("getent", "group", "moley"); err != nil {
		if err := run("groupadd", "--system", "moley"); err != nil {
			return err
		}
	}
	if err := run("getent", "passwd", "moley"); err != nil {
		if err := run("useradd", "--system", "--gid", "moley", "--home-dir", SystemDataDir(), "--no-create-home",
			"--shell", "/usr/sbin/nologin", "moley"); err != nil {
			return err
		}
	}
	for _, u := range allow {
		if err := run("usermod", "--append", "--groups", "moley", u); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(SystemDataDir(), 0o700); err != nil {
		return err
	}
	if err := run("chown", "-R", "moley:moley", SystemDataDir()); err != nil {
		return err
	}
	if _, err := os.Stat("/usr/lib/systemd/system/moley.service"); err != nil {
		for name, unit := range Units(exe) {
			if err := os.WriteFile(filepath.Join("/etc/systemd/system", name), []byte(unit), 0o644); err != nil {
				return err
			}
		}
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "moley-killswitch.service"); err != nil {
		return err
	}
	return run("systemctl", "enable", "--now", "moley.service")
}

// UninstallService stops and removes the service and lifts a persistent
// kill switch.
func UninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("run it with sudo")
	}
	_ = run("systemctl", "disable", "--now", "moley.service", "moley-killswitch.service")
	for name := range Units("") {
		_ = removeIfExists(filepath.Join("/etc/systemd/system", name))
	}
	_ = run("systemctl", "daemon-reload")
	return SetKillSwitch("off", "")
}

// ServiceInstalled reports whether the moley unit is known to systemd.
func ServiceInstalled() bool {
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		if _, err := os.Stat(filepath.Join(dir, "moley.service")); err == nil {
			return true
		}
	}
	return false
}

// StartService asks systemd to start the service.
func StartService() error { return run("systemctl", "start", "moley.service") }

// CurrentUser names the user who ran this through sudo or pkexec (the
// tray app), for InstallService's allow list.
func CurrentUser() (string, error) {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u, nil
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" {
		u, err := user.LookupId(uid)
		if err != nil {
			return "", err
		}
		return u.Username, nil
	}
	return "", errors.New("can't tell who to admit: run it with sudo from your own account")
}

// InstallerUserDataDir is the per-user state of whoever ran sudo.
func InstallerUserDataDir() (string, error) {
	name, err := CurrentUser()
	if err != nil {
		return UserDataDir()
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, ".config", "moley"), nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
