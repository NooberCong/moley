//go:build unix

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

var browserDirs = map[string]string{
	"Chrome":   "google-chrome",
	"Chromium": "chromium",
	"Brave":    "BraveSoftware/Brave-Browser",
	"Edge":     "microsoft-edge",
}

// InstallNativeHost writes the host manifest into each Chromium browser's
// per-user NativeMessagingHosts directory.
func InstallNativeHost(exe string, origins []string) ([]string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	var done []string
	for name, dir := range browserDirs {
		path := filepath.Join(base, dir, "NativeMessagingHosts", NativeHostName+".json")
		if err := writeManifest(path, exe, origins); err != nil {
			return done, err
		}
		done = append(done, name)
	}
	return done, nil
}

// Detach makes cmd outlive the CLI process and its terminal.
func Detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// UninstallNativeHost removes the manifests.
func UninstallNativeHost() error {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	for _, dir := range browserDirs {
		if err := removeIfExists(filepath.Join(base, dir, "NativeMessagingHosts", NativeHostName+".json")); err != nil {
			return err
		}
	}
	return nil
}
