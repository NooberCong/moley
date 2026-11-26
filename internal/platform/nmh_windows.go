package platform

import (
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// browserKeys are the per-user registry roots Chromium browsers read
// native messaging hosts from.
var browserKeys = map[string]string{
	"Chrome":   `Software\Google\Chrome\NativeMessagingHosts\`,
	"Edge":     `Software\Microsoft\Edge\NativeMessagingHosts\`,
	"Brave":    `Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\`,
	"Chromium": `Software\Chromium\NativeMessagingHosts\`,
}

// InstallNativeHost writes the host manifest and registers it for every
// Chromium browser for the current user.
func InstallNativeHost(exe string, origins []string) ([]string, error) {
	dir, err := UserDataDir()
	if err != nil {
		return nil, err
	}
	manifest := filepath.Join(dir, NativeHostName+".json")
	if err := writeManifest(manifest, exe, origins); err != nil {
		return nil, err
	}
	var done []string
	for name, key := range browserKeys {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, key+NativeHostName, registry.SET_VALUE)
		if err != nil {
			return done, err
		}
		err = k.SetStringValue("", manifest)
		k.Close()
		if err != nil {
			return done, err
		}
		done = append(done, name)
	}
	return done, nil
}

// Detach makes cmd outlive the CLI process and its console.
func Detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
}

// UninstallNativeHost removes the registrations and the manifest.
func UninstallNativeHost() error {
	for _, key := range browserKeys {
		if err := registry.DeleteKey(registry.CURRENT_USER, key+NativeHostName); err != nil && err != registry.ErrNotExist {
			return err
		}
	}
	dir, err := UserDataDir()
	if err != nil {
		return err
	}
	return removeIfExists(filepath.Join(dir, NativeHostName+".json"))
}
