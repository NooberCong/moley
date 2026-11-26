package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// hideConsole keeps a console window from flashing for moley.exe.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// shellExecuteInfo is SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	size          uint32
	mask          uint32
	hwnd          windows.Handle
	verb          *uint16
	file          *uint16
	parameters    *uint16
	directory     *uint16
	show          int32
	instApp       windows.Handle
	idList        uintptr
	class         *uint16
	keyClass      windows.Handle
	hotKey        uint32
	iconOrMonitor windows.Handle
	process       windows.Handle
}

var procShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// errCancelled: the user said no to the elevation prompt.
var errCancelled = errors.New("cancelled")

// elevate runs exe with args as administrator (the UAC prompt) and waits
// for it to finish.
func elevate(exe string, args ...string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	info := shellExecuteInfo{
		mask:       0x40 | 0x400, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		verb:       verb,
		file:       file,
		parameters: params,
		show:       windows.SW_HIDE,
	}
	info.size = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errCancelled
		}
		return err
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s %s failed (exit %d)", exe, strings.Join(args, " "), code)
	}
	return nil
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func autostartCommand() string {
	exe, _ := os.Executable()
	return windows.EscapeArg(exe) + " --hidden"
}

func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Moley")
	return err == nil && v == autostartCommand()
}

func setAutostart(on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if on {
		return k.SetStringValue("Moley", autostartCommand())
	}
	if err := k.DeleteValue("Moley"); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// runInstaller starts a downloaded installer silently, as administrator,
// without waiting: it closes this app, updates everything and starts the
// new tray.
func runInstaller(path string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(path)
	params, _ := windows.UTF16PtrFromString("/S /launch")
	info := shellExecuteInfo{mask: 0x400, verb: verb, file: file, parameters: params, show: windows.SW_SHOWNORMAL}
	info.size = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errCancelled
		}
		return err
	}
	return nil
}

// trayIconSize is the notification area's icon size at the display's
// scale, so the mark is drawn for it rather than scaled.
func trayIconSize() int {
	const smCxSmIcon = 49
	n, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("GetSystemMetrics").Call(smCxSmIcon)
	if n < 16 {
		return 32
	}
	return int(n)
}

// ensureToastIcon writes the mark where Windows looks for Moley's
// notification icon. The notifications service registers that path but
// fills it from an icon resource id the build doesn't use, so without this
// the toast shows no icon. A temp-folder cleanup may remove it, so it is
// checked before each notification.
func ensureToastIcon() {
	k, err := registry.OpenKey(registry.CURRENT_USER, notifications.ToastRegistryPath+"Moley", registry.QUERY_VALUE)
	if err != nil {
		return
	}
	path, _, err := k.GetStringValue("IconUri")
	k.Close()
	if err != nil || path == "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		return
	}
	_ = os.WriteFile(path, drawIcon(256, markTunnel), 0o644)
}
