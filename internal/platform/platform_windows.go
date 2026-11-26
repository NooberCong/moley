package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// PipePath is the control channel. Override with MOLEY_PIPE (tests).
func PipePath() string {
	if p := os.Getenv("MOLEY_PIPE"); p != "" {
		return p
	}
	return `\\.\pipe\moley`
}

// Listen opens the control pipe. Only the current user and SYSTEM can open
// it, so other users on the machine can't drive the daemon. The service
// admits SYSTEM, administrators and the users it was installed for.
func Listen() (net.Listener, error) {
	sddl := "D:P(A;;GA;;;SY)"
	if system {
		sddl += "(A;;GA;;;BA)"
		for _, sid := range allowed {
			sddl += "(A;;GA;;;" + sid + ")"
		}
	} else {
		sid, err := currentUserSID()
		if err != nil {
			return nil, err
		}
		sddl += "(A;;GA;;;" + sid + ")"
	}
	return winio.ListenPipe(PipePath(), &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
}

// Dial connects to the daemon and checks the pipe's server runs as this
// user (or SYSTEM): another user who grabbed the name first must not
// receive profiles or secrets.
func Dial(ctx context.Context) (net.Conn, error) {
	c, err := winio.DialPipeContext(ctx, PipePath())
	if err != nil {
		return nil, err
	}
	if err := checkServer(c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// checkServer reads who created the pipe (its owner): this user, SYSTEM
// for the service, or Administrators for a daemon started elevated. Unlike the server process's token, the owner is
// readable through the client's own handle, also for a SYSTEM server.
func checkServer(c net.Conn) error {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("control pipe: can't identify the server")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("control pipe: owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("control pipe: owner: %w", err)
	}
	me, err := currentUserSID()
	if err != nil {
		return err
	}
	if sid := owner.String(); sid != me && sid != "S-1-5-18" && sid != "S-1-5-32-544" {
		return fmt.Errorf("control pipe is served by another user (%s); refusing to talk to it", sid)
	}
	return nil
}

var procGetNamedPipeServerProcessId = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeServerProcessId")

// ServerPID is the process serving a control connection.
func ServerPID(c net.Conn) int {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0
	}
	var pid uint32
	if r, _, _ := procGetNamedPipeServerProcessId.Call(f.Fd(), uintptr(unsafe.Pointer(&pid))); r == 0 {
		return 0
	}
	return int(pid)
}

// EndProcess waits up to grace for pid to exit, then terminates it.
func EndProcess(pid int, grace time.Duration) error {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return nil // already gone
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, uint32(grace.Milliseconds())); ev == windows.WAIT_OBJECT_0 {
		return nil
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	_, _ = windows.WaitForSingleObject(h, 5000)
	return nil
}

// Peer looks up the client process of a pipe connection.
func Peer(c net.Conn) Caller {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return Caller{}
	}
	var pid uint32
	if err := getNamedPipeClientProcessID(windows.Handle(f.Fd()), &pid); err != nil {
		return Caller{}
	}
	return describe(int(pid))
}

var procGetNamedPipeClientProcessId = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientProcessId")

func getNamedPipeClientProcessID(h windows.Handle, pid *uint32) error {
	r, _, err := procGetNamedPipeClientProcessId.Call(uintptr(h), uintptr(unsafe.Pointer(pid)))
	if r == 0 {
		return err
	}
	return nil
}

// describe names a process and its parent from one process snapshot.
func describe(pid int) Caller {
	c := Caller{PID: pid}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return c
	}
	defer windows.CloseHandle(snap)
	type proc struct {
		ppid uint32
		exe  string
	}
	procs := map[uint32]proc{}
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		procs[e.ProcessID] = proc{e.ParentProcessID, windows.UTF16ToString(e.ExeFile[:])}
	}
	me, ok := procs[uint32(pid)]
	if !ok {
		return c
	}
	c.Exe = me.exe
	// Skip shell wrappers (browsers start native hosts through cmd.exe) so
	// the audit log names the program that actually asked.
	parent, ok := procs[me.ppid]
	for hops := 0; ok && hops < 3 && strings.EqualFold(parent.exe, "cmd.exe"); hops++ {
		parent, ok = procs[parent.ppid]
	}
	if ok {
		c.Parent = parent.exe
	}
	return c
}

func currentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// DataDir is where the daemon keeps its state: %LocalAppData%\Moley per
// user, %ProgramData%\Moley for the service.
func DataDir() (string, error) {
	if d := os.Getenv("MOLEY_HOME"); d != "" {
		return d, nil
	}
	if system {
		return SystemDataDir(), nil
	}
	return UserDataDir()
}

func UserDataDir() (string, error) {
	base, err := os.UserCacheDir() // %LocalAppData%
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Moley"), nil
}

func SystemDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Moley")
}

// PrepareDataDir creates dir. The service's directory admits only SYSTEM
// and administrators: profile secrets in it are sealed to the machine.
func PrepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if !system {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
