//go:build unix

package platform

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SystemSocket is the service's control socket; members of the moley
// group may use it.
const SystemSocket = "/run/moley/moley.sock"

// PipePath is the control socket: the service's when it runs, else the
// per-user daemon's. Override with MOLEY_PIPE (tests).
func PipePath() string {
	if p := os.Getenv("MOLEY_PIPE"); p != "" {
		return p
	}
	if _, err := os.Stat(SystemSocket); system || err == nil {
		return SystemSocket
	}
	return UserPipePath()
}

func UserPipePath() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "moley.sock")
	}
	// A private directory, so another user can't pre-create the socket.
	return filepath.Join(os.TempDir(), "moley-"+strconv.Itoa(os.Getuid()), "moley.sock")
}

// Listen opens the control socket, usable only by the current user (the
// service's: also by its group, moley).
func Listen() (net.Listener, error) {
	path := PipePath()
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, errors.New("another moley daemon is listening on " + path)
	}
	dirMode, mask := os.FileMode(0o700), 0o077
	if system {
		dirMode, mask = 0o750, 0o007
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, err
	}
	if err := ownedBy(filepath.Dir(path), os.Getuid()); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	ln, err := net.Listen("unix", path)
	if err == nil && system {
		err = os.Chmod(path, 0o660)
	}
	return ln, err
}

// Dial connects to the daemon's socket after checking who owns it: this
// user, or for the service's socket root or the moley user.
func Dial(ctx context.Context) (net.Conn, error) {
	path := PipePath()
	owners := []int{os.Getuid()}
	if path == SystemSocket {
		owners = append(owners, 0)
		if u, err := user.Lookup("moley"); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil {
				owners = append(owners, uid)
			}
		}
	}
	if err := ownedBy(path, owners...); err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

func ownedBy(path string, uids ...int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && !slices.Contains(uids, int(st.Uid)) {
		return errors.New(path + " belongs to another user; refusing to use it")
	}
	return nil
}

func Peer(c net.Conn) Caller {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Caller{}
	}
	pid := peerPID(uc)
	if pid <= 0 {
		return Caller{}
	}
	cl := Caller{PID: pid, Exe: procName(pid)}
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// pid (comm) state ppid ...
		if i := strings.LastIndexByte(string(stat), ')'); i > 0 {
			if f := strings.Fields(string(stat[i+1:])); len(f) > 1 {
				if ppid, err := strconv.Atoi(f[1]); err == nil {
					cl.Parent = procName(ppid)
				}
			}
		}
	}
	return cl
}

func procName(pid int) string {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return filepath.Base(exe)
}

// DataDir is where the daemon keeps its state: ~/.config/moley per user,
// /var/lib/moley for the service.
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
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "moley"), nil
}

// SystemDataDir is the service's state (systemd's StateDirectory=moley).
func SystemDataDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return d
	}
	return "/var/lib/moley"
}

func PrepareDataDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// ServerPID is the process serving a control connection.
func ServerPID(c net.Conn) int {
	if uc, ok := c.(*net.UnixConn); ok {
		return peerPID(uc)
	}
	return 0
}

// EndProcess waits up to grace for pid to exit, then kills it.
func EndProcess(pid int, grace time.Duration) error {
	for deadline := time.Now().Add(grace); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
