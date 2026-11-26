// Package platform holds the OS-specific pieces: the control channel
// (named pipe or Unix socket), who is on the other end of it, data
// directories, and browser native-messaging registration.
package platform

import (
	"errors"
	"fmt"
	"os"
)

// system is set when this process is the privileged service rather than
// a per-user daemon: state lives machine-wide and the control channel
// admits the allowed users and administrators.
var (
	system  bool
	allowed []string // Windows: user SIDs admitted to the pipe
)

// SetSystem switches this process to service mode. allow lists the
// Windows users (SIDs) who may control it; on Linux, members of the
// moley group may.
func SetSystem(allow []string) { system, allowed = true, allow }

// System reports whether this process runs as the service.
func System() bool { return system }

// NewSealer returns the sealer for this process's state.
func NewSealer() Sealer { return Sealer{Machine: system} }

// Caller identifies the process on the other end of a control connection,
// for the audit log. Parent is the process that started it (e.g. the
// shell or agent that ran the CLI).
type Caller struct {
	PID    int    `json:"pid"`
	Exe    string `json:"exe"`
	Parent string `json:"parent,omitempty"`
}

func (c Caller) String() string {
	if c.Exe == "" {
		return fmt.Sprintf("pid %d", c.PID)
	}
	if c.Parent != "" {
		return c.Parent + " → " + c.Exe
	}
	return c.Exe
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
