//go:build unix && !linux

package platform

import "net"

// peerPID is not implemented outside Linux yet (macOS: LOCAL_PEERPID).
func peerPID(*net.UnixConn) int { return 0 }
