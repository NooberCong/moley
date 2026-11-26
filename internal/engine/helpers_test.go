package engine_test

import (
	"encoding/base64"
	"net"
	"slices"
	"strconv"
	"testing"
)

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	if testing.Verbose() {
		w.t.Log(string(b))
	}
	return len(b), nil
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	// The engine needs port and port+1 (hint inbound).
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if l2, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p+1)); err == nil {
			l2.Close()
			return uint16(p)
		}
	}
	t.Fatal("no free port pair")
	return 0
}

func portOf(addr string) string { _, p, _ := net.SplitHostPort(addr); return p }
func itoa(i int) string         { return strconv.Itoa(i) }
func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}
func basic(u, p string) string { return base64.StdEncoding.EncodeToString([]byte(u + ":" + p)) }
