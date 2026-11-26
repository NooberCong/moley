// Command teststack runs the loopback VPN test servers for manual and
// browser testing, and writes client profiles into a directory:
//
//	go run ./internal/teststack/cmd/teststack <dir>
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"

	"moley/internal/teststack"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: teststack <dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	s, err := teststack.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer s.Close()
	for name, content := range map[string]string{
		"work.ovpn": s.OVPN, "wg.conf": s.WG, "awg.conf": s.AWG, "ss.txt": s.SSLink,
		"urls.txt": fmt.Sprintf("trace %s\npublic %s\nhealth %s\nintranet http://%s:%s/\n",
			s.TraceURL(), s.PublicTraceURL(), s.HealthURL(), teststack.IntranetHost, port(s.EchoAddr)),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Println("teststack up; profiles in", dir)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}
