package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"moley/internal/engine"
	"moley/internal/platform"
	"moley/internal/rpc"
)

// TestEvents subscribes the way the tray app does and checks a config
// change arrives as a status event, without waiting for the next tick.
func TestEvents(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"default_exit":"direct","settings":{"proxy_port":` + strconv.Itoa(freePort(t)) + `}}`
	if err := os.WriteFile(filepath.Join(dir, "moley.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir, engine.NewLogs(io.Discard, false))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dial := func() *rpc.Client {
		a, b := net.Pipe()
		go rpc.Serve(ctx, b, platform.Caller{Exe: "test"}, d.handle)
		return rpc.NewClient(a)
	}
	sub, calls := dial(), dial()
	defer sub.Close()

	sctx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	var first time.Time
	var statuses []StatusResult
	err = sub.Subscribe(sctx, "events.subscribe", SubscribeParams{Conns: true}, func(event string, data json.RawMessage) error {
		if event != EventStatus {
			return nil
		}
		var st StatusResult
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		statuses = append(statuses, st)
		if len(statuses) == 1 {
			first = time.Now()
			if st.Mode.Service || st.Mode.KillSwitch != "off" {
				t.Errorf("mode: %+v", st.Mode)
			}
			go func() {
				if err := calls.Call(ctx, "default.set", ExitParams{Exit: "block"}, nil); err != nil {
					t.Error(err)
				}
			}()
			return nil
		}
		stop()
		return nil
	})
	if err != nil && sctx.Err() == context.DeadlineExceeded {
		t.Fatalf("no status event after the change: %v", err)
	}
	if len(statuses) != 2 || statuses[1].DefaultExit != "block" {
		t.Fatalf("statuses %+v", statuses)
	}
	if waited := time.Since(first); waited > 900*time.Millisecond {
		t.Errorf("the change took %v to arrive; it should not wait for the tick", waited)
	}

	// The per-user daemon refuses system mode with a pointer to the service.
	if platform.CanRouteSystem() != nil {
		on := true
		err := calls.Call(ctx, "mode.set", ModeParams{TUN: &on}, nil)
		if re, ok := err.(*rpc.Error); !ok || re.Code != CodeNeedsService {
			t.Errorf("mode.set tun as a user: %v", err)
		}
	}
}

func freePort(t *testing.T) int {
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if l2, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p+1)); err == nil {
			l2.Close()
			return p
		}
	}
	t.Fatal("no free port pair")
	return 0
}
