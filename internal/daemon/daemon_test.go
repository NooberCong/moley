package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
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

// TestHolds puts, renews and releases holds the way agents do, and checks
// that one lapses on its own and the audit log says so.
func TestHolds(t *testing.T) {
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
	ctx := context.Background()
	a, b := net.Pipe()
	go rpc.Serve(ctx, b, platform.Caller{Exe: "agent.exe"}, d.handle)
	calls := rpc.NewClient(a)
	defer calls.Close()

	put := func(name string, ttl time.Duration) (HoldResult, error) {
		var res HoldResult
		err := calls.Call(ctx, "holds.put", HoldParams{Name: name, TTLMS: ttl.Milliseconds()}, &res)
		return res, err
	}
	release := func(name string) HoldResult {
		var res HoldResult
		if err := calls.Call(ctx, "holds.release", ReleaseParams{Name: name}, &res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	holds := func() []string {
		var st StatusResult
		if err := calls.Call(ctx, "status", nil, &st); err != nil {
			t.Fatal(err)
		}
		if st.Mode.SystemRouting {
			t.Error("without system mode a hold must not report the adapter up")
		}
		var names []string
		for _, h := range st.Holds {
			names = append(names, h.Name)
		}
		return names
	}

	res, err := put("agent-a", 0)
	if err != nil || res.Hold == nil || res.SystemRouting || res.Removed {
		t.Fatalf("put: %+v %v", res, err)
	}
	if left := time.Until(res.Hold.Until); left < DefaultHoldTTL-time.Minute || left > DefaultHoldTTL {
		t.Errorf("default hold lasts %v", left)
	}
	if res.Hold.Caller == "" {
		t.Error("a hold should name who put it")
	}
	// Renewing replaces; a second name adds.
	if res, err := put("agent-a", time.Hour); err != nil || time.Until(res.Hold.Until) < 59*time.Minute {
		t.Fatalf("renew: %+v %v", res, err)
	}
	putB := time.Now()
	if _, err := put("agent-b", 1200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := holds(); len(got) != 2 || got[0] != "agent-a" || got[1] != "agent-b" {
		t.Fatalf("holds %v", got)
	}

	if !release("agent-a").Removed {
		t.Error("release of a held name should say it removed it")
	}
	if release("agent-a").Removed {
		t.Error("releasing again should be a no-op")
	}

	for _, bad := range []HoldParams{{Name: " "}, {Name: "x", TTLMS: 500}, {Name: "x", TTLMS: (25 * time.Hour).Milliseconds()}, {Name: "a\nb"}} {
		err := calls.Call(ctx, "holds.put", bad, nil)
		if re, ok := err.(*rpc.Error); !ok || re.Code != rpc.CodeInvalidParams {
			t.Errorf("holds.put %+v: %v", bad, err)
		}
	}

	// agent-b lapses on its own.
	deadline := time.Now().Add(5 * time.Second)
	for len(holds()) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("hold never lapsed: %v", holds())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lasted := time.Since(putB); lasted < 1200*time.Millisecond {
		t.Errorf("a 1.2s hold lapsed after %v", lasted)
	}
	var hist []AuditEntry
	if err := calls.Call(ctx, "history.list", LimitParams{}, &hist); err != nil {
		t.Fatal(err)
	}
	var methods []string
	for _, e := range hist {
		methods = append(methods, e.Method)
	}
	want := []string{"holds.put", "holds.put", "holds.put", "holds.release", "holds.lapse"}
	if !slices.Equal(methods, want) {
		t.Errorf("audit log %v, want %v", methods, want)
	}
}
