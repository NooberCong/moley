package rpc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"moley/internal/rpc"
)

// TestSubscribe streams events for one request while calls on another
// connection keep working, and stops when the client goes away.
func TestSubscribe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan struct{})
	h := func(ctx context.Context, _ any, method string, _ json.RawMessage) (any, error) {
		switch method {
		case "count":
			defer close(ended)
			for i := 0; ; i++ {
				if err := rpc.Emit(ctx, "n", i); err != nil {
					return nil, err
				}
				select {
				case <-ctx.Done():
					return nil, nil
				case <-time.After(5 * time.Millisecond):
				}
			}
		case "ping":
			return "pong", nil
		}
		return nil, rpc.Errorf(rpc.CodeUnknownMethod, "", "no")
	}
	dial := func() *rpc.Client {
		a, b := net.Pipe()
		go rpc.Serve(ctx, b, nil, h)
		return rpc.NewClient(a)
	}
	sub, calls := dial(), dial()
	sctx, stop := context.WithCancel(ctx)
	var got []int
	err := sub.Subscribe(sctx, "count", nil, func(event string, data json.RawMessage) error {
		var n int
		if event != "n" || json.Unmarshal(data, &n) != nil {
			t.Errorf("event %q %s", event, data)
		}
		got = append(got, n)
		if len(got) == 3 {
			var pong string
			if err := calls.Call(ctx, "ping", nil, &pong); err != nil || pong != "pong" {
				t.Errorf("call during a subscription: %q %v", pong, err)
			}
			stop()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("subscribe ended with %v", err)
	}
	if len(got) != 3 || got[0] != 0 || got[2] != 2 {
		t.Fatalf("events %v", got)
	}
	sub.Close()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream kept running after the client left")
	}
}
