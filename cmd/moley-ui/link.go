package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"moley/internal/platform"
	"moley/internal/rpc"
)

// link connects the UI to the daemon: an event stream that redials when
// the daemon comes back, and calls on short-lived connections (so a slow
// call never holds up another).
type link struct {
	onEvent func(event string, data json.RawMessage)
	onDown  func() // the daemon can't be reached; called once per outage

	mu      sync.Mutex
	conns   bool          // stream open connections too
	restart chan struct{} // closed to resubscribe (conns changed, or retry now)
}

func newLink(onEvent func(string, json.RawMessage), onDown func()) *link {
	return &link{onEvent: onEvent, onDown: onDown, restart: make(chan struct{})}
}

// watchConns turns the connection stream on or off (the Activity view).
func (l *link) watchConns(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns != on {
		l.conns = on
		l.kick()
	}
}

// retry ends a wait between redials, e.g. right after starting the daemon.
func (l *link) retry() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.kick()
}

func (l *link) kick() {
	close(l.restart)
	l.restart = make(chan struct{})
}

func (l *link) state() (bool, <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns, l.restart
}

// run keeps the stream open until ctx ends.
func (l *link) run(ctx context.Context) {
	up := true // so the first failure is reported
	for ctx.Err() == nil {
		conns, restart := l.state()
		err := l.subscribe(ctx, conns, restart, func() { up = true })
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRestart) {
			continue
		}
		if up {
			up = false
			l.onDown()
		}
		select {
		case <-ctx.Done():
		case <-restart:
		case <-time.After(2 * time.Second):
		}
	}
}

var errRestart = errors.New("resubscribe")

func (l *link) subscribe(ctx context.Context, conns bool, restart <-chan struct{}, connected func()) error {
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	conn, err := platform.Dial(dctx)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-restart:
			stop()
		case <-sctx.Done():
		}
	}()
	err = rpc.NewClient(conn).Subscribe(sctx, "events.subscribe", map[string]bool{"conns": conns}, func(event string, data json.RawMessage) error {
		connected()
		l.onEvent(event, data)
		return nil
	})
	select {
	case <-restart:
		return errRestart
	default:
	}
	if err == nil {
		err = errors.New("the daemon ended the stream")
	}
	return err
}

// call makes one RPC call on its own connection.
func call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	conn, err := platform.Dial(dctx)
	cancel()
	if err != nil {
		return nil, &rpc.Error{Code: "daemon_unreachable", Message: "Moley isn't running"}
	}
	c := rpc.NewClient(conn)
	defer c.Close()
	var out json.RawMessage
	err = c.Call(ctx, method, params, &out)
	return out, err
}
