package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"time"

	"moley/internal/engine"
	"moley/internal/platform"
	"moley/internal/rpc"
)

// Events pushed by events.subscribe. Each is sent when it changes, checked
// once a second and right after any config change. Nothing is computed
// while no one is subscribed.
const (
	EventStatus  = "status"  // StatusResult
	EventTraffic = "traffic" // Traffic
	EventConns   = "conns"   // []engine.Conn, newest first (with conns: true)
)

// Traffic is throughput in bytes per second, in total and per exit.
type Traffic struct {
	Up    int64                   `json:"up"`
	Down  int64                   `json:"down"`
	Exits map[string]engine.Usage `json:"exits"` // exits that carried traffic
	Open  int                     `json:"open"`  // open connections
}

type SubscribeParams struct {
	Conns bool `json:"conns,omitempty"` // also stream open connections
}

const (
	eventTick     = time.Second
	maxEventConns = 200
)

func subscribe(ctx context.Context, d *Daemon, _ platform.Caller, p SubscribeParams) (any, error) {
	var last struct {
		status, traffic, conns []byte
		usage                  map[string]engine.Usage
		at                     time.Time
	}
	send := func(event string, v any, prev *[]byte) error {
		b, err := json.Marshal(v)
		if err != nil || bytes.Equal(b, *prev) {
			return err
		}
		*prev = b
		return rpc.Emit(ctx, event, json.RawMessage(b))
	}
	tick := time.NewTicker(eventTick)
	defer tick.Stop()
	for {
		changed := d.changes()
		st, _ := status(ctx, d, platform.Caller{}, none{})
		if err := send(EventStatus, st, &last.status); err != nil {
			return nil, err
		}
		usage, open := d.engine.Usage()
		now := time.Now()
		if last.usage != nil {
			t := Traffic{Exits: map[string]engine.Usage{}, Open: open}
			secs := now.Sub(last.at).Seconds()
			for id, u := range usage {
				was := last.usage[id]
				r := engine.Usage{Up: rate(u.Up-was.Up, secs), Down: rate(u.Down-was.Down, secs)}
				if r != (engine.Usage{}) {
					t.Exits[id] = r
					t.Up += r.Up
					t.Down += r.Down
				}
			}
			if err := send(EventTraffic, t, &last.traffic); err != nil {
				return nil, err
			}
		}
		last.usage, last.at = maps.Clone(usage), now
		if p.Conns {
			cs := d.engine.Conns("", false)
			if len(cs) > maxEventConns {
				cs = cs[:maxEventConns]
			}
			if err := send(EventConns, orEmpty(cs), &last.conns); err != nil {
				return nil, err
			}
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-tick.C:
		case <-changed:
		}
	}
}

// rate is bytes per second; counters restart with the engine, so a drop
// reads as idle rather than negative.
func rate(delta int64, secs float64) int64 {
	if delta <= 0 || secs <= 0 {
		return 0
	}
	return int64(float64(delta) / secs)
}

// changes returns a channel that is closed at the next config change.
func (d *Daemon) changes() <-chan struct{} {
	d.changeMu.Lock()
	defer d.changeMu.Unlock()
	return d.changed
}

func (d *Daemon) notify() {
	d.changeMu.Lock()
	defer d.changeMu.Unlock()
	close(d.changed)
	d.changed = make(chan struct{})
}
