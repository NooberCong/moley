package daemon

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"

	"moley/internal/platform"
	"moley/internal/rpc"
)

// Holds keep the network adapter up for a while without changing where
// anything goes. It is what a client (an agent, say) needs to reach a work
// VPN's networks from programs that ignore proxy settings (psql, ssh) while
// you're disconnected: the rules already send those networks through the
// VPN, but only the browser and `moley exec` follow them while the adapter
// is down (see model.Config.SystemRouting).
//
// Holds are runtime state: never saved, gone when the daemon restarts. Each
// lapses on its own, so a client that crashes can't leave the adapter up,
// and each has a name, so clients holding at once never undo each other.

const (
	DefaultHoldTTL = 30 * time.Minute
	MaxHoldTTL     = 24 * time.Hour
)

type Hold struct {
	Name   string    `json:"name"`
	Until  time.Time `json:"until"`
	Caller string    `json:"caller"`
}

type HoldParams struct {
	Name  string `json:"name"`
	TTLMS int64  `json:"ttl_ms,omitempty"` // default 30 min, at most 24 h; putting it again renews it
}

type ReleaseParams struct {
	Name string `json:"name"`
}

type HoldResult struct {
	Hold    *Hold `json:"hold,omitempty"`    // the hold put
	Removed bool  `json:"removed,omitempty"` // a release found the hold
	// SystemRouting: the adapter is up now. A hold doesn't bring it up while
	// system mode is off.
	SystemRouting bool `json:"system_routing"`
	Rebuilt       bool `json:"rebuilt"`
}

func putHold(_ context.Context, d *Daemon, c platform.Caller, p HoldParams) (any, error) {
	name, err := holdName(p.Name)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(p.TTLMS) * time.Millisecond
	if p.TTLMS == 0 {
		ttl = DefaultHoldTTL
	}
	if ttl < time.Second || ttl > MaxHoldTTL {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "", "a hold lasts from 1s to %s, not %s", MaxHoldTTL, ttl)
	}
	h := Hold{Name: name, Until: time.Now().Add(ttl).UTC(), Caller: c.String()}
	res, err := d.changeHolds(func(holds map[string]Hold) { holds[name] = h })
	if err != nil {
		return nil, err
	}
	res.Hold = &h
	d.audit(AuditEntry{Method: "holds.put", Caller: h.Caller, Rebuilt: res.Rebuilt,
		Summary: fmt.Sprintf("hold system routing as %q for %s", name, ttl.Round(time.Second))})
	return res, nil
}

func releaseHold(_ context.Context, d *Daemon, c platform.Caller, p ReleaseParams) (any, error) {
	name, err := holdName(p.Name)
	if err != nil {
		return nil, err
	}
	// Releasing a hold that's gone (it lapsed, say) is not an error: either
	// way the caller ends up holding nothing, which is what it asked for.
	var found bool
	res, err := d.changeHolds(func(holds map[string]Hold) {
		_, found = holds[name]
		delete(holds, name)
	})
	if err != nil {
		return nil, err
	}
	res.Removed = found
	if found {
		d.audit(AuditEntry{Method: "holds.release", Caller: c.String(), Rebuilt: res.Rebuilt,
			Summary: fmt.Sprintf("release the hold %q", name)})
	}
	return res, nil
}

func holdName(s string) (string, error) {
	name := strings.TrimSpace(s)
	if name == "" || len(name) > 64 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", rpc.Errorf(rpc.CodeInvalidParams, "", "a hold needs a name of 1 to 64 printable characters, e.g. the agent holding it")
	}
	return name, nil
}

// changeHolds runs fn on the holds and brings the adapter in line. If the
// engine can't follow, the holds go back as they were.
func (d *Daemon) changeHolds(fn func(map[string]Hold)) (HoldResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	prev := maps.Clone(d.holds)
	fn(d.holds)
	lapsed := d.pruneHolds(time.Now())
	res, err := d.engine.SetHeld(len(d.holds) > 0)
	if err != nil {
		d.holds = prev
		return HoldResult{}, rpc.Errorf(rpc.CodeInvalidParams, "see `moley logs`", "the engine couldn't follow: %v", err)
	}
	d.auditLapsed(lapsed, res.Rebuilt)
	d.scheduleHoldExpiry()
	d.notify()
	return HoldResult{SystemRouting: d.cfg.SystemRouting(len(d.holds) > 0), Rebuilt: res.Rebuilt}, nil
}

// pruneHolds drops the holds that lapsed by now and returns them. d.mu held.
func (d *Daemon) pruneHolds(now time.Time) []Hold {
	var lapsed []Hold
	for name, h := range d.holds {
		if !now.Before(h.Until) {
			lapsed = append(lapsed, h)
			delete(d.holds, name)
		}
	}
	return lapsed
}

// scheduleHoldExpiry arms the timer for the next hold to lapse. d.mu held.
func (d *Daemon) scheduleHoldExpiry() {
	if d.holdTimer != nil {
		d.holdTimer.Stop()
		d.holdTimer = nil
	}
	if len(d.holds) == 0 {
		return
	}
	next := slices.MinFunc(slices.Collect(maps.Values(d.holds)), func(a, b Hold) int { return a.Until.Compare(b.Until) })
	d.holdTimer = time.AfterFunc(time.Until(next.Until), d.expireHolds)
}

func (d *Daemon) expireHolds() {
	d.mu.Lock()
	defer d.mu.Unlock()
	lapsed := d.pruneHolds(time.Now())
	if len(lapsed) > 0 {
		res, err := d.engine.SetHeld(len(d.holds) > 0)
		if err != nil {
			// The adapter stays up; the next change to the holds tries again.
			d.logs.Error("drop the adapter after holds lapsed: " + err.Error())
		}
		d.auditLapsed(lapsed, res.Rebuilt)
		d.notify()
	}
	d.scheduleHoldExpiry()
}

func (d *Daemon) auditLapsed(lapsed []Hold, rebuilt bool) {
	for _, h := range lapsed {
		d.audit(AuditEntry{Method: "holds.lapse", Caller: "moley", Rebuilt: rebuilt,
			Summary: fmt.Sprintf("the hold %q lapsed", h.Name)})
	}
}

// activeHolds lists the holds in force, by name. d.mu held.
func (d *Daemon) activeHolds() []Hold {
	now := time.Now()
	out := make([]Hold, 0, len(d.holds))
	for _, h := range d.holds {
		if now.Before(h.Until) {
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b Hold) int { return strings.Compare(a.Name, b.Name) })
	return out
}
