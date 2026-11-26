package main

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// vpn is the tunnel everything without a rule goes through, and how it is
// doing: the part of the status the notifications follow.
type vpn struct {
	exit string // "" when traffic goes direct or is blocked, or Moley isn't running
	name string // exit as shown
	up   bool
	lost bool // it was up and dropped; it is reconnecting
}

func vpnOf(st status, offline bool) vpn {
	if offline || st.DefaultExit == "" || st.DefaultExit == "direct" || st.DefaultExit == "block" {
		return vpn{}
	}
	v := vpn{exit: st.DefaultExit, name: st.name(st.DefaultExit), up: true} // a group is up while Moley runs
	for _, p := range st.Profiles {
		if p.ID == st.DefaultExit {
			v.up = p.State == "connected" || p.State == "ready"
		}
	}
	return v
}

// vpnChange says what changed between two states, as a notification, and
// returns next with whether it is reconnecting after a drop.
func vpnChange(prev, next vpn, offline bool) (vpn, string, string) {
	switch {
	case prev.exit != "" && next.exit == "":
		if offline {
			return next, "Disconnected", "Moley stopped."
		}
		return next, "Disconnected", "Disconnected from " + prev.name + "."
	case next.exit == "":
		return next, "", ""
	case next.exit != prev.exit:
		if next.up {
			return next, "Connected", "Connected to " + next.name + "."
		}
		return next, "", ""
	case prev.up && !next.up:
		next.lost = true
		return next, "Connection lost", "Reconnecting to " + next.name + "…"
	case !prev.up && next.up:
		if prev.lost {
			return next, "Reconnected", "Reconnected to " + next.name + "."
		}
		return next, "Connected", "Connected to " + next.name + "."
	}
	next.lost = prev.lost && !next.up
	return next, "", ""
}

// followVPN notifies about a change of the VPN in use; the first status
// after the tray starts only sets where it stands.
func (u *ui) followVPN(st status, offline bool) {
	u.mu.Lock()
	prev, known := u.vpn, u.vpnKnown
	next, title, body := vpnChange(prev, vpnOf(st, offline), offline)
	u.vpn, u.vpnKnown = next, true
	u.mu.Unlock()
	if known && title != "" {
		u.notify(title, body)
	}
}

var notified atomic.Int64

// notify shows a notification from the system: a toast on Windows, the
// desktop's notifications on Linux.
func (u *ui) notify(title, body string) {
	ensureToastIcon()
	id := "moley-" + strconv.FormatInt(notified.Add(1), 10)
	if err := u.notifier.SendNotification(notifications.NotificationOptions{ID: id, Title: title, Body: body}); err != nil {
		u.tray.SetTooltip(fmt.Sprintf("Moley · %s", body))
	}
}
