package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// status is the part of the daemon's status the tray needs.
type status struct {
	DefaultExit string `json:"default_exit"`
	Exits       []string
	Profiles    []profileStatus `json:"profiles"`
	Mode struct {
		TUN        bool   `json:"tun"`
		KillSwitch string `json:"kill_switch"`
		Service    bool   `json:"service"`
		Error      string `json:"error"`
	} `json:"mode"`
}

// trayState is everything the tray shows; the tray is redrawn only when
// it changes.
type trayState struct {
	mark    mark
	tooltip string
	menu    string // the menu's content, as a comparable key
}

func (u *ui) refreshTray() {
	u.mu.Lock()
	offline := u.offline != "" || u.last["status"] == nil
	var st status
	_ = json.Unmarshal(u.last["status"], &st)
	u.mu.Unlock()
	u.followVPN(st, offline)

	next := trayState{mark: markOff, tooltip: "Moley isn't running"}
	if !offline {
		next.mark, next.tooltip = describe(st)
		key, _ := json.Marshal([]any{st.DefaultExit, st.Exits, st.Mode})
		next.menu = string(key)
	}
	u.mu.Lock()
	prev := u.tray0
	u.tray0 = next
	u.mu.Unlock()
	if next.mark != prev.mark || prev.tooltip == "" {
		u.tray.SetIcon(drawIcon(trayIconSize(), next.mark))
	}
	if next.tooltip != prev.tooltip {
		u.tray.SetTooltip(next.tooltip)
	}
	if next.menu != prev.menu || prev.tooltip == "" {
		u.tray.SetMenu(u.menu(offline, st))
	}
}

// describe picks the tray's mark and words: a problem first, then whether
// you're connected. Only the connection you chose counts: rules and work
// networks route through VPNs while disconnected too, and that isn't "on".
func describe(st status) (mark, string) {
	tip := "Moley · Disconnected"
	switch st.DefaultExit {
	case "", "direct":
	case "block":
		tip = "Moley · Blocking"
	default:
		tip = "Moley · Connected to " + st.name(st.DefaultExit)
	}
	if st.Mode.Error != "" {
		return markDown, "Moley · " + st.Mode.Error
	}
	for _, p := range st.Profiles {
		if p.State == "error" {
			return markDown, fmt.Sprintf("Moley · Can't reach %s", st.name(p.ID))
		}
	}
	for _, p := range st.Profiles {
		if p.ID == st.DefaultExit && (p.State == "connecting" || p.State == "auth-pending") {
			return markConnecting, "Moley · Connecting to " + st.name(p.ID)
		}
	}
	if st.DefaultExit == "" || st.DefaultExit == "direct" {
		return markDirect, tip
	}
	return markTunnel, tip
}

type profileStatus struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Error string `json:"error"`
}

// name is how an exit is shown: a profile's display name if it has one.
func (st status) name(id string) string {
	switch id {
	case "", "direct":
		return "Direct"
	case "block":
		return "Block all"
	}
	for _, p := range st.Profiles {
		if p.ID == id && p.Name != "" {
			return p.Name
		}
	}
	return id
}

// menu is the tray's right-click menu: the few things worth doing without
// opening the window.
func (u *ui) menu(offline bool, st status) *application.Menu {
	m := u.app.NewMenu()
	m.Add("Open Moley").OnClick(func(*application.Context) { u.show() })
	m.AddSeparator()
	if offline {
		m.Add("Start Moley").OnClick(func(*application.Context) {
			go func() {
				if startDaemon() == nil {
					u.link.retry()
				}
			}()
		})
	} else {
		every := m.AddCheckbox("All apps", st.Mode.TUN)
		if !st.Mode.Service {
			every.SetEnabled(false).SetLabel("All apps (setup needed)")
		}
		every.OnClick(func(*application.Context) { u.do("mode.set", map[string]any{"tun": !st.Mode.TUN}) })
		kill := m.AddCheckbox("Kill switch", st.Mode.KillSwitch != "off")
		kill.SetEnabled(st.Mode.Service)
		kill.OnClick(func(*application.Context) {
			ks := "on"
			if st.Mode.KillSwitch != "off" {
				ks = "off"
			}
			u.do("mode.set", map[string]any{"kill_switch": ks})
		})
		sub := m.AddSubmenu("Connection")
		for _, id := range st.Exits {
			if id == "block" {
				continue
			}
			sub.AddRadio(st.name(id), id == st.DefaultExit).OnClick(func(*application.Context) {
				u.do("default.set", map[string]any{"exit": id})
			})
		}
	}
	m.AddSeparator()
	m.Add("Quit").OnClick(func(*application.Context) { u.app.Quit() })
	return m
}

// do runs a daemon call from the tray; a failure shows as a notification.
func (u *ui) do(method string, params any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := call(ctx, method, params); err != nil {
			u.notify(err.Error(), "")
		}
	}()
}
