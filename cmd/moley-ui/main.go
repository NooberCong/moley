// Command moley-ui is Moley's tray app for Windows and Linux: a tray icon
// that shows at a glance whether traffic is protected, a short menu, and
// a window with exits, live activity, rules and settings.
//
// It is a thin client of the daemon's RPC: it holds no state of its own,
// the daemon never depends on it, and when its window is closed it frees
// the WebView and keeps only the tray icon.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"slices"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

//go:embed all:frontend/dist
var dist embed.FS

// version is set at build time (-ldflags "-X main.version=…").
var version = "0.2.0"

func main() {
	assets, err := fs.Sub(dist, "frontend/dist")
	if err != nil {
		log.Fatal(err)
	}
	u := &ui{last: map[string]json.RawMessage{}, notifier: notifications.New()}
	u.app = application.New(application.Options{
		Name:        "Moley",
		Description: "Routes your traffic through your VPNs and proxies, by your rules.",
		LogLevel:    slog.LevelWarn,
		Icon:        drawIcon(256, markTunnel),
		Services:    []application.Service{application.NewService(&Bridge{ui: u}), application.NewService(u.notifier)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID:               "app.moley.tray",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) { u.show() },
		},
		Linux: application.LinuxOptions{DisableQuitOnLastWindowClosed: true, ProgramName: "moley-ui"},
		// Closing the window leaves the tray running, as on Linux.
		Windows: application.WindowsOptions{DisableQuitOnLastWindowClosed: true, AdditionalBrowserArgs: debugArgs()},
	})
	u.tray = u.app.SystemTray.New()
	u.tray.OnClick(u.show)
	u.refreshTray()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.link = newLink(u.onEvent, u.onDown)
	go u.link.run(ctx)
	if !slices.Contains(os.Args[1:], "--hidden") {
		u.app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) { u.show() })
	}
	initUpdates(u.app)
	if err := u.app.Run(); err != nil {
		log.Fatal(err)
	}
}

// debugArgs opens the WebView to automation (UI tests) when
// MOLEY_UI_DEBUG_PORT is set.
func debugArgs() []string {
	if port := os.Getenv("MOLEY_UI_DEBUG_PORT"); port != "" {
		return []string{"--remote-debugging-port=" + port}
	}
	return nil
}

// ui is the app's state: the tray, the window (nil while closed) and the
// daemon's latest events.
type ui struct {
	app      *application.App
	tray     *application.SystemTray
	link     *link
	notifier *notifications.NotificationService

	mu       sync.Mutex
	win      *application.WebviewWindow
	last     map[string]json.RawMessage // latest data per event
	offline  string                     // why the daemon can't be reached
	tray0    trayState                  // what the tray shows now
	started  bool                       // tried starting the daemon once
	vpn      vpn                        // the VPN in use, for notifications
	vpnKnown bool                       // vpn has been set from a status
}

// show opens the window, or brings it to the front.
func (u *ui) show() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.win != nil {
		u.win.Show()
		u.win.Restore()
		u.win.Focus()
		return
	}
	w := u.app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "main",
		Title:            "Moley",
		Width:            420,
		Height:           720,
		MinWidth:         380,
		MinHeight:        600,
		URL:              "/",
		BackgroundColour: application.NewRGB(0x05, 0x07, 0x06), // the page's own black: no flash on open
		InitialPosition:  application.WindowCentered,
		DevToolsEnabled:  os.Getenv("MOLEY_UI_DEVTOOLS") != "",
		Windows:          application.WindowsWindow{Theme: application.Dark},
	})
	// Closing destroys the window and its WebView; only the tray stays.
	w.OnWindowEvent(events.Common.WindowClosing, func(*application.WindowEvent) {
		u.mu.Lock()
		if u.win == w {
			u.win = nil
		}
		u.mu.Unlock()
		u.link.watchConns(false)
	})
	u.win = w
}

func (u *ui) onEvent(event string, data json.RawMessage) {
	u.mu.Lock()
	u.last[event] = data
	u.offline = ""
	u.mu.Unlock()
	u.app.Event.Emit(event, data)
	if event == "status" { // the tray follows the status alone
		u.refreshTray()
	}
}

func (u *ui) onDown() {
	u.mu.Lock()
	u.last = map[string]json.RawMessage{}
	u.offline = "Moley isn't running"
	start := !u.started
	u.started = true
	u.mu.Unlock()
	u.app.Event.Emit("offline", u.offline)
	u.refreshTray()
	// At login the tray starts first: bring the daemon up once. After
	// that, a stopped daemon was stopped on purpose.
	if start {
		go func() {
			if startDaemon() == nil {
				u.link.retry()
			}
		}()
	}
}

// snapshot is the latest state, for a window that just opened.
func (u *ui) snapshot() map[string]json.RawMessage {
	u.mu.Lock()
	defer u.mu.Unlock()
	res := make(map[string]json.RawMessage, len(u.last)+1)
	for k, v := range u.last {
		res[k] = v
	}
	if u.offline != "" {
		b, _ := json.Marshal(u.offline)
		res["offline"] = b
	}
	return res
}
