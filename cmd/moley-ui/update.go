package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/endpoint"
)

// Set at build time for a release (-ldflags "-X main.updateURL=… -X
// main.updateKey=…"). A build without them doesn't update itself.
var (
	updateURL string // the update manifest
	updateKey string // base64 Ed25519 public key; every release must be signed by it
)

// updatesEnabled: Windows installs and AppImages update themselves; .deb
// and .rpm installs update through the package manager.
func updatesEnabled() bool {
	if manifestURL() == "" || updateKey == "" {
		return false
	}
	return runtime.GOOS == "windows" || os.Getenv("APPIMAGE") != ""
}

// manifestURL can be pointed elsewhere for testing; the signing key can't.
func manifestURL() string {
	if u := os.Getenv("MOLEY_UPDATE_URL"); u != "" {
		return u
	}
	return updateURL
}

func initUpdates(app *application.App) {
	if !updatesEnabled() {
		return
	}
	key, err := base64.StdEncoding.DecodeString(updateKey)
	if err != nil {
		app.Logger.Error("updates: bad key", "error", err)
		return
	}
	p, err := endpoint.New(endpoint.Config{URL: manifestURL()})
	if err == nil {
		err = app.Updater.Init(updater.Config{CurrentVersion: version, Providers: []updater.Provider{p}, PublicKey: key, Window: updater.WindowNone})
	}
	if err != nil {
		app.Logger.Error("updates", "error", err)
	}
}

type Update struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// CheckUpdate asks the update server for a newer release.
func (b *Bridge) CheckUpdate() Reply {
	if !updatesEnabled() {
		return reply(nil, errors.New("this build updates through your package manager"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rel, err := b.ui.app.Updater.Check(ctx)
	if err != nil {
		return reply(nil, err)
	}
	u := Update{}
	if rel != nil {
		u = Update{Available: true, Version: rel.Version, Notes: rel.Notes}
	}
	out, _ := json.Marshal(u)
	return reply(out, nil)
}

// InstallUpdate downloads the release CheckUpdate found, verifies its
// signature, and installs it: on Windows by running the installer (which
// updates the service too and starts the new tray), on Linux by swapping
// the AppImage.
func (b *Bridge) InstallUpdate() Reply {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	up := b.ui.app.Updater
	if err := up.DownloadAndInstall(ctx); err != nil {
		return reply(nil, err)
	}
	if runtime.GOOS != "windows" {
		return reply(nil, up.Restart(ctx))
	}
	if err := runInstaller(up.DownloadedPath()); err != nil {
		return reply(nil, err)
	}
	b.ui.app.Quit()
	return reply(nil, nil)
}
