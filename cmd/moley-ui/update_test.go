package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/endpoint"

	"moley/internal/release"
)

// host stands in for the app: the updater runs headless (WindowNone).
type host struct{}

func (host) Emit(string, ...any) bool                              { return true }
func (host) OnEvent(string, func(any)) func()                      { return func() {} }
func (host) OpenWindow(updater.WindowOptions) updater.WindowHandle { return nil }
func (host) Quit()                                                 {}

// TestUpdate runs the updater the tray uses against a local update server:
// a release signed with the built-in key installs; one signed by another
// key, or altered after signing, never does.
func TestUpdate(t *testing.T) {
	pub, priv, _ := release.Keygen()
	_, otherPriv, _ := release.Keygen()
	installer := []byte("MZ pretend installer for 0.3.0")
	var manifest, served []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest.json" {
			w.Write(manifest)
			return
		}
		w.Write(served)
	}))
	defer srv.Close()
	publish := func(version, key string, file []byte) {
		a, err := release.Sign(bytes.NewReader(installer), key, release.Artifact{
			URL: srv.URL + "/Moley-Setup.exe", Filename: "Moley-Setup.exe", Platform: runtime.GOOS, Arch: runtime.GOARCH})
		if err != nil {
			t.Fatal(err)
		}
		manifest, _ = release.NewManifest(version, "", a)
		served = file
	}
	newUpdater := func() *updater.Updater {
		key, _ := base64.StdEncoding.DecodeString(pub)
		p, _ := endpoint.New(endpoint.Config{URL: srv.URL + "/latest.json"})
		u := updater.New(host{})
		if err := u.Init(updater.Config{CurrentVersion: "0.2.0", Providers: []updater.Provider{p}, PublicKey: key, Window: updater.WindowNone}); err != nil {
			t.Fatal(err)
		}
		return u
	}
	ctx := context.Background()

	publish("0.2.0", priv, installer)
	if rel, err := newUpdater().Check(ctx); err != nil || rel != nil {
		t.Fatalf("same version: %+v %v", rel, err)
	}

	publish("0.3.0", priv, installer)
	u := newUpdater()
	if rel, err := u.Check(ctx); err != nil || rel == nil || rel.Version != "0.3.0" {
		t.Fatalf("newer version: %+v %v", rel, err)
	}
	if err := u.DownloadAndInstall(ctx); err != nil {
		t.Fatalf("signed release: %v", err)
	}
	if got, _ := os.ReadFile(u.DownloadedPath()); !bytes.Equal(got, installer) {
		t.Fatalf("downloaded %q", got)
	}

	for name, tc := range map[string]struct {
		key  string
		file []byte
	}{
		"signed by another key": {otherPriv, installer},
		"altered after signing": {priv, append([]byte("evil"), installer...)},
	} {
		publish("0.3.0", tc.key, tc.file)
		u := newUpdater()
		if _, err := u.Check(ctx); err != nil {
			t.Fatal(err)
		}
		if err := u.DownloadAndInstall(ctx); err == nil {
			t.Errorf("%s: installed", name)
		} else {
			t.Logf("%s: refused: %v", name, err)
		}
	}
}
