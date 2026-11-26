module moley/cmd/moley-ui

go 1.26.0

toolchain go1.27.4

require (
	golang.org/x/sys v0.49.0
	moley v0.0.0
)

require git.sr.ht/~jackmordaunt/go-toast/v2 v2.0.3 // indirect

require (
	github.com/Microsoft/go-winio v0.6.4 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/ebitengine/purego v0.11.1 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/wailsapp/wails/v3 v3.1.0
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/term v0.46.0 // indirect
)

replace moley => ../..
