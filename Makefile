TAGS := with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls
export GOFLAGS := -tags=$(TAGS)

.PHONY: build ui test test-linux extension dist-windows dist-linux clean
EXE := $(if $(filter Windows_NT,$(OS)),.exe)

build:
	go build -trimpath -ldflags "-s -w" -o bin/moley$(EXE) ./cmd/moley

# The tray app is its own module, so the daemon never links Wails.
ui:
	cd cmd/moley-ui/frontend && npm ci && npm run build
	cd cmd/moley-ui && GOFLAGS= go build -trimpath -ldflags "-s -w $(if $(EXE),-H windowsgui)" -o ../../bin/moley-ui$(EXE) .

# -p 1: the integration tests start loopback VPN servers and proxy ports.
test:
	go vet ./...
	go test -p 1 ./...
	cd cmd/moley-ui && GOFLAGS= go vet . && GOFLAGS= go test .

test-linux:
	test/linux/run.sh

dist-windows:
	packaging/windows/build.sh

dist-linux:
	packaging/linux/build.sh

extension:
	cd extension && npm ci && npm run build

clean:
	rm -rf bin dist extension/dist cmd/moley-ui/frontend/dist
