package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

var marks = map[string]mark{"tunnel": markTunnel, "connecting": markConnecting, "down": markDown, "direct": markDirect, "off": markOff}

// TestIcon renders the mark in every state; MOLEY_ICON_OUT keeps them for
// a look.
func TestIcon(t *testing.T) {
	for name, m := range marks {
		for _, size := range []int{16, 24, 32, 256} {
			b := drawIcon(size, m)
			img, err := png.Decode(bytes.NewReader(b))
			if err != nil || img.Bounds().Dx() != size {
				t.Fatalf("%s %d: %v", name, size, err)
			}
			if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
				t.Errorf("%s %d: the corner should be transparent", name, size)
			}
			if _, _, _, a := img.At(size/2, size/2).RGBA(); a == 0 {
				t.Errorf("%s %d: the middle should be drawn", name, size)
			}
			if dir := os.Getenv("MOLEY_ICON_OUT"); dir != "" {
				_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d.png", name, size)), b, 0o644)
			}
		}
	}
}

// TestAssets redraws the app's icon files from the mark when
// MOLEY_WRITE_ASSETS is set: go test -run Assets with it, after changing it.
func TestAssets(t *testing.T) {
	if os.Getenv("MOLEY_WRITE_ASSETS") == "" {
		t.Skip("set MOLEY_WRITE_ASSETS to redraw the icon files")
	}
	write := func(path string, b []byte) {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("build/icon.png", drawIcon(256, markTunnel))
	write("build/moley.ico", ico(16, 24, 32, 48, 64, 128, 256))
	for _, n := range []int{16, 32, 48, 128} {
		write(fmt.Sprintf("../../extension/icons/%d.png", n), drawIcon(n, markTunnel))
	}
}

// ico packs the mark at each size into a .ico of PNG images.
func ico(sizes ...int) []byte {
	var head, body bytes.Buffer
	_ = binary.Write(&head, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for _, n := range sizes {
		img := drawIcon(n, markTunnel)
		_ = binary.Write(&head, binary.LittleEndian, struct {
			W, H, Colours, Reserved uint8
			Planes, Bits            uint16
			Size, Offset            uint32
		}{uint8(n % 256), uint8(n % 256), 0, 0, 1, 32, uint32(len(img)), uint32(offset)})
		offset += len(img)
		body.Write(img)
	}
	return append(head.Bytes(), body.Bytes()...)
}
