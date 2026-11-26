package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// mark is how the Moley mark looks in one state: a tunnel mouth built of
// segments, like the window's power ring, on a dark tile. Lit, the arch
// glows and there is light at the end of the tunnel; unlit, it sits dark.
type mark struct {
	arch color.NRGBA
	lit  bool
}

var (
	markTunnel     = mark{color.NRGBA{0x2e, 0xe6, 0xa8, 0xff}, true}  // protected: through a tunnel, or every app
	markConnecting = mark{color.NRGBA{0xf3, 0xb6, 0x4e, 0xff}, true}  // the tunnel in use is connecting
	markDown       = mark{color.NRGBA{0xff, 0x6a, 0x55, 0xff}, true}  // a tunnel or the mode has a problem
	markDirect     = mark{color.NRGBA{0x6e, 0x7a, 0x76, 0xff}, false} // running, nothing tunneled
	markOff        = mark{color.NRGBA{0x3a, 0x43, 0x40, 0xff}, false} // Moley isn't running

	tileTop    = color.NRGBA{0x1d, 0x23, 0x21, 0xff}
	tileBottom = color.NRGBA{0x07, 0x09, 0x08, 0xff}
)

// The mark on a 128 grid: a half ring of stones over two legs.
const (
	archX, archY = 64.0, 65.0 // the half ring's centre
	archInner    = 22.0
	archOuter    = 40.0
	archFloor    = 103.0 // where the legs stand
	stones       = 5     // in the half ring
	stoneGap     = 5.5   // between stones, straight-sided
)

// drawIcon renders the mark at size px. It is drawn from distance fields,
// so it is crisp at any size without image assets.
func drawIcon(size int, m mark) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size) / 128
	const ss = 4 // supersampling per axis
	for y := range size {
		for x := range size {
			var r, g, b, a float64 // premultiplied sums
			for sy := range ss {
				for sx := range ss {
					px := (float64(x) + (float64(sx)+0.5)/ss) / s
					py := (float64(y) + (float64(sy)+0.5)/ss) / s
					if roundedRect(px, py, 4, 4, 124, 124, 30) > 0 {
						continue
					}
					c := markAt(px, py, m)
					r, g, b, a = r+c[0], g+c[1], b+c[2], a+1
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{R: unit(r / a), G: unit(g / a), B: unit(b / a), A: unit(a / (ss * ss))})
		}
	}
	var out bytes.Buffer
	_ = png.Encode(&out, img)
	return out.Bytes()
}

// markAt is the colour (0..1 RGB) of the mark at a point inside the tile.
func markAt(x, y float64, m mark) [3]float64 {
	tile := lerp(rgb(tileTop), rgb(tileBottom), y/128)
	tone := rgb(m.arch)
	if light, ok := stone(x, y); ok {
		if !m.lit {
			return tone
		}
		return lerp(scale(tone, 0.7), tone, light) // lit from above
	}
	if !m.lit {
		return tile
	}
	// Light at the end of the tunnel, and a faint halo around the arch.
	dx, dy := x-archX, y-archFloor
	inside := math.Abs(dx) < archInner && (y > archY || math.Hypot(x-archX, y-archY) < archInner) && y <= archFloor
	glow := 0.12 * math.Exp(-math.Pow((math.Hypot(x-archX, y-archY)-(archInner+archOuter)/2)/16, 2))
	if inside {
		glow = math.Max(glow, 0.95*math.Exp(-math.Pow(math.Hypot(dx*0.9, dy)/20, 2)))
	}
	return lerp(tile, lerp(tone, [3]float64{1, 1, 1}, 0.2*glow), math.Min(glow, 1))
}

// stone reports whether a point is on one of the arch's stones, and how
// much light falls on it (1 at the top).
func stone(x, y float64) (float64, bool) {
	dx, dy := x-archX, y-archY
	if y > archY { // the legs
		ok := math.Abs(dx) >= archInner && math.Abs(dx) <= archOuter && y <= archFloor && dy >= stoneGap/2
		return 0.45, ok
	}
	r := math.Hypot(dx, dy)
	if r < archInner || r > archOuter {
		return 0, false
	}
	step := math.Pi / stones
	a := math.Atan2(dx, -dy) + math.Pi/2 // 0 at the left foot, π at the right
	off := math.Mod(a, step)
	if r*math.Sin(math.Min(off, step-off)) < stoneGap/2 && a > step/2 && a < math.Pi-step/2 {
		return 0, false
	}
	if r*math.Sin(math.Min(a, math.Pi-a)) < stoneGap/2 { // the joint over each leg
		return 0, false
	}
	mid := (math.Floor(a/step)+0.5)*step - math.Pi/2
	return 0.35 + 0.65*(1+math.Cos(mid))/2, true
}

func rgb(c color.NRGBA) [3]float64 {
	return [3]float64{float64(c.R) / 255, float64(c.G) / 255, float64(c.B) / 255}
}

func lerp(a, b [3]float64, t float64) [3]float64 {
	return [3]float64{a[0] + (b[0]-a[0])*t, a[1] + (b[1]-a[1])*t, a[2] + (b[2]-a[2])*t}
}

func scale(a [3]float64, k float64) [3]float64 { return [3]float64{a[0] * k, a[1] * k, a[2] * k} }

func unit(v float64) uint8 { return uint8(math.Round(255 * math.Min(math.Max(v, 0), 1))) }

func roundedRect(x, y, x0, y0, x1, y1, r float64) float64 {
	qx := math.Max(math.Max(x0+r-x, x-(x1-r)), 0)
	qy := math.Max(math.Max(y0+r-y, y-(y1-r)), 0)
	if qx == 0 && qy == 0 {
		return -1
	}
	return math.Hypot(qx, qy) - r
}
