package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// mark is how the Moley mark looks in one state: a white shield shaped as
// an M, glowing on a tile coloured for the state, over a dot map of the
// world.
type mark struct {
	tone, deep color.NRGBA // the tile's top and bottom
	lit        bool
}

var (
	markTunnel     = mark{color.NRGBA{0x2e, 0xe6, 0xa8, 0xff}, color.NRGBA{0x12, 0x9a, 0x72, 0xff}, true}  // protected: through a tunnel, or every app
	markConnecting = mark{color.NRGBA{0xf3, 0xb6, 0x4e, 0xff}, color.NRGBA{0xb0, 0x72, 0x14, 0xff}, true}  // the tunnel in use is connecting
	markDown       = mark{color.NRGBA{0xff, 0x6a, 0x55, 0xff}, color.NRGBA{0xb8, 0x30, 0x22, 0xff}, true}  // a tunnel or the mode has a problem
	markDirect     = mark{color.NRGBA{0x8c, 0x98, 0x94, 0xff}, color.NRGBA{0x55, 0x60, 0x5c, 0xff}, false} // running, nothing tunneled
	markOff        = mark{color.NRGBA{0x5e, 0x68, 0x65, 0xff}, color.NRGBA{0x33, 0x3a, 0x38, 0xff}, false} // Moley isn't running
)

// The shield on a 128 grid, clockwise from its top left peak: its top
// dips in a V between two peaks, the M, and its sides curve to a point.
var shield = func() [][2]float64 {
	const l, r, top, vee, waist, tip = 30.0, 98.0, 24.0, 48.0, 60.0, 104.0
	pts := [][2]float64{{l, top}, {(l + r) / 2, vee}, {r, top}}
	// Each side is a curve from the waist to the tip, bending in late.
	const n = 16
	for i := range n + 1 {
		t := float64(i) / n
		pts = append(pts, side(r, waist, tip, t))
	}
	for i := n - 1; i >= 0; i-- {
		p := side(r, waist, tip, float64(i)/n)
		pts = append(pts, [2]float64{128 - p[0], p[1]})
	}
	return pts
}()

// side is a point t of the way down the shield's right side, a quadratic
// curve from (x, waist) toward the tip under the centre.
func side(x, waist, tip, t float64) [2]float64 {
	cx, cy := x, waist+(tip-waist)*0.62 // the control point
	u := 1 - t
	return [2]float64{u*u*x + 2*u*t*cx + t*t*64, u*u*waist + 2*u*t*cy + t*t*tip}
}

const shieldRim = 5.0 // the inset rim's distance from the edge

// world is a dot map of the world, a cell per character.
var world = []string{
	"..................................",
	"......###.#####.........##........",
	"..#############......#.##########.",
	".###############....##############",
	"..##############...###############",
	"...###########.....##.############",
	"....#########......###############",
	".....#######.......##############.",
	".....######.......#############...",
	"......####........###.#########...",
	".......###.......######.######....",
	"........##......########..###.....",
	".........##.....#########..#......",
	"..........#.....##########........",
	"...........###...########.........",
	"...........#####..######......#...",
	"...........######..#####.....##...",
	"............#####...####..........",
	".............####...###......###..",
	".............###....##......#####.",
	".............###...........######.",
	".............##.............####..",
	"............##..................#.",
	"............#.....................",
}

const (
	worldX, worldY = 5.0, 12.0 // the map's top left
	worldCell      = 3.5
	worldDot       = 2.5
)

// drawIcon renders the mark at size px. It is drawn from distance fields,
// so it is crisp at any size without image assets.
func drawIcon(size int, m mark) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size) / 128
	const ss = 4         // supersampling per axis
	detail := size >= 48 // the map and glow, too fine to read smaller
	for y := range size {
		for x := range size {
			var r, g, b, a float64 // premultiplied sums
			for sy := range ss {
				for sx := range ss {
					px := (float64(x) + (float64(sx)+0.5)/ss) / s
					py := (float64(y) + (float64(sy)+0.5)/ss) / s
					if roundedRect(px, py, 4, 4, 124, 124, 28) > 0 {
						continue
					}
					c := markAt(px, py, m, detail)
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
func markAt(x, y float64, m mark, detail bool) [3]float64 {
	tone, white := rgb(m.tone), [3]float64{1, 1, 1}
	d := polygon(x, y, shield)
	if d < 0 {
		face := white
		if !m.lit {
			face = lerp(tone, white, 0.75)
		}
		if x > 64 { // the right half in the shade
			face = lerp(face, tone, 0.22)
		}
		if math.Abs(d+shieldRim) < 1.1 { // the inset rim
			face = lerp(face, rgb(m.deep), 0.5)
		}
		return face
	}
	// The tile, deep green fading deeper down.
	c := lerp(lerp(tone, rgb(m.deep), 0.35), scale(rgb(m.deep), 0.8), y/128)
	if !detail { // small: just the tile and the shield, for contrast
		return c
	}
	glow := 0.0
	if m.lit {
		glow = math.Exp(-d / 6)
	}
	if onDot(x, y) {
		c = lerp(c, white, 0.12+0.2*glow)
	}
	// The shield lights the tile just around it.
	return lerp(c, lerp(tone, white, 0.3), 0.35*glow)
}

// onDot reports whether a point is on one of the world map's dots.
func onDot(x, y float64) bool {
	col, row := (x-worldX)/worldCell, (y-worldY)/worldCell
	if col < 0 || row < 0 || int(row) >= len(world) || int(col) >= len(world[int(row)]) {
		return false
	}
	if world[int(row)][int(col)] != '#' {
		return false
	}
	fx, fy := (col-math.Floor(col))*worldCell, (row-math.Floor(row))*worldCell
	return fx < worldDot && fy < worldDot
}

// polygon is the signed distance to a closed polygon: negative inside.
func polygon(x, y float64, v [][2]float64) float64 {
	d := math.Inf(1)
	sign := 1.0
	for i, j := 0, len(v)-1; i < len(v); j, i = i, i+1 {
		ex, ey := v[j][0]-v[i][0], v[j][1]-v[i][1]
		wx, wy := x-v[i][0], y-v[i][1]
		t := math.Min(math.Max((wx*ex+wy*ey)/(ex*ex+ey*ey), 0), 1)
		d = math.Min(d, math.Hypot(wx-ex*t, wy-ey*t))
		a, b, c := y >= v[i][1], y < v[j][1], ex*wy > ey*wx
		if (a && b && c) || (!a && !b && !c) {
			sign = -sign
		}
	}
	return sign * d
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
