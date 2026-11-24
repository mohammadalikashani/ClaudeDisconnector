package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// shieldICO draws a 32x32 shield in the given color, with a white check (ok=true)
// or cross (ok=false) or nothing (mark=false), and returns it as an .ico (PNG payload).
func shieldICO(fill color.RGBA, mark bool, ok bool) []byte {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	white := color.RGBA{255, 255, 255, 255}
	border := color.RGBA{fill.R / 2, fill.G / 2, fill.B / 2, 255}

	inShield := func(x, y float64, inset float64) bool {
		cx := 15.5
		top, mid, bottom := 2.0+inset, 15.0, 30.0-inset
		if y < top || y > bottom {
			return false
		}
		half := 13.0 - inset
		if y > mid {
			half = (13.0 - inset) * (bottom - y) / (bottom - mid)
		}
		return math.Abs(x-cx) <= half
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			switch {
			case inShield(fx, fy, 1.5):
				img.Set(x, y, fill)
			case inShield(fx, fy, 0):
				img.Set(x, y, border)
			}
		}
	}

	if mark {
		thick := func(x0, y0, x1, y1 float64) {
			for y := 0; y < n; y++ {
				for x := 0; x < n; x++ {
					px, py := float64(x)+0.5, float64(y)+0.5
					dx, dy := x1-x0, y1-y0
					t := math.Max(0, math.Min(1, ((px-x0)*dx+(py-y0)*dy)/(dx*dx+dy*dy)))
					if math.Hypot(px-(x0+t*dx), py-(y0+t*dy)) <= 1.9 {
						img.Set(x, y, white)
					}
				}
			}
		}
		if ok {
			thick(9.5, 15.5, 14, 20.5)
			thick(14, 20.5, 22.5, 10)
		} else {
			thick(10.5, 9.5, 20.5, 19.5)
			thick(20.5, 9.5, 10.5, 19.5)
		}
	}

	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)

	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, []uint16{0, 1, 1}) // reserved, type=icon, count
	ico.Write([]byte{n, n, 0, 0})                              // w, h, colors, reserved
	binary.Write(&ico, binary.LittleEndian, []uint16{1, 32})   // planes, bpp
	binary.Write(&ico, binary.LittleEndian, []uint32{uint32(pngBuf.Len()), 22})
	ico.Write(pngBuf.Bytes())
	return ico.Bytes()
}

var (
	iconAllowed  = shieldICO(color.RGBA{0x2e, 0x9e, 0x44, 255}, true, true)
	iconProxy    = shieldICO(color.RGBA{0x1a, 0x73, 0xe8, 255}, true, true)
	iconIran     = shieldICO(color.RGBA{0xd9, 0x30, 0x25, 255}, true, false)
	iconUnknown  = shieldICO(color.RGBA{0xe8, 0x71, 0x0a, 255}, true, false)
	iconChecking = shieldICO(color.RGBA{0xe0, 0xa8, 0x00, 255}, false, false)
	iconDown     = shieldICO(color.RGBA{0x80, 0x80, 0x80, 255}, false, false)
)
