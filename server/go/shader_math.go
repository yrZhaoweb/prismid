package prismid

import (
	"fmt"
	"math"
)

// DefaultSamplePoints defines the 8 canonical coordinates sampled on the 256x256
// dynamic challenge canvas when no custom points are specified.
var DefaultSamplePoints = [][2]int{
	{32, 48},
	{96, 64},
	{160, 80},
	{224, 96},
	{48, 144},
	{112, 160},
	{176, 192},
	{208, 224},
}

// ComputeExpectedSpotPixel evaluates the exact GLSL fragment shader color at integer
// pixel coordinate (x, y) on a 256x256 canvas.
//
// Critical alignment rule:
// In OpenGL ES / WebGL fragment shaders, gl_FragCoord.xy is evaluated at the pixel
// center (x + 0.5, y + 0.5), with (0, 0) at the bottom-left corner matching gl.readPixels.
//
//	u = (x + 0.5) / 256.0
//	v = (y + 0.5) / 256.0
//	r = 0.5 + 0.5 * sin(u * s0 + v * s1 + s2)
//	g = 0.5 + 0.5 * cos(u * s1 - v * s2 + s3)
//	b = 0.5 + 0.5 * sin((u + v) * s3 + s0)
func ComputeExpectedSpotPixel(x, y int, seed [4]float64) [4]uint8 {
	u := (float64(x) + 0.5) / 256.0
	v := (float64(y) + 0.5) / 256.0

	s0, s1, s2, s3 := seed[0], seed[1], seed[2], seed[3]

	r := 0.5 + 0.5*math.Sin(u*s0+v*s1+s2)
	g := 0.5 + 0.5*math.Cos(u*s1-v*s2+s3)
	b := 0.5 + 0.5*math.Sin((u+v)*s3+s0)

	return [4]uint8{
		quantizeChannel(r),
		quantizeChannel(g),
		quantizeChannel(b),
		255,
	}
}

// ComputeAllExpectedSpotPixels computes the expected RGBA values for all sample coordinates.
func ComputeAllExpectedSpotPixels(points [][2]int, seed [4]float64) [][4]uint8 {
	out := make([][4]uint8, len(points))
	for i, pt := range points {
		out[i] = ComputeExpectedSpotPixel(pt[0], pt[1], seed)
	}
	return out
}

// VerifySpotPixels compares the client-reported spot pixels against the server-computed
// mathematical expectation. Each 8-bit channel allows an absolute quantization difference
// of at most maxTolerance (default 2) to accommodate hardware SFU rounding differences
// across Apple Metal, ANGLE Direct3D11, Vulkan, and OpenGL drivers without false positives.
func VerifySpotPixels(points [][2]int, seed [4]float64, actual [][4]uint8, maxTolerance int) (bool, string) {
	if len(points) == 0 {
		return false, "empty_sample_points"
	}
	if len(actual) != len(points) {
		return false, fmt.Sprintf("spot_pixel_count_mismatch: got %d, want %d", len(actual), len(points))
	}
	if maxTolerance <= 0 {
		maxTolerance = 2
	}

	for i, pt := range points {
		expected := ComputeExpectedSpotPixel(pt[0], pt[1], seed)
		got := actual[i]
		if got[3] != 255 {
			return false, fmt.Sprintf("spot_pixel[%d]@(%d,%d) alpha=%d != 255", i, pt[0], pt[1], got[3])
		}
		for ch := 0; ch < 3; ch++ {
			diff := int(got[ch]) - int(expected[ch])
			if diff < 0 {
				diff = -diff
			}
			if diff > maxTolerance {
				return false, fmt.Sprintf(
					"spot_pixel[%d]@(%d,%d) ch=%d actual=%d expected=%d diff=%d > %d",
					i, pt[0], pt[1], ch, got[ch], expected[ch], diff, maxTolerance,
				)
			}
		}
	}
	return true, ""
}

func quantizeChannel(val float64) uint8 {
	if val <= 0.0 {
		return 0
	}
	if val >= 1.0 {
		return 255
	}
	return uint8(math.Round(val * 255.0))
}
