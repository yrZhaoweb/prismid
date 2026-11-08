package prismid

import (
	"strconv"
	"strings"
)

// virtualGPUKeywords lists software rasterizers and hypervisor virtual GPU adapters
// commonly used by headless browser farms (Docker Puppeteer/Playwright) and VM clones.
var virtualGPUKeywords = []string{
	"swiftshader",
	"llvmpipe",
	"softpipe",
	"lavapipe",
	"mesa offscreen",
	"software rasterizer",
	"microsoft basic render driver",
	"vmware",
	"svga3d",
	"virtualbox",
	"vboxvideo",
	"parallels",
	"qemu",
	"virtio",
	"chromium", // standalone unmasked renderer "Chromium" in headless stubs
}

// IsVirtualOrSoftwareGPU detects whether the reported WebGL renderer or native hardware
// anchor belongs to a software renderer (e.g., SwiftShader, llvmpipe) or a virtual machine
// (e.g., VMware, VirtualBox, Parallels, QEMU).
func IsVirtualOrSoftwareGPU(vendor, renderer string, nativeAnchor *NativeHardwareAnchor) (bool, string) {
	if nativeAnchor != nil && nativeAnchor.IsVM {
		reason := "native_hypervisor_detected"
		if strings.TrimSpace(nativeAnchor.VMVendor) != "" {
			reason += ":" + strings.ToLower(strings.TrimSpace(nativeAnchor.VMVendor))
		}
		return true, reason
	}

	combined := strings.ToLower(strings.TrimSpace(vendor) + " " + strings.TrimSpace(renderer))
	if strings.TrimSpace(renderer) == "" {
		return true, "missing_gpu_renderer"
	}

	for _, kw := range virtualGPUKeywords {
		if kw == "chromium" {
			if strings.EqualFold(strings.TrimSpace(renderer), "chromium") {
				return true, "virtual_gpu:chromium_stub"
			}
			continue
		}
		if strings.Contains(combined, kw) {
			return true, "virtual_gpu:" + kw
		}
	}

	return false, ""
}

// VerifyGPURegisterLaws checks physical hardware pairing laws between the reported
// GPU architecture, WebGL hardware register limits vector, OS platform, and JS engine
// FDLIBM Math constants.
//
// Canonical WebGLLimitsVector format (pipe-delimited 10 segments):
//
//	0: MAX_TEXTURE_SIZE (e.g. "16384")
//	1: MAX_CUBE_MAP_TEXTURE_SIZE (e.g. "16384")
//	2: MAX_VIEWPORT_DIMS (e.g. "16384,16384")
//	3: MAX_RENDERBUFFER_SIZE (e.g. "16384")
//	4: MAX_VERTEX_UNIFORM_VECTORS (e.g. "4096")
//	5: MAX_FRAGMENT_UNIFORM_VECTORS (e.g. "1024")
//	6: MAX_VARYING_VECTORS (e.g. "31")
//	7: ALIASED_LINE_WIDTH_RANGE (e.g. "1,1")
//	8: ALIASED_POINT_SIZE_RANGE (e.g. "1,511")
//	9: MAX_TEXTURE_MAX_ANISOTROPY_EXT (e.g. "16")
//	10: SHADER_PRECISION_BITS (e.g. "23,23,23,23")
//	11: EXTENSIONS_HASH (8+ hex chars)
func VerifyGPURegisterLaws(payload *ProbePayload) []string {
	var violations []string
	if payload == nil {
		return []string{"nil_payload"}
	}

	rendererLower := strings.ToLower(strings.TrimSpace(payload.WebGL.GPURenderer))
	vendorLower := strings.ToLower(strings.TrimSpace(payload.WebGL.GPUVendor))
	platformLower := strings.ToLower(strings.TrimSpace(payload.System.Platform))
	uaLower := strings.ToLower(strings.TrimSpace(payload.System.UserAgent))

	parts := strings.Split(strings.TrimSpace(payload.WebGL.WebGLLimitsVector), "|")
	if len(parts) < 8 {
		violations = append(violations, "gpu_register_law_violation:malformed_limits_vector")
		return violations
	}

	maxTexSize, errTex := strconv.Atoi(strings.TrimSpace(parts[0]))
	lineWidthRange := strings.ReplaceAll(strings.TrimSpace(parts[7]), " ", "")

	if errTex != nil || maxTexSize < 2048 {
		violations = append(violations, "gpu_register_law_violation:invalid_max_texture_size")
	}

	isAppleSiliconGPU := strings.Contains(rendererLower, "apple m1") ||
		strings.Contains(rendererLower, "apple m2") ||
		strings.Contains(rendererLower, "apple m3") ||
		strings.Contains(rendererLower, "apple m4") ||
		strings.Contains(rendererLower, "apple gpu")

	// Law 1: Apple Silicon GPUs only exist on Apple operating systems, always enforce
	// ALIASED_LINE_WIDTH_RANGE == [1,1] in Metal/WebGL, and support MAX_TEXTURE_SIZE >= 16384.
	if isAppleSiliconGPU {
		if strings.Contains(platformLower, "win") || strings.Contains(platformLower, "linux") ||
			strings.Contains(uaLower, "windows nt") {
			violations = append(violations, "gpu_register_law_violation:apple_gpu_on_non_apple_os")
		}
		if lineWidthRange != "1,1" {
			violations = append(violations, "gpu_register_law_violation:apple_gpu_invalid_line_width")
		}
		if maxTexSize < 16384 {
			violations = append(violations, "gpu_register_law_violation:apple_gpu_texture_size_below_16384")
		}
		if strings.Contains(rendererLower, "direct3d") || strings.Contains(rendererLower, "d3d11") {
			violations = append(violations, "gpu_register_law_violation:apple_gpu_with_d3d_backend")
		}
	}

	// Law 2: ANGLE Direct3D11 / Direct3D9 backends only exist on Windows, never on macOS or Linux.
	if strings.Contains(rendererLower, "direct3d") || strings.Contains(rendererLower, "d3d11") || strings.Contains(rendererLower, "d3d9") {
		if strings.Contains(platformLower, "mac") || strings.Contains(platformLower, "iphone") || strings.Contains(platformLower, "ipad") {
			violations = append(violations, "gpu_register_law_violation:d3d_backend_on_apple_platform")
		}
		// ANGLE Direct3D11 always reports ALIASED_LINE_WIDTH_RANGE as [1,1].
		if lineWidthRange != "1,1" {
			violations = append(violations, "gpu_register_law_violation:d3d_backend_non_unit_line_width")
		}
	}

	// Law 3: Vendor and Renderer cross-consistency (e.g., vendor="Apple" claiming NVIDIA GeForce RTX).
	if strings.Contains(vendorLower, "apple") && (strings.Contains(rendererLower, "nvidia") || strings.Contains(rendererLower, "radeon") || strings.Contains(rendererLower, "geforce")) {
		violations = append(violations, "gpu_register_law_violation:apple_vendor_with_discrete_pc_gpu")
	}

	// Law 4: Native anchor OS vs Web system platform consistency.
	if payload.NativeAnchor != nil && strings.TrimSpace(payload.NativeAnchor.Platform) != "" {
		natPlat := strings.ToLower(strings.TrimSpace(payload.NativeAnchor.Platform))
		if natPlat == "macos" && (strings.Contains(platformLower, "win") || strings.Contains(platformLower, "linux")) {
			violations = append(violations, "gpu_register_law_violation:native_macos_vs_web_platform_mismatch")
		}
		if natPlat == "windows" && strings.Contains(platformLower, "mac") {
			violations = append(violations, "gpu_register_law_violation:native_windows_vs_web_platform_mismatch")
		}
	}

	// Law 5: JS Engine FDLIBM Math signature vs User-Agent claim.
	mathSig := strings.ToLower(strings.TrimSpace(payload.Lies.MathEngineSignature))
	if mathSig != "" {
		if mathSig == "jsc" && strings.Contains(uaLower, "firefox/") {
			violations = append(violations, "math_engine_ua_mismatch:jsc_claiming_firefox")
		}
		if mathSig == "spidermonkey" && strings.Contains(uaLower, "chrome/") && !strings.Contains(uaLower, "firefox/") {
			violations = append(violations, "math_engine_ua_mismatch:spidermonkey_claiming_chrome")
		}
		if mathSig == "v8" && strings.Contains(uaLower, "firefox/") {
			violations = append(violations, "math_engine_ua_mismatch:v8_claiming_firefox")
		}
	}

	return violations
}
