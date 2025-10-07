const std = @import("std");

// Export HCTR2
const hctr2 = @import("hctr2.zig");
pub const Hctr2_128 = hctr2.Hctr2_128;
pub const Hctr2_256 = hctr2.Hctr2_256;
pub const Hctr2 = hctr2.Hctr2;

// Export HCTR3
const hctr3 = @import("hctr3.zig");
pub const Hctr3_128 = hctr3.Hctr3_128;
pub const Hctr3_256 = hctr3.Hctr3_256;
pub const Hctr3 = hctr3.Hctr3;

// Export HCTR2-FP (Format-Preserving)
const hctr2fp = @import("hctr2fp.zig");
pub const Hctr2Fp = hctr2fp.Hctr2Fp;
pub const Hctr2Fp_128_Decimal = hctr2fp.Hctr2Fp_128_Decimal;
pub const Hctr2Fp_256_Decimal = hctr2fp.Hctr2Fp_256_Decimal;
pub const Hctr2Fp_128_Hex = hctr2fp.Hctr2Fp_128_Hex;
pub const Hctr2Fp_256_Hex = hctr2fp.Hctr2Fp_256_Hex;
pub const Hctr2Fp_128_Base64 = hctr2fp.Hctr2Fp_128_Base64;
pub const Hctr2Fp_256_Base64 = hctr2fp.Hctr2Fp_256_Base64;
pub const encodeBaseRadix = hctr2fp.encodeBaseRadix;
pub const decodeBaseRadix = hctr2fp.decodeBaseRadix;

// Export HCTR3-FP (Format-Preserving)
const hctr3fp = @import("hctr3fp.zig");
pub const Hctr3Fp = hctr3fp.Hctr3Fp;
pub const Hctr3Fp_128_Decimal = hctr3fp.Hctr3Fp_128_Decimal;
pub const Hctr3Fp_256_Decimal = hctr3fp.Hctr3Fp_256_Decimal;
pub const Hctr3Fp_128_Hex = hctr3fp.Hctr3Fp_128_Hex;
pub const Hctr3Fp_256_Hex = hctr3fp.Hctr3Fp_256_Hex;
pub const Hctr3Fp_128_Base64 = hctr3fp.Hctr3Fp_128_Base64;
pub const Hctr3Fp_256_Base64 = hctr3fp.Hctr3Fp_256_Base64;
