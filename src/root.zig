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
