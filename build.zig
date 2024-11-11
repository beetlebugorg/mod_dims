const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libmod_dims = b.addSharedLibrary(.{
        .name = "mod_dims",
        .target = target,
        .optimize = optimize,
        .version = .{ .major = 4, .minor = 0, .patch = 0 },
    });

    libmod_dims.linkSystemLibrary("curl");
    libmod_dims.linkSystemLibrary("apr-1");
    libmod_dims.linkSystemLibrary("MagickWand");
    libmod_dims.addCSourceFiles(.{
        .files = &.{
            "src/configuration.c",
            "src/encryption.c",
            "src/handler.c",
            "src/mod_dims_ops.c",
            "src/mod_dims.c",
            "src/module.c",
            "src/status.c",
        }, 
        .flags = &.{
        "-I/usr/local/apache2/include/",
        "-Wall",
        "-W",
        "-Wstrict-prototypes",
        "-Wwrite-strings",
        "-Wno-missing-field-initializers",
        },
      }
    );

    b.installArtifact(libmod_dims);
}
