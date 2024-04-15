const std = @import("std");
const exit = std.process.exit;

const mem = std.mem;
const Allocator = mem.Allocator;

const io = std.io;
const stderr = io.getStdErr().writer();
const stdout = io.getStdOut().writer();

const debug = std.debug;
const print = debug.print;
const panic = debug.panic;

const fs = std.fs;
const Writer = fs.File.Writer;

pub fn validCIdentFromStr(allocator: Allocator, str: []const u8) ![]u8 {
    const result = try allocator.dupe(u8, str);
    for (0..result.len) |i| {
        if (!std.ascii.isAlphabetic(result[i])) {
            result[i] = '_';
        }
    }
    return result;
}

pub const Bundler = struct {
    const Entry = struct {
        path: []const u8,
        content: []const u8,
    };

    allocator: Allocator,
    entries: std.ArrayList(Entry),

    const boiler_plate_top =
        \\#include <string.h>
        \\
        \\const char *
        \\bundler_get_content(const char *path, size_t *out_size)
        \\{
        \\  const char *result = NULL;
    ;

    const boiler_plate_bot =
        \\  return result;
        \\}
    ;

    pub fn init(allocator: Allocator) Bundler {
        return Bundler{ .allocator = allocator, .entries = std.ArrayList(Entry).init(allocator) };
    }

    pub fn deinit(self: Bundler) void {
        self.entries.deinit();
    }

    pub fn addEntry(self: *Bundler, path: []const u8) !void {
        const file = try fs.cwd().openFile(path, .{});
        defer file.close();

        // TODO: Maybe its not a good idea to load all files into memory
        const content = try file.readToEndAlloc(self.allocator, std.math.maxInt(usize));
        try self.entries.append(.{ .path = path, .content = content });
    }

    fn dumpEntry(allocator: Allocator, writer: Writer, entry: Entry, first: bool) !void {
        const keyword = if (first) "if" else "else if";
        try writer.print("  {s}(strcmp(path, \"{s}\") == 0)\n", .{ keyword, entry.path });
        try writer.print("  {{\n", .{});

        const cIdent = try validCIdentFromStr(allocator, entry.path);
        defer allocator.free(cIdent);

        try writer.print("    result = {s}_content;\n", .{cIdent});
        try writer.print("    *out_size = {s}_count;\n", .{cIdent});
        try writer.print("  }}\n", .{});
    }

    fn dumpEntryVars(allocator: Allocator, writer: Writer, entries: std.ArrayList(Entry)) !void {
        for (entries.items) |entry| {
            const cIdent = try validCIdentFromStr(allocator, entry.path);
            defer allocator.free(cIdent);
            try writer.print("#define {s}_count {}\n", .{ cIdent, entry.content.len });
            try writer.print("const char {s}_content[{s}_count] = {{", .{ cIdent, cIdent });
            for (entry.content) |char| {
                try writer.print("0x{X},", .{char});
            }
            try writer.print("}};\n", .{});
        }
    }

    fn bundleDirectory(self: *Bundler, path: []const u8) !void {
        var directory = fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
            stderr.print("Could not open directory: {s}\n", .{@errorName(err)}) catch {};
            return;
        };
        defer directory.close();

        var walker = try directory.walk(self.allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != fs.File.Kind.file) {
                continue;
            }

            const full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ path, entry.path });
            defer self.allocator.free(full_path);
            self.addEntry(full_path) catch |err| {
                stderr.print("Coult not add path: {s} to bundler: {s}\n", .{ full_path, @errorName(err) }) catch {};
                return;
            };
        }
    }

    pub fn bundle(self: *Bundler, path: []const u8) !void {
        const stat = try fs.cwd().statFile(path);
        if (stat.kind == fs.File.Kind.directory) {
            try self.bundleDirectory(path);
        } else if (stat.kind == fs.File.Kind.file) {
            try self.addEntry(path);
        } else {
            stderr.print("Cannot boundle file of type: {s}\n", .{@tagName(stat.kind)}) catch {};
        }
    }

    pub fn dump(self: Bundler, writer: Writer) !void {
        if (self.entries.items.len == 0) {
            return;
        }

        try dumpEntryVars(self.allocator, writer, self.entries);
        try writer.print("\n", .{});
        try writer.print("{s}\n", .{boiler_plate_top});
        try dumpEntry(self.allocator, writer, self.entries.items[0], true);
        if (self.entries.items.len > 1) {
            const rest = self.entries.items[1..];
            for (rest) |entry| {
                try dumpEntry(self.allocator, writer, entry, false);
            }
        }
        try writer.print("{s}\n", .{boiler_plate_bot});
    }
};

pub fn printUsage(program: []const u8) void {
    stderr.print("Usage: {s} [file | directory]\n", .{program}) catch {};
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);

    if (args.len < 2) {
        printUsage(args[0]);
        exit(1);
    }

    const input_path = args[1];
    var bundler = Bundler.init(allocator);
    try bundler.bundle(input_path);

    const outputFile = try fs.cwd().createFile("output.c", .{ .read = true });
    try bundler.dump(outputFile.writer());
}
