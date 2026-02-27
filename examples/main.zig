const std = @import("std");
const zencrypt = @import("zencrypt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 5) {
        printUsage(args[0]);
        std.debug.print("got {} args, expected at least 4\n", .{args.len - 1});
        return error.InvalidArgs;
    }

    const algorithm = args[1];
    const password = args[2];
    const input_path = args[3];
    const output_path = args[4];

    const intermediate_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{input_path});
    defer allocator.free(intermediate_path);

    const algo_type: zencrypt.ZEncryptType = blk: {
        if (std.mem.eql(u8, algorithm, "aes")) break :blk .aes;
        if (std.mem.eql(u8, algorithm, "xchacha20")) break :blk .xchacha20;
        std.debug.print("error: unknown algorithm '{s}'. use 'aes' or 'xchacha20'\n", .{algorithm});
        return error.UnknownAlgorithm;
    };

    {
        const input_file = std.fs.cwd().openFile(input_path, .{}) catch |err| {
            std.debug.print("error: could not open input file '{s}': {}\n", .{ input_path, err });
            return err;
        };
        defer input_file.close();

        const intermediate_file = std.fs.cwd().createFile(intermediate_path, .{}) catch |err| {
            std.debug.print("error: could not create intermediate file '{s}': {}\n", .{ intermediate_path, err });
            return err;
        };
        defer intermediate_file.close();

        var read_buf: [4096]u8 = undefined;
        var in_reader = input_file.reader(&read_buf);
        var out_writer = intermediate_file.writer(&.{});

        var cipher = try zencrypt.ZEncrypt.init(allocator, algo_type, password);
        defer cipher.deinit();

        std.debug.print("encrypting '{s}' -> '{s}'...\n", .{ input_path, intermediate_path });
        try cipher.encrypt(&in_reader.interface, &out_writer.interface);

        const input_stat = try input_file.stat();
        const intermediate_stat = try intermediate_file.stat();
        std.debug.print("  original : {} bytes\n", .{input_stat.size});
        std.debug.print("  encrypted: {} bytes\n", .{intermediate_stat.size});
    }

    {
        const intermediate_file = std.fs.cwd().openFile(intermediate_path, .{}) catch |err| {
            std.debug.print("error: could not open intermediate file '{s}': {}\n", .{ intermediate_path, err });
            return err;
        };
        defer intermediate_file.close();

        const output_file = std.fs.cwd().createFile(output_path, .{}) catch |err| {
            std.debug.print("error: could not create output file '{s}': {}\n", .{ output_path, err });
            return err;
        };
        defer output_file.close();

        var read_buf: [4096]u8 = undefined;
        var in_reader = intermediate_file.reader(&read_buf);
        var out_writer = output_file.writer(&.{});

        var cipher = try zencrypt.ZEncrypt.init(allocator, algo_type, password);
        defer cipher.deinit();

        std.debug.print("decrypting '{s}' -> '{s}'...\n", .{ intermediate_path, output_path });
        try cipher.decrypt(&in_reader.interface, &out_writer.interface);

        const output_stat = try output_file.stat();
        std.debug.print("  decrypted: {} bytes\n", .{output_stat.size});
    }

    std.debug.print("done: '{s}' -> '{s}' -> '{s}'\n", .{ input_path, intermediate_path, output_path });
}

fn printUsage(exe: []const u8) void {
    std.debug.print(
        \\Usage: {s} <algorithm> <password> <input> <output>
        \\
        \\Algorithms:
        \\  aes        AES-256-GCM
        \\  xchacha20  XChaCha20-Poly1305
        \\
        \\Arguments:
        \\  password   encryption/decryption password
        \\  input      path to input file
        \\  output     path to output file (roundtrip result)
        \\
        \\Examples:
        \\  {s} aes mypassword plaintext.txt restored.txt
        \\  {s} xchacha20 mypassword photo.jpg restored.jpg
        \\
    , .{ exe, exe, exe });
}
