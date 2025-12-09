const std = @import("std");

const ze = @import("zencrypt");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var cryptor: ze.Cryptor = try ze.Cryptor.init(allocator, .Salsa20);

    const data = "Hello, Zig!" ** 10;

    std.debug.print("Original Data: {s}\n", .{data});

    var reader: std.Io.Reader = .fixed(data);
    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();

    const password = "my_secret_password";

    try cryptor.encrypt(&reader, &writer.writer, password);

    const encrypted_data = writer.written();
    std.debug.print("Encrypted Data: {s}\n", .{encrypted_data});

    var decrypt_reader: std.Io.Reader = .fixed(encrypted_data);
    var decrypt_writer: std.Io.Writer.Allocating = .init(allocator);
    defer decrypt_writer.deinit();

    try cryptor.decrypt(&decrypt_reader, &decrypt_writer.writer, password);

    const decrypted_data = decrypt_writer.written();
    std.debug.print("Decrypted Data: {s}\n", .{decrypted_data});
}
