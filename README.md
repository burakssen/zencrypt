# zencrypt

`zencrypt` is a Zig streaming encryption library AES-256-GCM and XChaCha20-Poly1305, with chunked threaded processing for large
inputs and built-in stress test tooling.

## Features

- Streaming encryption and decryption via `std.Io.Reader` / `std.Io.Writer`
- AEAD algorithm support:
  - `aes` (`AES-256-GCM`)
  - `xchacha20` (`XChaCha20-Poly1305`)
- Chunk-based multithreaded processing in the cipher core
- Runtime stress tooling with performance and reliability phases

## Requirements

- Zig `0.15.2` or newer compatible with this project
  - `build.zig.zon` declares `.minimum_zig_version = "0.15.2"`

## Quick Start

Include it in your projects like this:

```bash
zig fetch --save git+https://github.com/burakssen/zencrypt
```

and on your `build.zig`

```zig
const zencrypt_mod = b.dependency("zencrypt", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("zencrypt", zencrypt_mod);
```

## Library Usage

```zig
const std = @import("std");
const zencrypt = @import("zencrypt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const message = "hello zencrypt";

    var cipher = try zencrypt.ZEncrypt.init(allocator, .aes, "my-password");
    defer cipher.deinit();

    var in_reader: std.Io.Reader = .fixed(message);
    var encrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_buf.deinit();
    try cipher.encrypt(&in_reader, &encrypted_buf.writer);

    var decryptor = try zencrypt.ZEncrypt.initForDecrypt(allocator, .aes, "my-password");
    defer decryptor.deinit();

    var enc_reader: std.Io.Reader = .fixed(encrypted_buf.written());
    var decrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_buf.deinit();
    try decryptor.decrypt(&enc_reader, &decrypted_buf.writer);
}
```

`ZEncryptType` options:

- `.aes`
- `.xchacha20`

## Build Steps

Available steps (`zig build -l`):

## Stress Testing

Stress runs are split into two timed phases:

- Performance phase:
  - roundtrip-focused
  - reports throughput
  - gate can enforce minimum throughput
- Reliability phase:
  - mixed payload roundtrips
  - tamper checks (ciphertext corruption must fail decryption)

Options:

- `-Dstress-seconds` (default `75`)
- `-Dstress-workers` (default `4`)
- `-Dstress-scale` (default `1`)
- `-Dstress-min-throughput-mib` (default `20.0`)

Sample test on M2 Pro Macbook with 16GB RAM

```text
zig build stress -Dstress-seconds=300 -Dstress-workers=8 -Dstress-scale=16
stress summary: workers=8 target_seconds=300 scale=16 elapsed=300.65s
performance phase: roundtrips=6694 bytes=262060113920 throughput=1041.33 MiB/s threshold=20.00 MiB/s
reliability phase: roundtrips=1137 tamper_checks=1137 bytes=6291061216 throughput=99.99 MiB/s failures=0
aes: perf_roundtrips=3348 perf_bytes=131113943040 reliability_roundtrips=567 tamper_checks=567 reliability_bytes=3111459584
xchacha20: perf_roundtrips=3346 perf_bytes=130946170880 reliability_roundtrips=570 tamper_checks=570 reliability_bytes=3179601632
```


## License

This project is licensed under MIT. See [`LICENCE`](LICENCE).
