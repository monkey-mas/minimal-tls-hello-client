const allocator = std.heap.page_allocator;
const mem = std.mem;
const net = std.net;
const std = @import("std");
const testing = std.testing;

const ArrayList = std.ArrayList;

const ClientHello = @import("handshake.zig").ClientHello;
const CipherSuite = @import("handshake.zig").CipherSuite;
const CompressionMethod = @import("handshake.zig").CompressionMethod;
const Extension = @import("extension.zig").Extension;
const HandshakeHeader = @import("handshake.zig").HandshakeHeader;
const HandshakeMessage = @import("handshake.zig").HandshakeMessage;
const HandshakeType = @import("handshake.zig").HandshakeType;
const TlsVersion = @import("handshake.zig").TlsVersion;

// This code does the following;
// a) connects to a server 127.0.0.1 with port 4443.
//    You can also try to connect to google.com(142.250.68.46:443) if you like ;)
// b) sends ClientHello to the server as the first packet of TLS1.3 handshake.
// c) expects to receive ServerHello from the server, but not to expect to handle
//    HelloRetryRequest.
// d) terminates :)
pub fn main() anyerror!void {
    // TODO: add error handling and deinit() stuff.

    const dest_address = "127.0.0.1";
    const server_address = try net.Address.parseIp4(dest_address, 4443);
    const socket = try net.tcpConnectToAddress(server_address);
    std.debug.print("[debug] Connecting to {s}.\n", .{dest_address});

    var client_hello = try create_client_hello();
    defer client_hello.deinit();

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    try client_hello.encode(writer);
    try socket.writer().writeAll(fixed_stream.getWritten());
    std.debug.print("[debug] Sending ClientHello...\n", .{});
    std.debug.print("[debug] {s}\n", .{client_hello});

    var server_hello: [1024]u8 = undefined;
    _ = try socket.reader().read(&server_hello);

    if (server_hello[0] == 0x16) { // Handshake
        if (server_hello[5] == 0x02) { // ServerHello
            std.debug.print("[debug] Successfully received ServerHello! \n", .{});
        } else {
            std.debug.print("[debug] Unexpected Handshake type [{}]: ServerHello was expected \n", .{server_hello[5]});
        }
    } else {
        std.debug.print("[debug] Unexpected Content Type [{}]: Handshake was expected \n", .{server_hello[0]});
    }
}

// Returns an encoded ClientHello packet.
// @throws Err if some operations fail.
fn create_client_hello() !ClientHello {
    // We'll create ClientHello in the order of
    // 1) Handshake message
    // 2) Handshake header
    // 3) ClientHello
    // Since we need to set the whole packet/message size to its corresponding
    // header field(a.k.a length), this order makes our life easier :-)

    // Handshake Message
    var hm = HandshakeMessage.init();

    hm.version = TlsVersion.tls_1_2; // For backward compatibility reason, this should be 1.2.

    // TODO: use a secure random number here instead of hard-coded random.
    hm.random = [32]u8{
        0xbd, 0xa2, 0x70, 0xa0, 0x39, 0x4c, 0xa3, 0xa9, 0x42, 0xe0, 0xb6, 0xd6, 0x25, 0xc9, 0x89, 0xbc,
        0x9b, 0xd9, 0xcd, 0xdf, 0x1d, 0x9e, 0x82, 0xd7, 0xca, 0x36, 0xed, 0x8c, 0x23, 0x3d, 0xd9, 0x8e,
    };

    hm.session_id_length = 32;
    // TODO: use a randomized session id.
    hm.session_id = [32]u8{
        0x01, 0xe6, 0xec, 0xde, 0xba, 0xa4, 0x19, 0x98, 0x84, 0x34, 0xc0, 0x5e, 0x4b, 0x4c, 0xd4, 0xa6,
        0x4b, 0xee, 0x9e, 0x06, 0x47, 0x1b, 0x3d, 0x0d, 0xf7, 0x51, 0x8d, 0x57, 0x12, 0xa8, 0x94, 0x74,
    };

    hm.cipher_suites_length = 8;
    try hm.cipher_suites.append(CipherSuite.tls_aes_256_gcm_sha384);
    try hm.cipher_suites.append(CipherSuite.tls_chacha20_poly1305_sha256);
    try hm.cipher_suites.append(CipherSuite.tls_aes_128_gcm_sha256);
    try hm.cipher_suites.append(CipherSuite.tls_empty_renegotiation_info_scsv);

    hm.compression_method_length = 1;
    try hm.compression_methods.append(CompressionMethod.null_type);

    // const server_name = Extension.server_name(address);
    const supported_groups = try Extension.supported_groups();
    const signature_algorithms = try Extension.signature_algorithms();
    const supported_versions = try Extension.supported_versions();
    const key_share = Extension.key_share();

    // try hm.add_extension(server_name);
    try hm.add_extension(supported_groups);
    try hm.add_extension(signature_algorithms);
    try hm.add_extension(supported_versions);
    try hm.add_extension(key_share);

    // Each extension has 4 bytes to hold fileds of extension_type(2) and length(2).
    hm.extension_length = supported_groups.header.length + 4 + signature_algorithms.header.length + 4 + supported_versions.header.length + 4 + key_share.header.length + 4;

    // Handshake Header
    const hh = HandshakeHeader.init(HandshakeType.client_hello, hm);

    var ch = ClientHello.init();
    ch.handshake_header = hh;
    ch.handshake_message = hm;
    ch.length = @truncate(u16, hh.length) + 4; // Handshake Type(1) + length(3);

    return ch;
}
