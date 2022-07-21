const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const allocator = std.heap.page_allocator;
const ArrayList = std.ArrayList;

const Extension = @import("extension.zig").Extension;

pub const TlsRecordContentType = enum(u8) {
   handshake = 22,
};

pub const TlsVersion = enum(u16) {
    tls_1_0 = 0x0301,
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,
};

pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    tls_empty_renegotiation_info_scsv = 0x00ff,
};

pub const CompressionMethod = enum(u8) {
    null_type = 0x00,
};

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
};

pub const ClientHello = struct {
    content_type: TlsRecordContentType = TlsRecordContentType.handshake,
    version: TlsVersion = TlsVersion.tls_1_0,
    length: u16,
    handshake_header: HandshakeHeader,
    handshake_message: HandshakeMessage,

    pub fn init() ClientHello {
        return .{
            .length = undefined,
            .handshake_header = undefined,
            .handshake_message = undefined,
        };
    }

    pub fn deinit(self: *ClientHello) void {
        self.handshake_message.deinit();
    }

    pub fn encode(self: ClientHello, writer: anytype) !void {
        try writer.writeIntBig(u8, @enumToInt(self.content_type));
        try writer.writeIntBig(u16, @enumToInt(self.version));
        try writer.writeIntBig(u16, self.length);

        const encoded_header = self.handshake_header.encode();
        for (encoded_header) |value| {
            try writer.writeIntBig(u8, value);
        }
        try self.handshake_message.encode(writer);
    }

    fn decode(bytes: []const u8) !ClientHello {
        var ch = ClientHello.init();

        ch.content_type = @intToEnum(TlsRecordContentType, mem.readIntBig(u8, &bytes[0]));
        ch.version = @intToEnum(TlsVersion, mem.readIntBig(u16, bytes[1..3]));
        ch.length = mem.readIntBig(u16, bytes[3..5]);
        ch.handshake_header = HandshakeHeader.decode(bytes[5..9]);
        ch.handshake_message = try HandshakeMessage.decode(bytes[9..]);

        return ch;
    }
};

test "Client Hello" {
    const bytes = [_]u8{
        // Content Type: Handshake
        0x16,
        // Version
        0x03, 0x01,
        // TLS Record Length 203
        0x00, 0xcb,
        // Handshake Type: Client Hello
        0x01,
        // Length 199
        0x00, 0x00, 0xc7,
        // Version
        0x03, 0x03,
        // Random
        0xbd, 0xa2, 0x70, 0xa0, 0x39, 0x4c, 0xa3, 0xa9, 0x42, 0xe0, 0xb6, 0xd6, 0x25, 0xc9, 0x89, 0xbc,
        0x9b, 0xd9, 0xcd, 0xdf, 0x1d, 0x9e, 0x82, 0xd7, 0xca, 0x36, 0xed, 0x8c, 0x23, 0x3d, 0xd9, 0x8e,
        // Session ID length
        0x20,
        // Session ID
        0x01, 0xe6, 0xec, 0xde, 0xba, 0xa4, 0x19, 0x98, 0x84, 0x34, 0xc0, 0x5e, 0x4b, 0x4c, 0xd4, 0xa6, 
        0x4b, 0xee, 0x9e, 0x06, 0x47, 0x1b, 0x3d, 0x0d, 0xf7, 0x51, 0x8d, 0x57, 0x12, 0xa8, 0x94, 0x74,
        // Cipher Suites Length
        0x00, 0x08,
        // Cipher Suites
        0x13, 0x02,
        0x13, 0x03,
        0x13, 0x01,
        0x00, 0xff,
        // Compression Method Length
        0x01,
        // Compression Methods
        0x00,
        // Extension Length (118)
        0x00, 0x76,

        // Server Name
        // Extension Type
        0x00, 0x00,
        // Length
        0x00, 0x0f,
        // Server Name list length
        0x00, 0x0d,
        // Server Name Type
        0x00,
        // Server Name Length
        0x00, 0x0a,
        // Server Name
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,

        // Supported Groups
        // Extension Type
        0x00, 0x0a,
        // Length
        0x00, 0x0c,
        // List Length
        0x00, 0x0a,
        // Supported Groups
        0x00, 0x1d, // x25519
        0x00, 0x17,
        0x00, 0x1e,
        0x00, 0x19,
        0x00, 0x18,

        // Signature Algorithm
        // Extension Type
        0x00, 0x0d,
        // Length
        0x00, 0x1e,
        // Signature Algorithms Length
        0x00, 0x1c,
        // Signature Algorithms
        0x04, 0x03,
        0x05, 0x03,
        0x06, 0x03,
        0x08, 0x07,
        0x08, 0x08,
        0x08, 0x09,
        0x08, 0x0a,
        0x08, 0x0b,
        0x08, 0x04,
        0x08, 0x05,
        0x08, 0x06,
        0x04, 0x01,
        0x05, 0x01,
        0x06, 0x01,

        // Supported Version
        // Extension Type
        0x00, 0x2b,
        // Length
        0x00, 0x03,
        // Supported Versions Length
        0x02,
        // Supported Versions
        0x03, 0x04, // TLS1.3

        // Key Share
        // Extension Type
        0x00, 0x33,
        // Length
        0x00, 0x26,
        // Key Share Length
        0x00, 0x24,
        // Group
        0x00, 0x1d,
        // Key Exchange Length
        0x00, 0x20,
        // Key Exchange
        0x1c, 0xdc, 0x20, 0x04, 0x75, 0xd4, 0x5c, 0x85,
        0x9f, 0xeb, 0xa8, 0x4d, 0x52, 0x59, 0x8c, 0xe4,
        0xdb, 0x07, 0x70, 0xb7, 0xd4, 0x43, 0x86, 0xb0,
        0xae, 0xbb, 0xee, 0x60, 0x1d, 0x3d, 0xe4, 0x61,
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const ch = try ClientHello.decode(bytes[0..]);
    try ch.encode(writer);
    const actual = fixed_stream.getWritten();
    try testing.expect(mem.eql(u8, actual, &bytes));
}

pub const HandshakeHeader = struct {
    handshake_type: HandshakeType,
    // Note: this is the size of a message(body) without including the size of header itself.
    //       you need to add 4 bytes to have the whole size!
    length: u24,

    pub fn init(handshakeType: HandshakeType, handshakeMessage: HandshakeMessage) HandshakeHeader {
        const length = 2 // TLS version
            + 32 // Random
            + 1 // Session ID Length
            + handshakeMessage.session_id_length // Session ID
            + 2 // Cipher Suites Length
            + handshakeMessage.cipher_suites_length // Cipher Suites
            + 1 // Compression Methods Length
            + handshakeMessage.compression_method_length // Compression Methods
            + 2 // Extension Length
            + handshakeMessage.extension_length; // Extensions

        return .{
            .handshake_type = handshakeType,
            .length = length,
        };
    }

    fn encode(self: HandshakeHeader) [4]u8 {
        var buf: [4]u8 = undefined;
        buf[0] = @enumToInt(self.handshake_type);
        mem.writeIntBig(u24, buf[1..4], self.length);
        return buf;
    }

    fn decode(bytes: []const u8) HandshakeHeader {
        return .{
            .handshake_type = @intToEnum(HandshakeType, bytes[0]),
            .length = mem.readIntBig(u24, bytes[1..4]),
        };
    }
};

test "Handshake Header" {
    const bytes = [_]u8{
        // Handshake Type: ClientHello
        0x01,
        // Length,
        0x00, 0x00, 0xf7,
    };

    const hh = HandshakeHeader.decode(bytes[0..]);
    const b = hh.encode();
    try testing.expectEqual(b, bytes);
}

pub const HandshakeMessage = struct {
    version: TlsVersion,
    random: [32]u8,
    session_id_length: u8 = 32,
    session_id: [32]u8,
    cipher_suites_length: u16,
    cipher_suites: ArrayList(CipherSuite),
    compression_method_length: u8,
    compression_methods: ArrayList(CompressionMethod),
    extension_length: u16,
    extensions: ArrayList(Extension),

    pub fn init() HandshakeMessage {
        return .{
            .version = undefined,
            .random = undefined,
            .session_id_length = undefined,
            .session_id = undefined,
            .cipher_suites_length = undefined,
            .cipher_suites = ArrayList(CipherSuite).init(allocator),
            .compression_method_length = undefined,
            .compression_methods = ArrayList(CompressionMethod).init(allocator),
            .extension_length = undefined,
            .extensions = ArrayList(Extension).init(allocator),
        };
    }

    fn deinit(self: *HandshakeMessage) void {
        self.cipher_suites.deinit();
        self.compression_methods.deinit();
        self.extensions.deinit();
    }

    pub fn add_extension(self: *HandshakeMessage, extension: Extension) !void {
        try self.extensions.append(extension);
    }

    fn encode(self: HandshakeMessage, writer: anytype) !void {
        try writer.writeIntBig(u16, @enumToInt(self.version));

        // Random
        for (self.random) |value| {
            try writer.writeIntBig(u8, value);
        }

        // Session ID Length
        try writer.writeIntBig(u8, self.session_id_length);

        // Session ID
        for (self.session_id) |value| {
           try writer.writeIntBig(u8, value);
        }

        // Cipher Suites Length
        try writer.writeIntBig(u16, self.cipher_suites_length);

        // Cipher Suites
        for (self.cipher_suites.items) |cipher_suite| {
            try writer.writeIntBig(u16, @enumToInt(cipher_suite));
        }

        // Compression Method
        try writer.writeIntBig(u8, self.compression_method_length);
        for (self.compression_methods.items) |compression_method| {
            try writer.writeIntBig(u8, @enumToInt(compression_method));
        }

        // Extension
        try writer.writeIntBig(u16, self.extension_length);
        for (self.extensions.items) |extension| {
            try extension.encode(writer);
        }
    }

    fn decode(bytes: []const u8) !HandshakeMessage {
        var hm = HandshakeMessage.init();
        hm.version = @intToEnum(TlsVersion, mem.readIntBig(u16, bytes[0..2]));
        hm.random = bytes[2..34].*; //ref. https://stackoverflow.com/a/70102927
        hm.session_id_length = bytes[34];
        hm.session_id = bytes[35..67].*;
        hm.cipher_suites_length = mem.readIntBig(u16, bytes[67..69]);

        // Cipher Suite
        const cipher_suites_length = mem.readIntBig(u16, bytes[67..69]);
        var index: u16 = 69;
        var cipher_suite_index: u8 = 0;
        while (cipher_suite_index < cipher_suites_length/2) {
            var cs_bytes: [2]u8 = undefined;
            cs_bytes[0] = bytes[index];
            cs_bytes[1] = bytes[index+1];
            // FIXME: use the following instead. Currently 'somehow' other test cases impact this,
            //        and got thread panic...
            // const csb = @ptrCast(*const [2]u8, @alignCast(2, bytes[index..index+2].ptr));
            const cipher_suite = @intToEnum(CipherSuite, mem.readIntBig(u16, &cs_bytes));
            try hm.cipher_suites.append(cipher_suite);
            index += 2;
            cipher_suite_index += 1;
        }
        hm.cipher_suites_length = cipher_suites_length;

        //  Compression Method
        const compression_method_length = bytes[index];
        hm.compression_method_length = compression_method_length;

        index += 1;
        var compression_method_index: u8 = 0;
        while (compression_method_index < compression_method_length) {
            const compression_method = @intToEnum(CompressionMethod, mem.readIntBig(u8, &bytes[index]));
            try hm.compression_methods.append(compression_method);

            index += 1;
            compression_method_index += 1;
        }

        // Extension
        var el_bytes: [2]u8 = undefined;
        el_bytes[0] = bytes[index];
        el_bytes[1] = bytes[index+1];
        const extension_length = mem.readIntBig(u16, &el_bytes);
        index += 2;

        var extension_index: u16 = 0;
        while (extension_index < extension_length) {
            const offset = index + extension_index;
            const extension: Extension = try Extension.decode(bytes[offset..]);
            try hm.extensions.append(extension);

            const extension_size = extension.header.length;
            extension_index += extension_size + 4; // extension has its header size as well, which is 4 bytes.
        }
        hm.extension_length = extension_length;

        return hm;
    }
};

test "Handshake Message" {
    const bytes = [_]u8{
        // Version
        0x03, 0x03,
        // Random
        0xbd, 0xa2, 0x70, 0xa0, 0x39, 0x4c, 0xa3, 0xa9, 0x42, 0xe0, 0xb6, 0xd6, 0x25, 0xc9, 0x89, 0xbc,
        0x9b, 0xd9, 0xcd, 0xdf, 0x1d, 0x9e, 0x82, 0xd7, 0xca, 0x36, 0xed, 0x8c, 0x23, 0x3d, 0xd9, 0x8e,
        // Session ID length
        0x20,
        // Session ID
        0x01, 0xe6, 0xec, 0xde, 0xba, 0xa4, 0x19, 0x98, 0x84, 0x34, 0xc0, 0x5e, 0x4b, 0x4c, 0xd4, 0xa6, 
        0x4b, 0xee, 0x9e, 0x06, 0x47, 0x1b, 0x3d, 0x0d, 0xf7, 0x51, 0x8d, 0x57, 0x12, 0xa8, 0x94, 0x74,
        // Cipher Suites Length
        0x00, 0x08,
        // Cipher Suites
        0x13, 0x02,
        0x13, 0x03,
        0x13, 0x01,
        0x00, 0xff,
        // Compression Method Length
        0x01,
        // Compression Methods
        0x00,
        // Extension Length (118)
        0x00, 0x76,

        // Server Name
        // Extension Type
        0x00, 0x00,
        // Length
        0x00, 0x0f,
        // Server Name list length
        0x00, 0x0d,
        // Server Name Type
        0x00,
        // Server Name Length
        0x00, 0x0a,
        // Server Name
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,

        // Supported Groups
        // Extension Type
        0x00, 0x0a,
        // Length
        0x00, 0x0c,
        // List Length
        0x00, 0x0a,
        // Supported Groups
        0x00, 0x1d, // x25519
        0x00, 0x17,
        0x00, 0x1e,
        0x00, 0x19,
        0x00, 0x18,

        // Signature Algorithm
        // Extension Type
        0x00, 0x0d,
        // Length
        0x00, 0x1e,
        // Signature Algorithms Length
        0x00, 0x1c,
        // Signature Algorithms
        0x04, 0x03,
        0x05, 0x03,
        0x06, 0x03,
        0x08, 0x07,
        0x08, 0x08,
        0x08, 0x09,
        0x08, 0x0a,
        0x08, 0x0b,
        0x08, 0x04,
        0x08, 0x05,
        0x08, 0x06,
        0x04, 0x01,
        0x05, 0x01,
        0x06, 0x01,

        // Supported Version
        // Extension Type
        0x00, 0x2b,
        // Length
        0x00, 0x03,
        // Supported Versions Length
        0x02,
        // Supported Versions
        0x03, 0x04, // TLS1.3

        // Key Share
        // Extension Type
        0x00, 0x33,
        // Length
        0x00, 0x26,
        // Key Share Length
        0x00, 0x24,
        // Group
        0x00, 0x1d,
        // Key Exchange Length
        0x00, 0x20,
        // Key Exchange
        0x1c, 0xdc, 0x20, 0x04, 0x75, 0xd4, 0x5c, 0x85,
        0x9f, 0xeb, 0xa8, 0x4d, 0x52, 0x59, 0x8c, 0xe4,
        0xdb, 0x07, 0x70, 0xb7, 0xd4, 0x43, 0x86, 0xb0,
        0xae, 0xbb, 0xee, 0x60, 0x1d, 0x3d, 0xe4, 0x61,
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const h = try HandshakeMessage.decode(bytes[0..]);

    try h.encode(writer);
    const actual = fixed_stream.getWritten();
    try testing.expect(mem.eql(u8, actual, &bytes));
}