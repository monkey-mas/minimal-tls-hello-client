const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const allocator = std.heap.page_allocator;
const ArrayList = std.ArrayList;

const TlsVersion = @import("handshake.zig").TlsVersion;

// TODO: implement more extention types.
const ExtensionType = enum(u16) {
    server_name = 0x0000,
    supported_groups = 0x000a,
    signature_algorithms = 0x000d,
    supported_versions = 0x002b,
    key_share = 0x33,
};

pub const Extension = struct {
    header: ExtensionHeader,
    payload: ExtensionPayload,

    fn init(payload: ExtensionPayload, extension_type: ExtensionType) Extension {
        return .{
            .header = ExtensionHeader.init(payload, extension_type),
            .payload = payload,
        };
    }

    // Following functions are used to init a specific extension payload with a header.
    pub fn server_name(address: []const u8) Extension {
        const payload = ServerName.init(address);
        return Extension.init(ExtensionPayload{ .server_name = payload }, ExtensionType.server_name);
    }

    pub fn supported_groups() !Extension {
        var payload = SupportedGroups.init();
        payload.list_length = 10;
        // FIXME: we currenly use x25519 only for Key Share...
        try payload.supported_groups.append(NameGroup.x25519);
        try payload.supported_groups.append(NameGroup.secp256r1);
        try payload.supported_groups.append(NameGroup.x448);
        try payload.supported_groups.append(NameGroup.secp521r1);
        try payload.supported_groups.append(NameGroup.secp384r1);
        return Extension.init(ExtensionPayload{ .supported_groups = payload }, ExtensionType.supported_groups);
    }

    pub fn signature_algorithms() !Extension {
        var payload = SignatureAlgorithms.init();
        payload.signature_hash_algorithms_length = 28;
        // FIXME: implement more to handle other algorithms as well.
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.ecdsa_secp256r1_sha256);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.ecdsa_secp384r1_sha384);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.ecdsa_secp521r1_sha512);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.ed25519);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.ed448);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pss_pss_sha256);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pss_pss_sha384);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pss_pss_sha512);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pss_rsae_sha256);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pss_rsae_sha384);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pss_rsae_sha512);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pkcs1_sha256);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pkcs1_sha384);
        try payload.signature_hash_algorithms.append(SignatureAlgorithm.rsa_pkcs1_sha512);

        return Extension.init(ExtensionPayload{ .signature_algorithms = payload }, ExtensionType.signature_algorithms);
    }

    pub fn supported_versions() !Extension {
        var payload = SupportedVersions.init();
        // FIXME: we only handle TLS 1.3 just for now.
        payload.supported_versions_length = 2;
        try payload.supported_versions.append(TlsVersion.tls_1_3);
        return Extension.init(ExtensionPayload{ .supported_versions = payload }, ExtensionType.supported_versions);
    }

    pub fn key_share() Extension {
        var payload = KeyShare.init();
        // TODO: fix this with 'real' crypto by using curve25519 with a client private key for example.
        //       currently this is just hardcoded...
        payload.client_key_share_length = 36;
        payload.group = NameGroup.x25519;
        payload.key_exchange_length = 32;
        payload.key_exchange = [32]u8 {
            0x1c, 0xdc, 0x20, 0x04, 0x75, 0xd4, 0x5c, 0x85,
            0x9f, 0xeb, 0xa8, 0x4d, 0x52, 0x59, 0x8c, 0xe4,
            0xdb, 0x07, 0x70, 0xb7, 0xd4, 0x43, 0x86, 0xb0,
            0xae, 0xbb, 0xee, 0x60, 0x1d, 0x3d, 0xe4, 0x61,   
        };
        return Extension.init(ExtensionPayload{ .key_share = payload }, ExtensionType.key_share);
    }

    // Returns encoded bytes of an extension.
    // @param extension: extension to be encoded.
    // @param writer: stream to store encoded bytes.
    pub fn encode(self: Extension, writer: anytype) !void {
        const header_bytes = self.header.encode();
        for (header_bytes) |value| {
            try writer.writeIntBig(u8, value);
        }

        switch (self.payload) {
            .server_name => {
                try self.payload.server_name.encode(writer);
            },
            .supported_groups => {
                try self.payload.supported_groups.encode(writer);
            },
            .signature_algorithms => {
                try self.payload.signature_algorithms.encode(writer);
            },
            .supported_versions => {
                try self.payload.supported_versions.encode(writer);
            },
            .key_share => {
                try self.payload.key_share.encode(writer);
            },
            // else => unreachable, // TODO: implement more extension types.
        }
    }

    // Returns a decoded extension.
    // @param bytes: payload of extensions.
    pub fn decode(bytes: []const u8) !Extension {
        const extension_type = @intToEnum(ExtensionType, mem.readIntBig(u16, bytes[0..2]));
        const length = mem.readIntBig(u16, bytes[2..4]);
    
        var payload: ExtensionPayload = undefined;
        const payload_bytes = bytes[4..]; // offset for extension_type(2) + length(2);
        switch (extension_type) {
            ExtensionType.server_name => payload = ExtensionPayload{ .server_name = ServerName.decode(payload_bytes) },
            ExtensionType.supported_groups => payload = ExtensionPayload{ .supported_groups = try SupportedGroups.decode(payload_bytes) },
            ExtensionType.signature_algorithms => payload = ExtensionPayload{ .signature_algorithms = try SignatureAlgorithms.decode(payload_bytes) },
            ExtensionType.supported_versions => payload = ExtensionPayload{ .supported_versions = try SupportedVersions.decode(payload_bytes) },
            ExtensionType.key_share => payload = ExtensionPayload{ .key_share = KeyShare.decode(payload_bytes) },
            // else => unreachable, // TODO: implement more extension types.
        }
    
        return Extension {
            .header = ExtensionHeader {
                .extension_type = extension_type,
                .length = length,
            },
            .payload = payload
        };
    }
};

test "Extension" {
    // Decode and encode ServerName extension.
    const bytes = [_]u8{
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
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const e = try Extension.decode(bytes[0..]);
    try e.encode(writer);
    const actual = fixed_stream.getWritten();

    try testing.expect(mem.eql(u8, actual, &bytes));
}

const ExtensionHeader = struct {
    extension_type: ExtensionType,
    length: u16,

    fn init(extension_payload: ExtensionPayload, extension_type: ExtensionType) ExtensionHeader {
        return ExtensionHeader {
            .extension_type = extension_type,
            // The total size(length) of extension payload is set in header field.
            .length = @truncate(u16, extension_payload.length()),
        };
    }

    fn encode(self: ExtensionHeader) [4]u8 {
        var buf: [4]u8 = undefined;
        
        mem.writeIntBig(u16, buf[0..2], @enumToInt(self.extension_type));
        mem.writeIntBig(u16, buf[2..4], self.length);

        return buf;
    }

    fn decode(bytes: [4]u8) ExtensionHeader {
        return .{
            .extension_type = @intToEnum(ExtensionType, mem.readIntBig(u16, bytes[0..2])),
            .length = mem.readIntBig(u16, bytes[2..4]),
        };
    }
};

const ExtensionPayload = union(ExtensionType) {
    server_name: ServerName,
    supported_groups: SupportedGroups,
    signature_algorithms: SignatureAlgorithms,
    supported_versions: SupportedVersions,
    key_share: KeyShare,

    // Returns the total 'length' of extension payload, which is SET in header's 'length' field,
    // Note that this value doesn't include the additional size of a corresponding header fields.
    fn length(self: ExtensionPayload) usize {
        switch (self) {
            .server_name => |sn| {
                return sn.list_length + 2; // length of list_length field is 2 bytes.
            },
            .supported_groups => |sg| {
                return sg.list_length + 2; // length of list_length field is 2 bytes.
            },
            .signature_algorithms => |sa| {
                return sa.signature_hash_algorithms_length + 2; // length of hash algorithm length field is 2 bytes.
            },
            .supported_versions => |sv| {
                return sv.supported_versions_length + 1; // length of supported version length field is 1 byte1.
            },
            .key_share => |ks| {
                return ks.client_key_share_length + 2; // length of list_length field is 2 bytes.
            },
        }
    }
};

const ServerNameType = enum(u8) {
    host = 0x00,
};

const ServerName = struct {
    list_length: u16,
    server_name_type: ServerNameType,
    server_name_length: u16,
    server_name: []const u8,

    fn init(server_name: []const u8) ServerName {
        const server_name_length = @truncate(u16, server_name.len);
        return .{
            .list_length = 3 + server_name_length,
            .server_name_type = ServerNameType.host, // FIXME: if necessary...
            .server_name_length = server_name_length,
            .server_name = server_name,
        };
    }

    fn encode(self: ServerName, writer: anytype) !void {
        try writer.writeIntBig(u16, self.list_length);
        try writer.writeIntBig(u8, @enumToInt(self.server_name_type));
        try writer.writeIntBig(u16, self.server_name_length);
        for (self.server_name) |value| {
            try writer.writeIntBig(u8, value);
        }
    }

    fn decode(bytes: []const u8) ServerName {
        const server_name_length = mem.readIntBig(u16, bytes[3..5]);

        return .{
            .list_length = mem.readIntBig(u16, bytes[0..2]),
            .server_name_type = @intToEnum(ServerNameType, bytes[2]),
            .server_name_length = server_name_length,
            .server_name = bytes[5..5 + server_name_length],
        };
    }
};

test "ServerName" {
    // Testing decode and encode
    const bytes = [_]u8{
        // List Length
        0x00, 0x0d,
        // Server Name Type
        0x00,
        // Server Name Length
        0x00, 0x0a,
        // Server Name: "google.com"
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const sn = ServerName.decode(bytes[0..]);
    try sn.encode(writer);
    const actual = fixed_stream.getWritten();

    try testing.expect(mem.eql(u8, actual, &bytes));


    // Testing init(...)
    var buffer2: [1024]u8 = undefined;
    var fixed_stream2 = std.io.fixedBufferStream(&buffer2);
    const writer2 = fixed_stream2.writer();

    const sn2 = ServerName.init("google.com");
    try sn2.encode(writer2);
    const actual2 = fixed_stream2.getWritten();
    try testing.expect(mem.eql(u8, actual2, &bytes));
}

const NameGroup = enum(u16) {
    x25519 = 0x001d,
    secp256r1 = 0x0017,
    x448 = 0x001e,
    secp521r1 = 0x0019,
    secp384r1 = 0x0018,
};

const SupportedGroups = struct {
    list_length: u16,
    supported_groups: ArrayList(NameGroup),

    fn init() SupportedGroups {
        return .{
            .list_length = undefined,
            .supported_groups = ArrayList(NameGroup).init(allocator),
        };
    }

    fn deinit(self: *SupportedGroups) void {
        self.supported_groups.deinit();
    }

    fn encode(self: SupportedGroups, writer: anytype) !void {
        try writer.writeIntBig(u16, self.list_length);
        for (self.supported_groups.items) |supported_group| {
            try writer.writeIntBig(u16, @enumToInt(supported_group)); 
        }
    }

    fn decode(bytes: []const u8) !SupportedGroups {
        var supported_groups = SupportedGroups.init();

        const list_length = mem.readIntBig(u16, bytes[0..2]);
        supported_groups.list_length = list_length;

        var index: u8 = 2;
        var count: u8 = 0;
        while (count < list_length/2) {
            var buf: [2]u8 = undefined;
            buf[0] = bytes[index];
            buf[1] = bytes[index+1];
            const supported_group = @intToEnum(NameGroup, mem.readIntBig(u16, &buf));
            try supported_groups.supported_groups.append(supported_group);

            index += 2;
            count += 1;
        }

        return supported_groups;
    }
};

test "Supported Groups" {
    const bytes = [_]u8{
        // List Length
        0x00, 0x0a,
        // Supported Groups
        0x00, 0x1d, // x25519
        0x00, 0x17,
        0x00, 0x1e,
        0x00, 0x19,
        0x00, 0x18,
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const sg = try SupportedGroups.decode(bytes[0..]);
    try sg.encode(writer);
    const actual = fixed_stream.getWritten();

    try testing.expect(mem.eql(u8, actual, &bytes));
}

const SignatureAlgorithm = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
};

const SignatureAlgorithms = struct {
    signature_hash_algorithms_length: u16,
    signature_hash_algorithms: ArrayList(SignatureAlgorithm),

    fn init() SignatureAlgorithms {
        return .{
            .signature_hash_algorithms_length = undefined,
            .signature_hash_algorithms = ArrayList(SignatureAlgorithm).init(allocator),
        };
    }

    fn deinit(self: *SignatureAlgorithms) void {
        self.supported_groups.deinit();
    }

    fn encode(self: SignatureAlgorithms, writer: anytype) !void {
        try writer.writeIntBig(u16, self.signature_hash_algorithms_length);
        for (self.signature_hash_algorithms.items) |signature_hash_algorithm| {
            try writer.writeIntBig(u16, @enumToInt(signature_hash_algorithm)); 
        }
    }

    fn decode(bytes: []const u8) !SignatureAlgorithms {
        var sas = SignatureAlgorithms.init();

        const length = mem.readIntBig(u16, bytes[0..2]);
        sas.signature_hash_algorithms_length = length;

        var index: u8 = 2;
        var count: u8 = 0;
        while (count < length/2) {
            var buf: [2]u8 = undefined;
            buf[0] = bytes[index];
            buf[1] = bytes[index+1];
            const signature_algorithm = @intToEnum(SignatureAlgorithm, mem.readIntBig(u16, &buf));
            try sas.signature_hash_algorithms.append(signature_algorithm);

            index += 2;
            count += 1;
        }

        return sas;
    }
};

test "Signature Algorithms" {
    const bytes = [_]u8{
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
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const sas = try SignatureAlgorithms.decode(bytes[0..]);
    try sas.encode(writer);
    const actual = fixed_stream.getWritten();

    try testing.expect(mem.eql(u8, actual, &bytes));
}

const SupportedVersions = struct {
    supported_versions_length: u8,
    supported_versions: ArrayList(TlsVersion),

    fn init() SupportedVersions {
        return .{
            .supported_versions_length = undefined,
            .supported_versions = ArrayList(TlsVersion).init(allocator),
        };
    }

    fn deinit(self: *SupportedVersions) void {
        self.supported_versions.deinit();
    }

    fn encode(self: SupportedVersions, writer: anytype) !void {
        try writer.writeIntBig(u8, self.supported_versions_length);
        for (self.supported_versions.items) |supported_version| {
            try writer.writeIntBig(u16, @enumToInt(supported_version)); 
        }
    }

    fn decode(bytes: []const u8) !SupportedVersions {
        var sv = SupportedVersions.init();

        const length = mem.readIntBig(u8, &bytes[0]);
        sv.supported_versions_length = length;

        var index: u8 = 1;
        var count: u8 = 0;
        while (count < length/2) {
            var buf: [2]u8 = undefined;
            buf[0] = bytes[index];
            buf[1] = bytes[index+1];
            const supported_version = @intToEnum(TlsVersion, mem.readIntBig(u16, &buf));
            try sv.supported_versions.append(supported_version);

            index += 2;
            count += 1;
        }

        return sv;
    }
};

test "Supported Versions" {
    const bytes = [_]u8{
        // Supported Versions Length
        0x02,
        // Supported Versions
        0x03, 0x04, // TLS1.3
    };

    var buffer: [1024]u8 = undefined;
    var fixed_stream = std.io.fixedBufferStream(&buffer);
    const writer = fixed_stream.writer();

    const sv = try SupportedVersions.decode(bytes[0..]);
    try sv.encode(writer);
    const actual = fixed_stream.getWritten();
    try testing.expect(mem.eql(u8, actual, &bytes));
}

const KeyShare = struct {
    client_key_share_length: u16,
    group: NameGroup,
    key_exchange_length: u16 = 32,
    key_exchange: [32]u8,

    fn init() KeyShare {
        return .{
            .client_key_share_length = undefined,
            .group = undefined,
            .key_exchange = undefined
        };
    }

    fn deinit(self: *KeyShare) void {
        self.supported_versions.deinit();
    }

    fn encode(self: KeyShare, writer: anytype) !void {
        try writer.writeIntBig(u16, self.client_key_share_length);
        try writer.writeIntBig(u16, @enumToInt(self.group)); 
        try writer.writeIntBig(u16, self.key_exchange_length);
        for (self.key_exchange) |value| {
            try writer.writeIntBig(u8, value); 
        }
    }

    fn decode(bytes: []const u8) KeyShare {
        var ks = KeyShare.init();

        ks.client_key_share_length = mem.readIntBig(u16, bytes[0..2]);
        ks.group = @intToEnum(NameGroup, mem.readIntBig(u16, bytes[2..4]));
        const key_exchange_length = mem.readIntBig(u16, bytes[4..6]);
        ks.key_exchange_length = key_exchange_length;

        const offset = 6;
        var index: u8 = 0;
        var key_exchange: [32]u8 = undefined;
        while (index < key_exchange_length) : (index += 1) {
            key_exchange[index] = mem.readIntBig(u8, &bytes[offset+index]);
        }
        ks.key_exchange = key_exchange;

        return ks;
    }
};

test "Key Share" {
    const bytes = [_]u8{
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

    const ks = KeyShare.decode(bytes[0..]);
    try ks.encode(writer);
    const actual = fixed_stream.getWritten();
    try testing.expect(mem.eql(u8, actual, &bytes));
}
