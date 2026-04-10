//! TLS protocol constants (aligned with Go `crypto/tls` / uTLS).

/// GREASE placeholder for cipher suites, curves, etc. (normalized form).
pub const GREASE_PLACEHOLDER: u16 = 0x0a0a;

pub const VERSION_TLS10: u16 = 0x0301;
pub const VERSION_TLS11: u16 = 0x0302;
pub const VERSION_TLS12: u16 = 0x0303;
pub const VERSION_TLS13: u16 = 0x0304;

pub const RECORD_TYPE_HANDSHAKE: u8 = 22;
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

pub const COMPRESSION_NONE: u8 = 0;

// —— TLS 1.2 cipher suites ——
pub const TLS_RSA_WITH_RC4_128_SHA: u16 = 0x0005;
pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x000a;
pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
pub const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;

pub const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: u16 = 0xc007;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
pub const TLS_ECDHE_RSA_WITH_RC4_128_SHA: u16 = 0xc011;
pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc012;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;

// TLS 1.3
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// Fake / legacy names used by uTLS parrots
pub const FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0033;
pub const FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0039;

// —— Named groups (curves) ——
pub const CURVE_P256: u16 = 0x0017;
pub const CURVE_P384: u16 = 0x0018;
pub const CURVE_P521: u16 = 0x0019;
pub const X25519: u16 = 0x001d;

pub const FAKE_FFDHE2048: u16 = 0x0100;
pub const FAKE_FFDHE3072: u16 = 0x0101;

// —— Signature schemes ——
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
pub const ECDSA_SHA1: u16 = 0x0203;
pub const RSA_PKCS1_SHA256: u16 = 0x0401;
pub const RSA_PKCS1_SHA384: u16 = 0x0501;
pub const RSA_PKCS1_SHA512: u16 = 0x0601;
pub const RSA_PKCS1_SHA1: u16 = 0x0201;
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;

// —— Extension types ——
pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_STATUS_REQUEST: u16 = 5;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_EC_POINT_FORMATS: u16 = 11;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;
pub const EXT_PADDING: u16 = 21;
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub const EXT_SESSION_TICKET: u16 = 35;
pub const EXT_PRE_SHARED_KEY: u16 = 41;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
pub const EXT_KEY_SHARE: u16 = 51;
pub const EXT_COMPRESS_CERTIFICATE: u16 = 27;
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

pub const FAKE_EXTENSION_CHANNEL_ID: u16 = 30032;
pub const UTLS_EXT_APPLICATION_SETTINGS: u16 = 17513;
pub const UTLS_EXT_APPLICATION_SETTINGS_NEW: u16 = 17613;

/// uTLS `fakeRecordSizeLimit` wire type (actually IANA `record_size_limit` = 28).
pub const EXT_RECORD_SIZE_LIMIT: u16 = 28;

pub const PSK_MODE_DHE: u8 = 1;

pub const POINT_FORMAT_UNCOMPRESSED: u8 = 0;

pub const RENEGOTIATE_ONCE_AS_CLIENT: u8 = 1;

/// Certificate compression: brotli (RFC 8879).
pub const CERT_COMPRESSION_BROTLI: u16 = 0x0002;
