Place `libbibavpn_ffi.a` here before archiving for device builds:

```bash
# From repo root (macOS), release + device:
rustup target add aarch64-apple-ios
cargo build -p bibavpn-ffi --release --target aarch64-apple-ios
mkdir -p apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/BibaVpnTunnel/rust-static/Release-iphoneos
cp target/aarch64-apple-ios/release/libbibavpn_ffi.a \
   apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/BibaVpnTunnel/rust-static/Release-iphoneos/
```

For Debug configs copy into `Debug-iphoneos/` accordingly.

Simulator builds need `aarch64-apple-ios-sim` (or `x86_64-apple-ios`) libraries separately — use Xcode destination **generic/iOS device** until simulator linkage is wired.
