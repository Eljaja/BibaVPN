# iOS VPN extras (merge into `gen/apple` after `tauri ios init`)

This folder mirrors [`android-bibavpn-extras`](../android-bibavpn-extras): Network Extension + Rust FFI.

**Current status:** tunnel start **fails** after SOCKS bind until Tun2socks (or
equivalent) wires `packetFlow` / TUN fd forwarding in
`PacketTunnelProvider.completeTunnelForwarding`. The gomobile Tun2socks script
below remains a follow-up — the extension does not route traffic yet.

## Prerequisites

- macOS with Xcode + Apple Developer Program (**Personal VPN** + **Network Extension** entitlements on the main app).
- [`bibavpn_ffi.h`](../../../bibavpn-ffi/include/bibavpn_ffi.h) copied into `BibaVpnTunnel/include/` (handled by [`integrate-bibavpn-into-tauri-ios.sh`](../../../../scripts/integrate-bibavpn-into-tauri-ios.sh)).
- Static library [`libbibavpn_ffi.a`](./BibaVpnTunnel/rust-static/README.md) for `aarch64-apple-ios` (device).

## Tun2socks

```bash
bash apps/scripts/build-tun2socks-ios-gomobile.sh
```

Adds `Tun2socks.xcframework` under `Frameworks/`. Wire symbols inside `PacketTunnelProvider.completeTunnelForwarding` once API names are confirmed (`gomobile bind` output).

## Bootstrap

From repo root:

```bash
cd apps/bibavpn-desktop
npm run ios:bootstrap   # tauri ios init + integrate script + UI build (see package.json)
```

Then open `src-tauri/gen/apple/*.xcodeproj` (or regenerate via XcodeGen) and fix signing / capabilities:

- Main app: App Group `group.dev.bibavpn.desktop`, Network Extensions → Packet Tunnel + Personal VPN.
- Extension bundle id: `dev.bibavpn.desktop.BibaVpnTunnel` (must match Swift constants).

## XcodeGen merge

[`merge_bibavpn_ios_project.py`](../../../../scripts/merge_bibavpn_ios_project.py) patches `gen/apple/project.yml` (requires `pip install pyyaml`). Re-run after each `tauri ios init` if Tauri regenerates the file.
