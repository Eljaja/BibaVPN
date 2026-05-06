# BibaVPN — client apps (`apps/`)

Briefing for agents and developers working on **desktop (Tauri)**, **Android**, and **iOS**
under this folder. Protocol, crypto, and CLI details stay in the repo root
**[AGENTS.md](../AGENTS.md)**.

## Layout


| Path                                                | Role                                                                                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `bibavpn-desktop/`                                  | Tauri app: `ui/` (Vite), `src-tauri/` (Rust workspace member `bibavpn-desktop`)                                               |
| `bibavpn-jni/`                                      | JNI Rust crate (`cargo -p bibavpn-jni`, workspace member `apps/bibavpn-jni`); builds `libbibavpn_jni.so` for Android          |
| `bibavpn-ffi/`                                      | C ABI static library for **iOS** Packet Tunnel (`cargo -p bibavpn-ffi`); link into `BibaVpnTunnel`                             |
| `android/`                                          | Standalone Gradle app (Compose); JNI → `android/app/src/main/jniLibs/` (see `wsl-build-rust-apk.sh`, `build-android-jni.ps1`) |
| `bibavpn-desktop/src-tauri/android-bibavpn-extras/` | Kotlin/XML VPN layer and assets; merged into Tauri `gen/android` after bootstrap scripts                                      |
| `bibavpn-desktop/src-tauri/ios-bibavpn-extras/`       | Swift Packet Tunnel + host VPN bridge; merged into Tauri `gen/apple` via `integrate-bibavpn-into-tauri-ios.sh`                   |
| `scripts/`                                          | Tauri mobile bootstrap, Android JNI helpers, iOS `merge_bibavpn_ios_project.py`                                                  |


Rust crates `**bibavpn`** and `**biba**` stay at the **repository root** (workspace members).
Workspace mobile bridges: `**bibavpn-jni**` (Android JNI) and `**bibavpn-ffi**` (iOS C ABI), both under `**apps/**`.

## Typical flows

**Desktop**

```bash
cd apps/bibavpn-desktop/ui && npm install && npm run build
cd .. && cargo tauri dev    # or from repo root: cargo build -p bibavpn-desktop --release
```

**Windows without MSVC** (single `exe`, portable MinGW via winlibs under `%LOCALAPPDATA%\bibavpn-mingw`):

```powershell
# from repo root
.\apps\scripts\build-desktop-windows-gnu.ps1
```

Output: `target/release/bibavpn-desktop.exe` (users typically need **Microsoft Edge WebView2 Runtime** installed once).

**Tauri Android (after first-time init)**

From repo root:

```bash
bash apps/scripts/tauri-android-init-local.sh          # or …-docker.sh
bash apps/scripts/integrate-bibavpn-into-tauri-android.sh
bash apps/scripts/wsl-build-tauri-android-jni.sh       # JNI → gen/android/jniLibs
cd apps/bibavpn-desktop && npm run tauri:android:build
```

`package.json` in `bibavpn-desktop` also exposes `android:bootstrap` /
`android:bootstrap:docker` chaining the init + integrate steps.

**Build JNI only**

```powershell
.\apps\scripts\build-android-jni.ps1                  # Windows, from repo root
```

**Tauri iOS (macOS)**

Requirements: Xcode, Apple Developer (VPN entitlements), `pip install pyyaml`, optional Go/gomobile for Tun2socks.

```bash
rustup target add aarch64-apple-ios
cargo build -p bibavpn-ffi --release --target aarch64-apple-ios
# Copy libbibavpn_ffi.a → см. bibavpn-desktop/src-tauri/ios-bibavpn-extras/BibaVpnTunnel/rust-static/README.md
bash apps/scripts/build-tun2socks-ios-gomobile.sh    # optional
cd apps/bibavpn-desktop && npm run ios:bootstrap       # или: ios init уже есть → npm run ios:integrate
cd apps/bibavpn-desktop && npm exec -- tauri ios dev
```

Один скрипт под `.ipa` (после настройки signing в Xcode или переменных `IOS_*`):

```bash
bash apps/scripts/build-ios-ipa.sh
```

Включите App Group `group.dev.bibavpn.desktop` и **Personal VPN** для основного target; bundle id extension: `dev.bibavpn.desktop.BibaVpnTunnel`.

## Environment (WSL / Linux)

- `apps/scripts/wsl-android-env.sh` — NDK linkers on `PATH`; source from `~/.bashrc`
(see `scripts/wsl-bashrc-snippet.sh` for a one-line installer).
- `ANDROID_HOME`, `ANDROID_NDK_HOME`, `JAVA_HOME` must point at valid SDK / NDK / JDK
installs before Tauri or Gradle commands.

## CI

Workflows under `**.github/workflows/**` (repo root):

- `**android.yml**` — Tauri Android: runs `tauri-android-init-local.sh` and `integrate-bibavpn-into-tauri-android.sh`, builds JNI (`bibavpn-jni`) into `gen/android/.../jniLibs`, then `**npx tauri android build**`; artifact: APK under `gen/android/app/build/outputs/apk/`.
- `**desktop-windows.yml**` / `**desktop-macos.yml**` — UI build + `**cargo build -p bibavpn-desktop --release**`, packaged as zip / `.app` + DMG on macOS.
- `**ios.yml**` — `cargo build -p bibavpn-ffi` для target `aarch64-apple-ios` (без полной Xcode IPA-сборки; нужна только проверка Rust FFI на macOS runner).
- `**ios-ipa.yml**` — только **workflow_dispatch**: полная сборка и артефакт `.ipa` после настройки секретов подписи (см. комментарии в workflow и [Tauri iOS signing](https://v2.tauri.app/distribute/sign/ios/)).
- `**release.yml**` — wires the above together and publishes artifacts.

The standalone `**apps/android/**` tree is **not** built by these workflows; use local scripts (e.g. `wsl-build-rust-apk.sh`) for that app.
