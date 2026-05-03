# BibaVPN — client apps (`apps/`)

Briefing for agents and developers working on **desktop (Tauri)** and **Android**
under this folder. Protocol, crypto, and CLI details stay in the repo root
**[AGENTS.md](../AGENTS.md)**.

## Layout


| Path               | Role                                                                              |
| ------------------ | --------------------------------------------------------------------------------- |
| `bibavpn-desktop/` | Tauri app: `ui/` (Vite), `src-tauri/` (Rust workspace member `bibavpn-desktop`)   |
| `bibavpn-jni/`     | JNI Rust crate (`cargo -p bibavpn-jni`); builds `libbibavpn_jni.so` for Android    |
| `android/`         | Standalone Gradle app (Compose); JNI `.so` output targets `app/src/main/jniLibs/` |
| `scripts/`         | Bootstrap Tauri Android gen, integrate legacy tree into gen, JNI/WSL helpers      |


Rust crates **`bibavpn`** and **`biba`** stay at the **repository root** (workspace members).
The JNI bridge **`bibavpn-jni`** lives here under **`bibavpn-jni/`**.

## Typical flows

**Desktop**

```bash
cd apps/bibavpn-desktop/ui && npm install && npm run build
cd .. && cargo tauri dev    # or: cargo build -p bibavpn-desktop --release
```

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

**Standalone Android APK (Gradle only, no Tauri gen)**

```bash
bash scripts/wsl-build-all.sh                          # installs SDK bits if needed, then
                                                       # apps/scripts/wsl-build-rust-apk.sh
```

Or build JNI only:

```bash
bash apps/scripts/build-android-jni.ps1                # Windows, from repo root
```

## Environment (WSL / Linux)

- `apps/scripts/wsl-android-env.sh` — NDK linkers on `PATH`; source from `~/.bashrc`
(see `scripts/wsl-bashrc-snippet.sh` for a one-line installer).
- `ANDROID_HOME`, `ANDROID_NDK_HOME`, `JAVA_HOME` must point at valid SDK / NDK / JDK
installs before Tauri or Gradle commands.

## CI

GitHub Actions under `.github/workflows/` use `apps/android` and
`apps/bibavpn-desktop` as working directories for the Android and desktop jobs.