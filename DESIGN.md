# BibaVPN — design system for cross-platform ports

This document describes the visual language of the Tauri app (React UI across desktop and Android), brand assets, and tokens needed to reproduce the same look on other platforms.

---

## 1. Brand identity

### 1.1 Meaning and metaphor

- **VPN / privacy** — the brand uses a **ghost** (stealth, “invisibility” on the network).
- **UI mood** — dark “night” interface, **neon mint** accent on **cool blue** (slate / sky).

### 1.2 Two graphic types


| Role                    | Description                                                                                                                                                     | File in the repo                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Horizontal wordmark** | **BIBA** lettering + **VPN** block with ghost; dark background baked into the asset. Used in the **main screen header** and as the basis for app/banner assets. | `branding/biba-vpn-logo.png` |
| **App icon**            | Square composition: **white ghost** on a **teal-green** rounded rectangle, overall dark background. Phone launcher / desktop app icon.                         | `branding/biba-vpn-app-icon.png`, exported under `apps/bibavpn-desktop/src-tauri/icons/` |


When porting, **keep the same PNGs** (or export from source with the same aspect ratio and padding).

### 1.3 Status-bar mini icon (Android only)

Vector **ghost**, fill `**#00E5FF`** (cyan): `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/res/drawable/ic_stat_vpn.xml`. On other OSes, reuse the same 24×24 silhouette and proportions.

---

## 2. Color (foundation)

All values are **sRGB**, `#RRGGBB`. Alpha is noted separately.

### 2.1 Background


| Token            | Hex       | Usage                                                                            |
| ---------------- | --------- | -------------------------------------------------------------------------------- |
| `bgRoot`         | `#070B14` | Root app background (main screen behind the gradient).                           |
| `bgScreen`       | `#0B0F1A` | **Settings** screen solid fill.                                                  |
| `bgRadialAccent` | `#16203B` | **Center** of the main screen **radial gradient** (top), blending into `bgRoot`. |
| `tvBannerBg`     | `#0B0F1A` | **Android TV banner** background (`tv_banner.xml`).                              |


### 2.2 Cards and fields


| Token            | Hex                         | Usage                                                     |
| ---------------- | --------------------------- | --------------------------------------------------------- |
| `cardBg`         | `#121826`                   | Card surfaces (status, server row).                       |
| `cardBgSettings` | `cardBg` @ **92%** opacity  | Settings section surfaces (`CardBg.copy(alpha = 0.92f)`). |
| `fieldInsetBg`   | `#020617` @ **55%** opacity | Multiline inset fields and `OutlinedTextField` container. |
| `fieldText`      | `#F8FAFC`                   | Input text.                                               |


### 2.3 Accents and text


| Token          | Hex       | Usage                                                    |
| -------------- | --------- | -------------------------------------------------------- |
| `labelSky`     | `#60A5FA` | Secondary accents, helper copy, field labels (sky blue). |
| `textMuted`    | `#94A3B8` | Secondary text, subtitles, placeholders.                 |
| `textSlate200` | `#E2E8F0` | Primary “light” text in headers / secondary blocks.      |
| `mint`         | `#00FFA3` | Primary accent: status, toggle, cursor, CTA chrome.      |
| `mintSoft`     | `#34D399` | Softer green (active connection status dot core).        |


### 2.4 Borders and translucency


| Token              | Value             | Usage                                                             |
| ------------------ | ----------------- | ----------------------------------------------------------------- |
| `borderSubtle`     | white **8%**      | Card, circular button, and field outlines (`Color.White` α=0.08). |
| `mainButtonBorder` | `#60A5FA` **20%** | Main **Connect / Disconnect** button outline (`0x3360A5FA`).      |
| `iconButtonFill`   | white **3%**      | Circular header buttons (settings, back).                         |


### 2.5 Main CTA gradient (vertical)

**Connect / Disconnect** button:

- Top: `#1A2950`
- Bottom: `#14203C`

Direction: **top to bottom** (`linear-gradient(180deg, #1A2950, #14203C)`).

### 2.6 Main screen radial gradient

- Center: **top center** (in UI terms — `center = (0.5, 0)` relative to the screen).
- Stops from center: `#16203B` → `#070B14` → `#070B14`.
- Large radius (~1200 dp equivalent) so edges read as flat `bgRoot`.

---

## 3. Typography

Android uses the **Material 3 system font** (Roboto). Elsewhere, a **neutral geometric sans** is enough: **Inter**, **SF Pro** (iOS), **Segoe UI** (Windows).


| Level                           | Size  | Weight                               | Color (typical)      |
| ------------------------------- | ----- | ------------------------------------ | -------------------- |
| Status “Connected”              | 20 sp | SemiBold (600)                       | `#FFFFFF`            |
| Main CTA title                  | 22 sp | SemiBold                             | `#FFFFFF`            |
| Subtitle under CTA              | 14 sp | Regular                              | `labelSky` @ 75%     |
| Server card title               | 18 sp | SemiBold                             | `#FFFFFF`            |
| “SERVER” label                  | 11 sp | Medium (500), letter-spacing **2.4** | `textMuted`          |
| Body / secondary on server card | 14 sp | Regular                              | `textMuted`          |
| Settings section title          | 18 sp | SemiBold                             | `#FFFFFF`            |
| Section subtitle                | 14 sp | Regular                              | `textMuted`          |
| Field label                     | 12 sp | Medium                               | `labelSky` @ 90%     |
| Field value                     | 14 sp | Regular                              | `#F8FAFC`            |
| Hint under field                | 11 sp | Regular                              | `textMuted`          |
| Settings header                 | 14 sp | Medium, letter-spacing **0.6**       | `textSlate200`       |
| Circular button glyph           | 18 sp | —                                    | `textSlate200` @ 88% |
| Server card chevron `›`         | 22 sp | —                                    | `textMuted` @ 55%    |


**Header logo** — bitmap, not live text; height **36 dp**, horizontal padding **12 dp**, horizontally **flex-1** between the settings control and a balancing **40 dp** spacer.

---

## 4. Spacing and grid

Base unit **4 dp**. Common values:

- Screen horizontal inset **20 dp** (home and settings).
- Below header to status card: **24 dp**.
- Status card to main CTA: **40 dp**.
- Main CTA to server card: **32 dp**.
- Inside status card: **20 dp**; title margin below: **12 dp**.
- CTA: padding **24 h / 22 v**; decorative square on the right **48 dp**, corner radius **16 dp**.

---

## 5. Corner radii


| Element                             | Radius                         |
| ----------------------------------- | ------------------------------ |
| Status card                         | **26 dp**                      |
| Main CTA                            | **28 dp**                      |
| Server card                         | **24 dp**                      |
| Settings section wrapper            | **28 dp**                      |
| Inputs, insets                      | **16 dp**                      |
| “Apply to connection fields” button | **14 dp**                      |
| Small square on CTA                 | **16 dp**                      |
| Circular icon buttons               | **50%** (circle)               |
| Status indicator (outer ring)       | **18 dp**; inner dot **10 dp** |


Strokes are **1 dp**, using `borderSubtle` or the special variants in §2.4.

---

## 6. Key components (behavior and look)

### 6.1 Main screen

- Top: **left** circular settings button, **center** wordmark, **right** empty **40 dp** for symmetry.
- **Status card**: subtle border, `cardBg` fill; **dot** on the left (active: outer ring `mint` 35% + core `mintSoft`; inactive: muted dot).
- **Main button**: gradient + `mainButtonBorder`; when config is incomplete, entire control **α = 0.55**.
- **Server card**: fully tappable; top **SERVER** label in all caps with increased tracking.

### 6.2 Settings

- `bgScreen` background, full-height scroll.
- Sections in cards with `cardBg` @ 92%.
- **TLS skip toggle**: on — thumb `mint`, track `mint` 40%; off — `textMuted`.
- **Invite apply button**: `mint` 20% fill, `mint` label, full width.

### 6.3 Notification (Android)

- Channel: low importance; title/body strings live in resources.
- Actions: Russian strings in `values/strings.xml`; English **Disable** / **Enable** in `values-en/strings.xml`.

---

## 7. System chrome (Android)

- **Status bar / navigation bar**: transparent (`themes.xml`).
- **App display name**: `BibaVPN` (`app_name`).

---

## 8. Checklist for a new platform

1. Wire up **two PNGs**: wordmark + app icon (from `branding/`).
2. Implement the **palette** from §2 (including gradients).
3. Recreate the main screen **radial** background and settings **solid** background.
4. Match **radii**, **1 dp** strokes, and **spacing** from §§4–5.
5. Typography: sans family; size/weight scale from §3.
6. Accent semantics: **mint** for success/ON, **sky** for secondary labels.

For the app source of truth, see `apps/bibavpn-desktop/ui/src/theme.js` and the React screens under `apps/bibavpn-desktop/ui/src/screens/`.