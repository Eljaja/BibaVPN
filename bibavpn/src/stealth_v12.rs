//! BibaV1.2 stealth presets (TLS labels, timing, decoy). Full BoringSSL / raw desync live in platform-specific code paths.
use std::str::FromStr;

use crate::frame::PadMode;
use crate::tls_util::TlsClientProfile;

/// CLI / config: balanced performance vs anti-fingerprint strength.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StealthProfile {
    /// Match Biba v1.1.x behaviour (plain rustls default, no implicit decoy).
    #[default]
    Default,
    /// Chrome132 template, moderate WS jitter, decoy browser mode, server RTT helpers if set.
    Balanced,
    /// Stronger jitter, decoy browser, optional dummy traffic; optional multi-WSS via `--ws-parallel`.
    Aggressive,
}

impl FromStr for StealthProfile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "default" => StealthProfile::Default,
            "balanced" => StealthProfile::Balanced,
            "aggressive" => StealthProfile::Aggressive,
            other => anyhow::bail!("unknown --stealth-profile {other:?}: default, balanced, aggressive"),
        })
    }
}

/// Decoy HTTPS style.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DecoyMode {
    #[default]
    Simple,
    /// Richer browser headers + path list (still same `rustls` stack; not a full browser).
    Browser,
}

impl FromStr for DecoyMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "simple" | "default" => DecoyMode::Simple,
            "browser" => DecoyMode::Browser,
            other => anyhow::bail!("unknown --decoy-mode {other:?}: simple, browser"),
        })
    }
}

/// Placeholder for raw-socket split / disorder (see `desync` module).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DesyncMode {
    #[default]
    Off,
    Split2,
    FakeDsplit,
    Disorder,
}

impl FromStr for DesyncMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "off" | "none" => DesyncMode::Off,
            "split2" | "split-2" => DesyncMode::Split2,
            "fakedsplit" | "fake-dsplit" => DesyncMode::FakeDsplit,
            "disorder" => DesyncMode::Disorder,
            other => anyhow::bail!("unknown --desync-mode {other:?}: off, split2, fakedsplit, disorder"),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TcpFooling {
    #[default]
    Off,
    Md5Sig,
    BadSeq,
    BadSum,
}

impl FromStr for TcpFooling {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "" | "off" | "none" => TcpFooling::Off,
            "md5sig" | "md5-sig" => TcpFooling::Md5Sig,
            "badseq" | "bad-seq" => TcpFooling::BadSeq,
            "badsum" | "bad-sum" => TcpFooling::BadSum,
            other => anyhow::bail!("unknown --fooling {other:?}: off, md5sig, badseq, badsum"),
        })
    }
}

/// Fields applied when `--stealth-profile` is set and explicit flags are absent (see client).
#[derive(Clone, Debug)]
pub struct StealthPreset {
    pub tls_profile: TlsClientProfile,
    pub pad_mode: PadMode,
    pub ws_jitter_min_ms: u8,
    pub ws_jitter_max_ms: u8,
    pub decoy_gets: bool,
    pub decoy_mode: DecoyMode,
    pub dummy_interval_secs: u64,
    /// `idle decoy` threshold (no mux data); `0` = feature off in preset.
    pub idle_decoy_secs: u64,
}

/// Suggested `bibavpn-server` delayed-ACK + RTT-mask (when not overridden by ms flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerRttDefaults {
    pub ack_delay_min_ms: u16,
    pub ack_delay_max_ms: u16,
    pub rtt_mask_jitter_ms: u16,
}

impl StealthProfile {
    /// BibaV1.2 server-side counter–RTT hints: off for `Default`, mid for `Balanced`, wide for `Aggressive`.
    pub fn server_rtt_defaults(self) -> Option<ServerRttDefaults> {
        match self {
            StealthProfile::Default => None,
            StealthProfile::Balanced => Some(ServerRttDefaults {
                ack_delay_min_ms: 40,
                ack_delay_max_ms: 120,
                rtt_mask_jitter_ms: 25,
            }),
            StealthProfile::Aggressive => Some(ServerRttDefaults {
                ack_delay_min_ms: 40,
                ack_delay_max_ms: 500,
                rtt_mask_jitter_ms: 100,
            }),
        }
    }
}

/// Client presets: TLS label, `PadMode::Adaptive` + WebSocket jitter ranges for `balanced` / `aggressive` (DPI traffic shape).
pub fn preset(p: StealthProfile) -> StealthPreset {
    match p {
        StealthProfile::Default => StealthPreset {
            tls_profile: TlsClientProfile::Default,
            pad_mode: PadMode::default(),
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            decoy_gets: false,
            decoy_mode: DecoyMode::Simple,
            dummy_interval_secs: 0,
            idle_decoy_secs: 0,
        },
        StealthProfile::Balanced => StealthPreset {
            tls_profile: TlsClientProfile::Chrome132,
            pad_mode: PadMode::Adaptive,
            ws_jitter_min_ms: 5,
            ws_jitter_max_ms: 15,
            decoy_gets: true,
            decoy_mode: DecoyMode::Browser,
            dummy_interval_secs: 0,
            idle_decoy_secs: 10,
        },
        StealthProfile::Aggressive => StealthPreset {
            tls_profile: TlsClientProfile::Chrome132,
            pad_mode: PadMode::Adaptive,
            ws_jitter_min_ms: 5,
            ws_jitter_max_ms: 25,
            decoy_gets: true,
            decoy_mode: DecoyMode::Browser,
            dummy_interval_secs: 45,
            idle_decoy_secs: 10,
        },
    }
}

/// Apply preset WS jitter only when the user did not set an explicit `min..=max` range (both zero).
pub fn apply_preset_ws_jitter(
    pr: Option<&StealthPreset>,
    explicit_min: u8,
    explicit_max: u8,
) -> (u8, u8) {
    if explicit_min == 0 && explicit_max == 0 {
        if let Some(p) = pr {
            return (p.ws_jitter_min_ms, p.ws_jitter_max_ms);
        }
    }
    (explicit_min, explicit_max)
}

/// `None` = inherit from `preset` when set; `Some(0)` = disabled; `Some(n)` = threshold in seconds.
pub fn merge_idle_decoy_secs(explicit: Option<u64>, pr: Option<&StealthPreset>) -> u64 {
    match explicit {
        Some(0) => 0,
        Some(n) => n,
        None => pr.map(|p| p.idle_decoy_secs).unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_jitter_uses_preset_when_both_zero() {
        let p = StealthProfile::Balanced;
        let pr = preset(p);
        let (a, b) = apply_preset_ws_jitter(Some(&pr), 0, 0);
        assert_eq!((a, b), (5, 15));
    }

    #[test]
    fn apply_jitter_respects_explicit_nonzero() {
        let p = StealthProfile::Balanced;
        let pr = preset(p);
        let (a, b) = apply_preset_ws_jitter(Some(&pr), 1, 3);
        assert_eq!((a, b), (1, 3));
    }

    #[test]
    fn merge_idle_uses_preset() {
        let pr = preset(StealthProfile::Balanced);
        assert_eq!(merge_idle_decoy_secs(None, Some(&pr)), 10);
        assert_eq!(merge_idle_decoy_secs(Some(0), Some(&pr)), 0);
    }

    #[test]
    fn stealth_profile_from_str() {
        assert_eq!(
            "balanced".parse::<StealthProfile>().unwrap(),
            StealthProfile::Balanced
        );
        assert_eq!(
            "AGGRESSIVE".parse::<StealthProfile>().unwrap(),
            StealthProfile::Aggressive
        );
        assert!("weird".parse::<StealthProfile>().is_err());
    }

    #[test]
    fn decoy_and_desync_from_str() {
        assert_eq!("browser".parse::<DecoyMode>().unwrap(), DecoyMode::Browser);
        assert_eq!("split2".parse::<DesyncMode>().unwrap(), DesyncMode::Split2);
        assert_eq!(
            "fake-dsplit".parse::<DesyncMode>().unwrap(),
            DesyncMode::FakeDsplit
        );
        assert_eq!("md5sig".parse::<TcpFooling>().unwrap(), TcpFooling::Md5Sig);
    }

    #[test]
    fn aggressive_preset_stronger_than_default() {
        let d = preset(StealthProfile::Default);
        let a = preset(StealthProfile::Aggressive);
        assert!(a.ws_jitter_max_ms >= d.ws_jitter_max_ms);
        assert!(a.idle_decoy_secs >= d.idle_decoy_secs);
    }
}
