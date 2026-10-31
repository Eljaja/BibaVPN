//! File-backed multi-user authentication and per-user session limits.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub label: String,
    pub token: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<usize>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct UsersFile {
    pub users: Vec<User>,
}

pub fn load_users(path: &Path) -> anyhow::Result<UsersFile> {
    let data = std::fs::read(path).context("read users file")?;
    if data.len() > 1024 * 1024 {
        bail!("users file exceeds 1 MiB");
    }
    let file: UsersFile = serde_json::from_slice(&data).context("parse users file")?;
    validate_users(&file)?;
    Ok(file)
}

pub fn validate_users(file: &UsersFile) -> anyhow::Result<()> {
    let mut labels = HashSet::new();
    let mut tokens = HashSet::new();
    for u in &file.users {
        if u.label.trim().is_empty()
            || u.label.len() > 128
            || u.label.chars().any(char::is_control)
            || u.label != u.label.trim()
            || !labels.insert(&u.label)
        {
            bail!("empty or duplicate user label");
        }
        crate::startup_secrets::validate_resolved_token(&u.token)?;
        if u.token != u.token.trim() || !tokens.insert(&u.token) {
            bail!("invalid or duplicate user token");
        }
        if u.max_concurrent == Some(0) {
            bail!("max_concurrent must be positive");
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct UserRegistry {
    path: PathBuf,
    active: Arc<Mutex<HashMap<String, usize>>>,
}

pub struct UserSession {
    label: String,
    active: Arc<Mutex<HashMap<String, usize>>>,
}

impl Drop for UserSession {
    fn drop(&mut self) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = active.get_mut(&self.label) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.label);
            }
        }
        tracing::info!(user = %self.label, "user session ended");
    }
}

impl UserRegistry {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        load_users(&path)?;
        Ok(Self {
            path,
            active: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Re-read on each new connection so administrator changes apply without restart.
    pub fn acquire(&self, token: &str) -> anyhow::Result<UserSession> {
        let users = load_users(&self.path)?;
        let candidate = blake3::hash(token.as_bytes());
        let mut user = None;
        for entry in &users.users {
            let stored = blake3::hash(entry.token.as_bytes());
            if crate::crypto_layer::secret_eq(candidate.as_bytes(), stored.as_bytes()) {
                user = Some(entry);
            }
        }
        let user = user
            .filter(|u| u.enabled)
            .context("unknown or disabled user")?;
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let count = active.entry(user.label.clone()).or_default();
        if user.max_concurrent.is_some_and(|limit| *count >= limit) {
            bail!("user session limit reached");
        }
        *count += 1;
        tracing::info!(user = %user.label, "user session authenticated");
        Ok(UserSession {
            label: user.label.clone(),
            active: self.active.clone(),
        })
    }

    /// REALITY carries a MAC, not a token. Check every enabled token against the transcript.
    pub fn find_token(&self, mut matches: impl FnMut(&str) -> bool) -> anyhow::Result<String> {
        let users = load_users(&self.path)?;
        let mut matched = None;
        for user in users.users.iter().filter(|u| u.enabled) {
            if matches(&user.token) {
                matched = Some(user.token.clone());
            }
        }
        matched.context("unknown or disabled user")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn registry_reloads_and_enforces_limits_across_threads() {
        let path =
            std::env::temp_dir().join(format!("bibavpn-users-{}.json", rand::random::<u64>()));
        let write = |enabled| {
            std::fs::write(&path, format!(r#"{{"users":[{{"label":"alice","token":"alice-secret","enabled":{enabled},"max_concurrent":1}}]}}"#)).unwrap()
        };
        write(true);
        let registry = UserRegistry::new(path.clone()).unwrap();
        assert!(registry.acquire("unknown").is_err());
        let session = registry.acquire("alice-secret").unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let other = registry.clone();
        let b = barrier.clone();
        let thread = std::thread::spawn(move || {
            b.wait();
            other.acquire("alice-secret").is_err()
        });
        barrier.wait();
        assert!(thread.join().unwrap());
        drop(session);
        assert!(registry.acquire("alice-secret").is_ok());
        write(false);
        assert!(registry.acquire("alice-secret").is_err());
        std::fs::write(&path, b"broken").unwrap();
        assert!(registry.acquire("alice-secret").is_err());
        std::fs::remove_file(path).unwrap();
    }
}
