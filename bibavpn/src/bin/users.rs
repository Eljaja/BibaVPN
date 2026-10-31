use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};
use bibavpn::users::{load_users, validate_users, User, UsersFile};
use clap::{Parser, Subcommand};
use rand::RngCore;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    users_file: PathBuf,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Add {
        label: String,
        #[arg(long)]
        max_concurrent: Option<usize>,
    },
    List,
    Enable {
        label: String,
    },
    Disable {
        label: String,
    },
    /// Mint with INVITE_PUBLIC, BIBA_VPN_PSK and BIBA_INVITE_PASSPHRASE in the environment.
    Mint {
        label: String,
    },
}

struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn private_create(path: &Path) -> anyhow::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

fn lock(path: &Path) -> anyhow::Result<Lock> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    private_create(&lock_path).context(
        "user registry is locked; remove the lock file only if no administrator is running",
    )?;
    Ok(Lock(lock_path))
}

fn save(path: &Path, users: &UsersFile) -> anyhow::Result<()> {
    validate_users(users)?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp.{:016x}", rand::random::<u64>()));
    let tmp = PathBuf::from(tmp);
    let result = (|| {
        let mut file = private_create(&tmp)?;
        serde_json::to_writer_pretty(&mut file, users)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&tmp, path).context("replace users file")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Action::List => {
            for user in load_users(&args.users_file)?.users {
                println!(
                    "{}\t{}\t{}",
                    user.label,
                    if user.enabled { "enabled" } else { "disabled" },
                    user.max_concurrent
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "unlimited".into())
                );
            }
        }
        Action::Mint { label } => {
            let user = load_users(&args.users_file)?
                .users
                .into_iter()
                .find(|u| u.label == label)
                .context("user not found")?;
            if !user.enabled {
                bail!("user is disabled");
            }
            let binary = std::env::current_exe()?.with_file_name(if cfg!(windows) {
                "bibavpn-mint-invite.exe"
            } else {
                "bibavpn-mint-invite"
            });
            let status = Command::new(binary)
                .env("BIBA_VPN_TOKEN", user.token)
                .env("BIBA_INVITE_INSECURE", "false")
                .status()
                .context("run bibavpn-mint-invite (install it alongside bibavpn-users)")?;
            if !status.success() {
                bail!("invite generation failed");
            }
        }
        action => {
            let _lock = lock(&args.users_file)?;
            let mut users = if args.users_file.exists() {
                load_users(&args.users_file)?
            } else if matches!(action, Action::Add { .. }) {
                UsersFile::default()
            } else {
                bail!("users file does not exist");
            };
            match action {
                Action::Add {
                    label,
                    max_concurrent,
                } => {
                    let mut secret = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut secret);
                    users.users.push(User {
                        label,
                        token: hex::encode(secret),
                        enabled: true,
                        max_concurrent,
                    });
                }
                Action::Enable { label } => {
                    let user = users
                        .users
                        .iter_mut()
                        .find(|u| u.label == label)
                        .context("user not found")?;
                    user.enabled = true;
                }
                Action::Disable { label } => {
                    let user = users
                        .users
                        .iter_mut()
                        .find(|u| u.label == label)
                        .context("user not found")?;
                    user.enabled = false;
                }
                _ => unreachable!(),
            }
            save(&args.users_file, &users)?;
        }
    }
    Ok(())
}
