use crate::{api::Api, store::Store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct Mounted {
    path: PathBuf,
    pid: u32,
    config: PathBuf,
}
fn default_mount() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("cannot locate home directory")?
        .join("GoogleDrive"))
}
pub fn run(
    api: &Api,
    path: Option<&Path>,
    drive: Option<&str>,
    read_only: bool,
    foreground: bool,
    connections: u8,
) -> Result<()> {
    if let Some(drive) = drive {
        ensure!(
            crate::drive::valid_id(drive) && !matches!(drive, "root" | "drives" | "shared"),
            "invalid Shared Drive ID"
        );
    }
    let version = Command::new("rclone")
        .arg("version")
        .output()
        .context("install rclone first (macOS: brew install rclone)")?;
    ensure!(version.status.success(), "rclone is unavailable");
    let version_text = String::from_utf8_lossy(&version.stdout);
    let number = version_text
        .lines()
        .next()
        .unwrap_or("")
        .strip_prefix("rclone v")
        .unwrap_or("");
    let parts: Vec<u32> = number
        .split('.')
        .take(3)
        .map(|part| {
            part.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect();
    ensure!(
        parts.len() == 3 && (parts[0], parts[1], parts[2]) >= (1, 75, 2),
        "rclone 1.75.2+ is required for mounting; update it using the installer or brew upgrade rclone"
    );
    if cfg!(target_os = "linux") {
        let fuse = Command::new("fusermount3")
            .arg("--version")
            .output()
            .context(
                "mounting requires FUSE3 (fusermount3); run the installer with --with-mount",
            )?;
        ensure!(fuse.status.success(), "fusermount3 is unavailable");
    }

    let db = Store::open(&api.db)?;
    let account = api.account.clone().context("run gdirect login first")?;
    let key = Store::mount_key(&account);
    ensure!(
        db.setting(&key)?.is_none(),
        "{account} is already mounted; run gdirect unmount --account {account} first"
    );
    let credentials_data = crate::auth::credentials(&db, Some(&account))?;
    // Fail here rather than inside rclone if the saved login no longer works.
    crate::auth::refresh(&credentials_data)?;
    let email = account.as_str();
    let path = path
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(default_mount)?;
    #[cfg(windows)]
    let path = {
        ensure!(
            !path.exists(),
            "Windows mount directory must not already exist"
        );
        let absolute = std::path::absolute(&path)?;
        let parent = absolute
            .parent()
            .context("mount requires a directory path")?;
        fs::create_dir_all(parent)?;
        absolute
    };
    #[cfg(not(windows))]
    let path = {
        fs::create_dir_all(&path)?;
        let path = path.canonicalize()?;
        ensure!(
            fs::read_dir(&path)?.next().is_none(),
            "mount directory must be empty"
        );
        path
    };
    let state = api
        .db
        .canonicalize()?
        .parent()
        .context("missing state directory")?
        .join("mount")
        .join(crate::api::safe_name(email));
    fs::create_dir_all(&state)?;
    let credentials = state.join("credentials.json");
    crate::auth::export_credentials(&credentials_data, &credentials)?;
    let config = state.join("rclone.conf");
    let conf = if credentials_data.is_service_account() {
        "[gdirect]\ntype = drive\n"
    } else {
        "[gdirect]\ntype = drive\nenv_auth = true\n"
    };
    fs::write(&config, conf)?;
    let log = state.join("rclone.log");
    #[cfg(unix)]
    let mut command = {
        if foreground {
            Command::new("rclone")
        } else {
            let mut cmd = Command::new("nohup");
            cmd.arg("rclone");
            cmd
        }
    };
    #[cfg(not(unix))]
    let mut command = Command::new("rclone");
    command
        .arg(if cfg!(target_os = "macos") {
            "nfsmount"
        } else {
            "mount"
        })
        .arg("gdirect:")
        .arg(&path)
        .arg("--config")
        .arg(&config)
        .env("GOOGLE_APPLICATION_CREDENTIALS", &credentials)
        .args([
            "--vfs-cache-mode",
            "full",
            "--vfs-cache-max-size",
            "5G",
            "--dir-cache-time",
            "1m",
            "--poll-interval",
            "30s",
            "--file-perms",
            "0600",
            "--dir-perms",
            "0700",
        ])
        .arg("--transfers")
        .arg(connections.to_string())
        .arg("--vfs-read-chunk-streams")
        .arg(connections.to_string())
        .args(["--vfs-read-chunk-size", "4M"])
        .arg("--cache-dir")
        .arg(state.join("cache"))
        .arg("--log-file")
        .arg(&log)
        .args(["--log-level", "INFO"]);
    if credentials_data.is_service_account() {
        command
            .arg("--drive-service-account-file")
            .arg(&credentials);
        if let Some(subject) = credentials_data.subject() {
            command.arg("--drive-impersonate").arg(subject);
        }
    }
    if let Some(drive) = drive {
        command.arg("--drive-team-drive").arg(drive);
    }
    if read_only {
        command.arg("--read-only");
    }
    println!(
        "Mount: {}\nAccount: {email}\nLog: {}",
        path.display(),
        log.display()
    );
    if foreground || cfg!(windows) {
        let status = command.status();
        let _ = fs::remove_file(&credentials);
        let status = status?;
        ensure!(
            status.success(),
            "rclone mount failed; see {}",
            log.display()
        );
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()?;
    let mounted = Mounted {
        path,
        pid: child.id(),
        config,
    };
    db.set(&key, &serde_json::to_string(&mounted)?)?;
    for _ in 0..60 {
        if let Some(status) = child.try_wait()? {
            db.unset(&key)?;
            let _ = fs::remove_file(&credentials);
            anyhow::bail!("rclone mount exited ({status}); see {}", log.display());
        }
        if is_mounted(&mounted.path)? {
            println!("Mounted. Use gdirect unmount to detach.");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    child.kill()?;
    child.wait()?;
    // Keep the record if the OS mounted at the timeout boundary.
    if !is_mounted(&mounted.path)? {
        db.unset(&key)?;
        let _ = fs::remove_file(&credentials);
    }
    anyhow::bail!(
        "mount did not become ready within 30s; see {}",
        log.display()
    )
}
fn is_mounted(path: &Path) -> Result<bool> {
    let result = Command::new("mount").output()?;
    ensure!(
        result.status.success(),
        "cannot inspect mounted filesystems"
    );
    let marker = format!(" on {} ", path.display());
    Ok(String::from_utf8_lossy(&result.stdout)
        .lines()
        .any(|line| line.contains(&marker)))
}
/// The account whose mount `unmount` detaches: the one asked for, else the
/// default account's mount, else the only mount recorded.
fn mounted_account(db: &Store, asked: Option<&str>) -> Result<String> {
    if let Some(account) = asked {
        return Ok(account.to_owned());
    }
    let mounted = db.mounted_accounts()?;
    if let Some(default) = db.default_account()?
        && mounted.contains(&default)
    {
        return Ok(default);
    }
    match mounted.as_slice() {
        [one] => Ok(one.clone()),
        [] => anyhow::bail!("no background mount recorded; foreground mounts stop with Ctrl-C"),
        many => anyhow::bail!(
            "several accounts are mounted ({}); choose one with --account",
            many.join(", ")
        ),
    }
}
pub fn unmount(db: &Store, account: Option<&str>) -> Result<()> {
    let account = mounted_account(db, account)?;
    let key = Store::mount_key(&account);
    let raw = db.setting(&key)?.with_context(|| {
        format!("no background mount recorded for {account}; foreground mounts stop with Ctrl-C")
    })?;
    let mounted: Mounted = serde_json::from_str(&raw)?;
    if is_mounted(&mounted.path)? {
        let status = if cfg!(target_os = "macos") {
            Command::new("diskutil")
                .arg("unmount")
                .arg(&mounted.path)
                .status()?
        } else {
            Command::new("fusermount3")
                .arg("-u")
                .arg(&mounted.path)
                .status()?
        };
        ensure!(
            status.success(),
            "unmount failed; close files using the mounted directory and retry"
        );
    }
    #[cfg(unix)]
    {
        // Avoid signalling a reused PID after a crash or reboot.
        let process = Command::new("ps")
            .args(["-p", &mounted.pid.to_string(), "-o", "command="])
            .output()?;
        let command = String::from_utf8_lossy(&process.stdout);
        if command.contains("rclone") && command.contains(mounted.config.to_string_lossy().as_ref())
        {
            let status = Command::new("kill")
                .args(["-TERM", &mounted.pid.to_string()])
                .status()?;
            ensure!(status.success(), "could not stop mount process");
        }
    }
    db.unset(&key)?;
    // rclone was given a copy of the refresh credential; do not leave it behind.
    let _ = fs::remove_file(mounted.config.with_file_name("credentials.json"));
    println!(
        "Unmounted {}. Cached writes are retained for the next mount.",
        mounted.path.display()
    );
    Ok(())
}
