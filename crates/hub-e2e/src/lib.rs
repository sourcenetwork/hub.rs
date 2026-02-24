//! End-to-end test harness for hub.
//!
//! Provides cluster configuration builders, process management, and
//! observability tools for driving multi-node test clusters via JSON-RPC.
//!
//! Each test run gets a unique `run_id` for isolation:
//! - State dirs under `target/e2e/{run_id}/`
//! - Auto-assigned ports (no conflicts between parallel runs)
//! - `Drop` cleans up unless `HUB_E2E_KEEP=1`

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use hub_crypto as _;

pub mod cluster;
pub mod contracts;
pub mod observe;

use std::{
    collections::HashMap,
    fmt,
    fs::OpenOptions,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::Rng;

/// Generate a unique run ID based on timestamp + random suffix.
pub fn generate_run_id() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let suffix: u32 = rand::thread_rng().gen_range(1000..9999);
    format!("{ts}-{suffix}")
}

/// Whether to keep test artifacts after completion.
pub fn keep_artifacts() -> bool {
    std::env::var("HUB_E2E_KEEP").is_ok_and(|v| v == "1" || v == "true")
}

/// Allocate N unique ports using OS auto-assignment.
///
/// Binds to port 0, holds the listener briefly to reserve the port,
/// then releases it for process startup.
pub fn allocate_ports(n: usize) -> eyre::Result<Vec<u16>> {
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| eyre::eyre!("failed to allocate port: {}", e))?;
        let port = listener.local_addr()?.port();
        ports.push(port);
        listeners.push(listener);
    }
    drop(listeners);
    Ok(ports)
}

/// Base directory for e2e test artifacts.
pub fn e2e_base_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."))
        .join("target")
        .join("e2e")
}

/// A managed child process that sends SIGTERM on drop.
///
/// Stores the command components (program, args, envs) so the process
/// can be respawned after being killed (e.g. for restart tests).
pub struct ManagedProcess {
    name: String,
    child: Option<Child>,
    log_dir: PathBuf,
    program: PathBuf,
    args: Vec<String>,
    envs: HashMap<String, String>,
}

impl fmt::Debug for ManagedProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedProcess")
            .field("name", &self.name)
            .field("running", &self.child.is_some())
            .field("log_dir", &self.log_dir)
            .finish()
    }
}

impl ManagedProcess {
    /// Spawn a new managed process.
    ///
    /// Stores the command components so the process can be respawned later.
    pub fn spawn(
        name: &str,
        program: &Path,
        args: &[&str],
        envs: &[(&str, &str)],
        log_dir: &Path,
    ) -> eyre::Result<Self> {
        std::fs::create_dir_all(log_dir)?;

        let stdout_file = std::fs::File::create(log_dir.join("stdout.log"))?;
        let stderr_file = std::fs::File::create(log_dir.join("stderr.log"))?;

        let mut cmd = Command::new(program);
        cmd.args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }

        let child = cmd
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()?;

        tracing::info!(name, pid = child.id(), "spawned process");

        Ok(Self {
            name: name.to_string(),
            child: Some(child),
            log_dir: log_dir.to_path_buf(),
            program: program.to_path_buf(),
            args: args.iter().map(|s| s.to_string()).collect(),
            envs: envs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }

    /// Kill the current process and spawn a new one with the same arguments.
    ///
    /// Log files are opened in append mode so existing `LogTracker` instances
    /// seamlessly pick up output from the new process.
    pub fn respawn(&mut self) -> eyre::Result<()> {
        self.kill();

        let stdout_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_dir.join("stdout.log"))?;
        let stderr_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_dir.join("stderr.log"))?;

        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }

        let child = cmd
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()?;

        tracing::info!(name = self.name, pid = child.id(), "respawned process");
        self.child = Some(child);
        Ok(())
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_none())
    }

    /// Kill the process.
    pub fn kill(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!(name = self.name, "killed process");
        }
        self.child = None;
    }

    /// Get the log directory path.
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }

            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            loop {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }

            tracing::debug!(name = self.name, "cleaned up process");
        }
    }
}

/// A test run directory that cleans up on drop (unless `HUB_E2E_KEEP=1`).
#[derive(Debug)]
pub struct TestRunDir {
    path: PathBuf,
    keep: bool,
}

impl TestRunDir {
    /// Create a new test run directory.
    pub fn new(run_id: &str) -> eyre::Result<Self> {
        let path = e2e_base_dir().join(run_id);
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            keep: keep_artifacts(),
        })
    }

    /// Get the run directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create a subdirectory for a named component.
    pub fn component_dir(&self, name: &str) -> eyre::Result<PathBuf> {
        let dir = self.path.join(name);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

impl Drop for TestRunDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        } else {
            eprintln!("Preserving test artifacts at: {}", self.path.display());
        }
    }
}
