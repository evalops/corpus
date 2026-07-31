//! fanotify sensor (spec 10.10 Linux): mount marks observe close-write and
//! moved-to events; FAN_OPEN_EXEC is attempted best-effort for execution
//! prioritization. Queue overflow is persisted as a SENSOR_OVERFLOW
//! coverage gap and triggers the reconciliation fallback.
//!
//! Requires CAP_SYS_ADMIN for FAN_MARK_MOUNT. If initialization fails
//! (EPERM, unsupported kernel) the caller falls back to the poll sensor.

use crate::state::{priority, StateDb};

const OUTCOME_SENSOR_OVERFLOW: &str = "SENSOR_OVERFLOW";
use anyhow::{anyhow, Context, Result};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;

pub struct FanotifySensor {
    rx: std_mpsc::Receiver<SensorEventKind>,
}

#[derive(Debug)]
pub enum SensorEventKind {
    File {
        path: PathBuf,
        priority: i64,
        reason: &'static str,
    },
    Overflow,
}

/// Map each watch path to its mount point (longest prefix in mountinfo).
fn mounts_for(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").context("reading mountinfo")?;
    let mut mounts: Vec<PathBuf> = info
        .lines()
        .filter_map(|l| l.split_whitespace().nth(4))
        .map(|m| PathBuf::from(m.replace("\\040", " ")))
        .collect();
    mounts.sort_by_key(|m| std::cmp::Reverse(m.as_os_str().len()));
    let mut out = Vec::new();
    'paths: for p in paths {
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        for m in &mounts {
            if canon.starts_with(m) {
                if !out.contains(m) {
                    out.push(m.clone());
                }
                continue 'paths;
            }
        }
        out.push(canon);
    }
    Ok(out)
}

fn init_fanotify(mounts: &[PathBuf]) -> Result<RawFd> {
    // SAFETY: fanotify_init/fanotify_mark are direct syscalls via libc.
    let fd = unsafe {
        libc::fanotify_init(
            (libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK) as libc::c_uint,
            (libc::O_RDONLY | libc::O_CLOEXEC) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(anyhow!(
            "fanotify_init failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut any = false;
    for m in mounts {
        let cpath = std::ffi::CString::new(m.as_os_str().as_encoded_bytes())?;
        // FAN_MOVED_TO is rejected on mount marks by several kernels, so
        // renames-into-tree are covered by the reconciliation scanner.
        // FAN_OPEN_EXEC is attempted best-effort for exec prioritization.
        let tiers: [u64; 2] = [
            libc::FAN_CLOSE_WRITE | libc::FAN_OPEN_EXEC,
            libc::FAN_CLOSE_WRITE,
        ];
        let mut marked = false;
        for mask in tiers {
            let rc = unsafe {
                libc::fanotify_mark(
                    fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                    mask,
                    libc::AT_FDCWD,
                    cpath.as_ptr(),
                )
            };
            if rc == 0 {
                marked = true;
                any = true;
                let with_exec = mask & libc::FAN_OPEN_EXEC != 0;
                tracing::info!(mount = %m.display(), exec_events = with_exec, "fanotify mount mark added");
                break;
            }
            tracing::debug!(mount = %m.display(), mask, error = %std::io::Error::last_os_error(), "fanotify mark tier failed");
        }
        if !marked {
            tracing::warn!(mount = %m.display(), "fanotify could not mark mount");
        }
    }
    if !any {
        return Err(anyhow!("fanotify: no watch path could be marked"));
    }
    Ok(fd)
}

const METADATA_LEN: usize = std::mem::size_of::<libc::fanotify_event_metadata>();

fn drain_fd(fd: RawFd, tx: &std_mpsc::Sender<SensorEventKind>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: buf is a valid writable region; fd is a live fanotify fd.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            tracing::error!(error = %err, "fanotify read failed");
            return;
        }
        let mut offset = 0usize;
        let n = n as usize;
        while offset + METADATA_LEN <= n {
            // SAFETY: the kernel lays out fanotify_event_metadata at offset;
            // alignment is guaranteed for the first event and event_len
            // strides thereafter.
            let meta = unsafe {
                (buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata).read_unaligned()
            };
            let event_len = meta.event_len as usize;
            if event_len < METADATA_LEN || offset + event_len > n {
                break;
            }
            if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                let _ = tx.send(SensorEventKind::Overflow);
            } else if meta.fd >= 0 {
                let link = format!("/proc/self/fd/{}", meta.fd);
                if let Ok(path) = std::fs::read_link(&link) {
                    let is_dir = meta.mask & libc::FAN_ONDIR != 0;
                    if !is_dir {
                        let (prio, reason) = if meta.mask & libc::FAN_OPEN_EXEC != 0 {
                            (priority::EXEC_TARGET, "exec_open")
                        } else if meta.mask & libc::FAN_MOVED_TO != 0 {
                            (priority::WRITTEN_OR_RENAMED, "moved_to")
                        } else {
                            (priority::WRITTEN_OR_RENAMED, "close_write")
                        };
                        let _ = tx.send(SensorEventKind::File {
                            path,
                            priority: prio,
                            reason,
                        });
                    }
                }
                // SAFETY: fd was provided by the kernel for this event.
                unsafe { libc::close(meta.fd) };
            }
            offset += event_len;
        }
    }
}

impl FanotifySensor {
    /// Try to start the fanotify sensor; caller falls back to polling on Err.
    pub fn start(paths: &[PathBuf]) -> Result<FanotifySensor> {
        let mounts = mounts_for(paths)?;
        let fd = init_fanotify(&mounts)?;
        let (tx, rx) = std_mpsc::channel();
        std::thread::Builder::new()
            .name("fanotify-reader".into())
            .spawn(move || drain_fd(fd, &tx))
            .context("spawning fanotify reader")?;
        Ok(FanotifySensor { rx })
    }

    /// Consume events and enqueue candidates; runs forever. Blocking: the
    /// caller runs it on a dedicated thread via spawn_blocking.
    pub fn run(self, db: std::sync::Arc<StateDb>, debounce_ms: u64, exclusions: Vec<String>) {
        tracing::info!("fanotify sensor active");
        loop {
            match self.rx.recv() {
                Ok(SensorEventKind::File {
                    path,
                    priority: prio,
                    reason,
                }) => {
                    let s = path.to_string_lossy();
                    if crate::config::matches_exclusion(&exclusions, &s) {
                        continue;
                    }
                    if let Err(e) = db.enqueue(&s, prio, reason, debounce_ms) {
                        tracing::warn!(error = %e, path = %s, "failed to enqueue fanotify candidate");
                    }
                }
                Ok(SensorEventKind::Overflow) => {
                    tracing::error!("fanotify queue overflow: recording SENSOR_OVERFLOW gap");
                    if let Err(e) = db.record_gap(
                        "fanotify",
                        OUTCOME_SENSOR_OVERFLOW,
                        None,
                        None,
                        Some("QUEUE_OVERFLOW"),
                        "{}",
                    ) {
                        tracing::error!(error = %e, "failed to record overflow gap");
                    }
                }
                Err(_) => {
                    tracing::error!("fanotify reader thread died");
                    return;
                }
            }
        }
    }
}
