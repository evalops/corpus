//! Filesystem change sensors.
//!
//! Platform backends feed a common capture queue. Each sensor is
//! observe-only: it records paths and reasons, never blocks writers.
//!
//! | Sensor | Platform | Source |
//! |--------|----------|--------|
//! | `usn` | Windows | NTFS USN journal |
//! | `rdcw` | Windows | ReadDirectoryChangesW |
//! | `fanotify` | Linux | fanotify mark events |
//! | `poll` | portable | periodic re-scan fallback |
//! | `ads` | Windows | alternate data stream hints |

#[cfg(target_os = "windows")]
pub mod ads;
#[cfg(target_os = "linux")]
pub mod fanotify;
pub mod poll;
#[cfg(target_os = "windows")]
pub mod rdcw;
/// Record-stream parser for rdcw; platform-free so it is tested everywhere.
pub mod rdcw_parse;
pub mod usn;
