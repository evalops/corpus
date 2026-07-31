//! Filesystem event sensors.
//!
//! Linux uses fanotify mount marks where privileges permit (spec 10.10);
//! Windows uses ReadDirectoryChangesW plus USN journal recovery
//! (user-mode fallback; a signed minifilter is the production design);
//! every platform has the periodic reconciliation-scan fallback. Sensor
//! queue loss is a coverage gap, never a silent miss (spec 2.2).

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
