//! Filesystem event sensors.
//!
//! Linux uses fanotify mount marks where privileges permit (spec 10.10);
//! every platform has the periodic reconciliation-scan fallback. Sensor
//! queue loss is a coverage gap, never a silent miss (spec 2.2).

pub mod poll;
#[cfg(target_os = "linux")]
pub mod fanotify;
