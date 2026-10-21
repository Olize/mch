// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Screenreader-friendly, line-oriented progress. No carriage returns or ANSI.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub(crate) struct Progress {
    copied: AtomicU64,
    finished: AtomicU64,
    total_bytes: u64,
    total_files: u64,
    hash_verification: bool,
    started: Instant,
}

impl Progress {
    pub(crate) fn new(total_bytes: u64, total_files: u64, hash_verification: bool) -> Self {
        Self {
            copied: AtomicU64::new(0),
            finished: AtomicU64::new(0),
            total_bytes,
            total_files,
            hash_verification,
            started: Instant::now(),
        }
    }

    pub(crate) fn add_bytes(&self, bytes: u64) {
        self.copied.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn file_finished(&self) {
        self.finished.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self, successful: Option<bool>) {
        let copied = self.copied.load(Ordering::Relaxed);
        let finished = self.finished.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            copied as f64 / elapsed
        } else {
            0.0
        };
        let percent = if self.total_bytes == 0 {
            if finished == self.total_files {
                100.0
            } else {
                0.0
            }
        } else {
            (copied as f64 * 100.0 / self.total_bytes as f64).min(100.0)
        };
        let eta = if successful == Some(true) {
            String::from("0s")
        } else if rate > 0.0 && copied < self.total_bytes {
            let secs = ((self.total_bytes - copied) as f64 / rate).ceil() as u64;
            format_duration(secs)
        } else {
            String::from("unknown")
        };
        let state = match successful {
            Some(true) if self.hash_verification => "COPY VERIFIED",
            Some(true) => "COPY COMPLETE (NO HASH VERIFICATION)",
            Some(false) => "FAILED",
            None if copied >= self.total_bytes && finished < self.total_files => {
                if self.hash_verification {
                    "VERIFYING"
                } else {
                    "FINALIZING"
                }
            }
            None => "COPYING",
        };
        eprintln!(
            "PROGRESS {state}: {percent:.1}% | {} / {} copied | {finished}/{} files | {}/s | copy ETA {eta}",
            human_bytes(copied),
            human_bytes(self.total_bytes),
            self.total_files,
            human_bytes(rate as u64),
        );
    }
}

fn human_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in ["KiB", "MiB", "GiB", "TiB", "PiB"] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    if unit == "B" {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {unit}")
    }
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

// Called on a scoped thread. Stop immediately when the copy completes;
// don't wait for the reporting interval before returning to the CLI.
pub(crate) fn watch(progress: &Progress, receiver: Receiver<bool>) {
    loop {
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(success) => {
                progress.snapshot(Some(success));
                break;
            }
            Err(RecvTimeoutError::Timeout) => progress.snapshot(None),
            Err(RecvTimeoutError::Disconnected) => {
                progress.snapshot(Some(false));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_byte_units_are_iec() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn duration_is_readable() {
        assert_eq!(format_duration(14), "14s");
        assert_eq!(format_duration(65), "1m 5s");
        assert_eq!(format_duration(3660), "1h 1m");
    }
}
