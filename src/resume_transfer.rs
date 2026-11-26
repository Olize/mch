// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Cli;
use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

const BLOCK: usize = 1024 * 1024;

// Every staged byte is compared anew against CURRENT source content.
pub(super) fn verify_prefix(source: &mut File, stage: &mut File, bytes: u64) -> Result<()> {
    source.seek(SeekFrom::Start(0))?;
    stage.seek(SeekFrom::Start(0))?;
    let mut left = bytes;
    let mut source_buf = vec![0_u8; BLOCK];
    let mut stage_buf = vec![0_u8; BLOCK];
    while left > 0 {
        let n = left.min(BLOCK as u64) as usize;
        source
            .read_exact(&mut source_buf[..n])
            .context("read source during resume-prefix verification")?;
        stage
            .read_exact(&mut stage_buf[..n])
            .context("read staging during resume-prefix verification")?;
        if source_buf[..n] != stage_buf[..n] {
            bail!(
                "resume prefix mismatch: partial copy differs from current source; refusing to overwrite"
            );
        }
        left -= n as u64;
    }
    Ok(())
}

fn show_transfer(copied: u64, reused: u64, total: u64, since: Instant, finished: bool) {
    let copied_total = copied.saturating_add(reused);
    let percent = if total == 0 {
        100.0
    } else {
        (copied_total as f64 * 100.0 / total as f64).min(100.0)
    };
    let seconds = since.elapsed().as_secs_f64().max(0.001);
    let rate = copied as f64 / seconds;
    let eta = if copied_total == total {
        String::from("0s")
    } else if rate > 0.0 {
        format!("{}s", ((total - copied_total) as f64 / rate).ceil() as u64)
    } else {
        String::from("unknown")
    };
    eprintln!(
        "RESUME {}: {percent:.1}% | {reused} B existing verified | {copied} B newly copied | {total} B total | {:.1} MiB/s new-data rate | copy ETA {eta}",
        if finished { "COPIED" } else { "COPYING" },
        rate / 1048576.0
    );
}

pub(super) fn transfer(
    cli: &Cli,
    source: &mut File,
    stage: &mut File,
    reused: u64,
    total: u64,
) -> Result<()> {
    let bytes_written = AtomicU64::new(0);
    let began = Instant::now();
    std::thread::scope(|scope| -> Result<()> {
        let (done, receiver) = mpsc::channel::<()>();
        let tracker = &bytes_written;
        let reporter = if cli.show_progress() {
            Some(scope.spawn(move || {
                loop {
                    match receiver.recv_timeout(Duration::from_millis(cli.progress_interval_ms)) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                            show_transfer(
                                tracker.load(Ordering::Relaxed),
                                reused,
                                total,
                                began,
                                true,
                            );
                            break;
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            show_transfer(
                                tracker.load(Ordering::Relaxed),
                                reused,
                                total,
                                began,
                                false,
                            );
                        }
                    }
                }
            }))
        } else {
            None
        };
        let result = (|| {
            source.seek(SeekFrom::Start(reused))?;
            stage.seek(SeekFrom::Start(reused))?;
            let mut buffer = vec![0_u8; BLOCK];
            let mut remaining = total - reused;
            while remaining != 0 {
                let size = remaining.min(BLOCK as u64) as usize;
                source
                    .read_exact(&mut buffer[..size])
                    .context("read source while resuming")?;
                stage
                    .write_all(&buffer[..size])
                    .context("write persistent resume staging")?;
                bytes_written.fetch_add(size as u64, Ordering::Relaxed);
                remaining -= size as u64;
            }
            stage.flush().context("flush staged resume data")?;
            stage.sync_all().context("sync staged resume data")?;
            Ok(())
        })();
        let _ = done.send(());
        if let Some(reporter) = reporter {
            reporter
                .join()
                .map_err(|_| anyhow!("resume progress thread panicked"))?;
        }
        result
    })
}
