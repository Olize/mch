// SPDX-License-Identifier: AGPL-3.0-or-later
// Debug builds only: deterministic crash injection for PRIVATE batch resume.
// No fault-injection environment variable is read in optimized release builds.
#[inline]
pub(crate) fn kill_if(point: &str) {
    #[cfg(debug_assertions)]
    {
        if std::env::var("MCH_BATCH_TEST_PAUSE_AT").ok().as_deref() == Some(point) {
            let marker = std::env::var("MCH_BATCH_TEST_GATE")
                .expect("pause injection must specify isolated test gate");
            let ready = std::path::Path::new(&marker);
            std::fs::write(ready, point).expect("create test-only ready marker");
            let go = std::path::PathBuf::from(format!("{marker}.go"));
            let mut released = false;
            for _ in 0..1000 {
                if go.exists() {
                    released = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(released, "test-only pause gate timed out");
        }
        if std::env::var("MCH_BATCH_TEST_SIGKILL_AT").ok().as_deref() == Some(point) {
            // SAFETY: signal only our own process at an explicitly selected
            // fault-injection point in a debug build.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            std::process::abort();
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = point;
}
