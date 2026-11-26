// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Private experimental Unix-only directory resume pilot.
// Only one directory tree, BLAKE3, copy-only, one worker, no overwrites.
// Existing v0.2.1 single-file resume is deliberately unchanged.
// Batch-stage writes and NO-REPLACE publishing are descriptor-anchored.
// Further adversarial concurrent-write and power-loss review is required.
use crate::{
    Cli, batch_mkdir, batch_plan::JobPlan, batch_store::LockedStore, batch_verify, batch_writer,
};
use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

fn existing_directory(input: &Path, purpose: &str) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(input).with_context(|| {
        format!(
            "{purpose} must be an existing real directory: {}",
            input.display()
        )
    })?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "{purpose} must be an actual directory without a final symlink"
    );
    let canonical = fs::canonicalize(input)?;
    ensure!(
        canonical != Path::new("/"),
        "{purpose} cannot be filesystem root"
    );
    Ok(canonical)
}

fn state_directory(input: &Path, src: &Path, dst: &Path) -> Result<PathBuf> {
    let original = if input.is_absolute() {
        input.to_path_buf()
    } else {
        std::env::current_dir()?.join(input)
    };
    let normalized = original.components().collect::<PathBuf>();
    let real = existing_directory(&normalized, "resume state")?;
    ensure!(
        normalized == real,
        "resume state directory has a symlinked ancestor or a non-normalized path"
    );
    ensure!(
        !real.starts_with(src)
            && !src.starts_with(&real)
            && !real.starts_with(dst)
            && !dst.starts_with(&real),
        "resume state must be outside both the source and destination trees"
    );
    Ok(real)
}

pub(crate) fn run(cli: &Cli) -> Result<()> {
    let src = existing_directory(&cli.sources[0], "source")?;
    let dst = existing_directory(&cli.destination, "destination")?;
    ensure!(
        !src.starts_with(&dst) && !dst.starts_with(&src),
        "source and destination directory trees overlap"
    );
    let state = state_directory(
        cli.resume_dir_state
            .as_deref()
            .context("missing --resume-dir-state")?,
        &src,
        &dst,
    )?;
    // Validation before even opening/creating the persistent lock inode.
    let plan = JobPlan::build(&src, &dst)?;
    let store = LockedStore::open(&state)?;
    let recorded = store.begin(&plan)?;
    let mut next_event = 0usize;
    let mut completed = Vec::with_capacity(usize::try_from(plan.regular_files())?);

    // Create only directories in the immutable plan, relative to pinned
    // target dirfds. No absolute target path is followed below the root.
    batch_mkdir::create_planned_directories(&plan)?;

    for index in 0..plan.regular_files() {
        let item = plan.regular_entry(index)?;
        let relative = std::ffi::OsString::from_vec(item.relative.to_vec());
        let source = src.join(&relative);
        let destination = dst.join(&relative);
        let historical = recorded
            .get(next_event)
            .filter(|record| record.file_index == index);
        let digest = if batch_writer::destination_exists(&plan, index)? {
            let digest = batch_verify::verify_completed(
                &plan,
                index,
                historical.map(|record| &record.full_file_digest),
            )
            .with_context(|| format!("verify existing target {}", destination.display()))?;
            // Publication may have been interrupted after atomic rename but
            // before applying source permissions or removing the manifest.
            // Never touch an ordinary preexisting target without our valid
            // private orphan manifest and lock; rehash again after recovery.
            batch_writer::finalize_recovered(&plan, index)?;
            batch_writer::sync_target_parent(&plan, index)?;
            digest
        } else {
            ensure!(
                historical.is_none(),
                "recorded completed target is missing: {}",
                destination.display()
            );
            // The stage, manifest and atomic no-replace rename are now fully
            // descriptor-relative; the v0.2.1 single-file command is untouched.
            let verified_stage = batch_writer::copy(&plan, index)
                .with_context(|| format!("resume tree file {}", source.display()))?;
            batch_writer::sync_target_parent(&plan, index)?;
            let destination_digest =
                batch_verify::verify_completed(&plan, index, Some(&verified_stage))?;
            ensure!(
                verified_stage == destination_digest,
                "published data was modified"
            );
            destination_digest
        };
        completed.push(digest);
        if historical.is_some() {
            next_event += 1;
            cli.report(
                &format!("RESUME-DIR VERIFIED {}", destination.display()),
                true,
            );
        } else {
            if recorded
                .get(next_event)
                .is_some_and(|entry| entry.file_index > index)
            {
                bail!(
                    "journal has a gap before a completed file: {}",
                    destination.display()
                );
            }
            store.record_verified(&plan, index, digest)?;
            crate::batch_fault::kill_if("recorded_event");
            cli.report(
                &format!("RESUME-DIR CHECKPOINT {}", destination.display()),
                true,
            );
        }
    }

    ensure!(
        next_event == recorded.len(),
        "unexpected trailing journal event"
    );
    // Recheck files completed early in a long job against their independently
    // verified digests. A successful per-file checkpoint can predate a later edit.
    crate::batch_fault::kill_if("before_final_tree_check");
    for (index, digest) in (0u64..).zip(&completed) {
        batch_verify::verify_completed(&plan, index, Some(digest)).with_context(|| {
            format!("final directory verification failed at file {}", index + 1)
        })?;
    }
    // Catch additions/removals and metadata changes in the source directory.
    // Contents of every completed file were independently rehashed above.
    plan.verify_completed_tree(&src, &dst)?;
    // Detect in-session same-size corruption which a coarse filesystem
    // timestamp could miss in the O(1) per-event fast path.
    store.verify_final(&plan)?;
    if !cli.quiet {
        println!(
            "DONE: {} verified regular files; directory resume state retained",
            plan.regular_files()
        );
    }
    Ok(())
}
