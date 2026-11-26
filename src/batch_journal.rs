// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Private experimental multi-file journal V1 record validation.
// Used only by the unmerged Unix --resume-dir pilot, NOT public v0.2.1.
// Full durability, concurrency and hostile state mutation reviews remain open.
use anyhow::{Result, bail, ensure};

const MAGIC: &[u8] = b"MCH-BATCH-JOURNAL-V1\n";
const PLAN_DIGEST_BYTES: usize = 32;
const PAYLOAD_BYTES: usize = 1 + 8 + 32;
const FRAME_BYTES: usize = 4 + PAYLOAD_BYTES + 32;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const VERIFIED_EVENT: u8 = 1;

#[cfg(unix)]
pub(crate) fn journal_header_len() -> usize {
    MAGIC.len() + PLAN_DIGEST_BYTES
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct VerifiedEvent {
    pub(crate) file_index: u64,
    pub(crate) full_file_digest: [u8; 32],
}

// Format: magic, then length:u32 LE + type:u8 + index:u64 LE +
// full-file BLAKE3 digest + BLAKE3 checksum(length+payload).
// Neither a checksum nor a journal claim authorizes skipping a real file hash.
pub(crate) fn encode(events: &[VerifiedEvent], plan_digest: &[u8; 32]) -> Vec<u8> {
    let mut output = MAGIC.to_vec();
    output.extend_from_slice(plan_digest);
    for item in events {
        let mut frame = Vec::with_capacity(FRAME_BYTES);
        frame.extend_from_slice(&(PAYLOAD_BYTES as u32).to_le_bytes());
        frame.push(VERIFIED_EVENT);
        frame.extend_from_slice(&item.file_index.to_le_bytes());
        frame.extend_from_slice(&item.full_file_digest);
        frame.extend_from_slice(blake3::hash(&frame).as_bytes());
        output.extend_from_slice(&frame);
    }
    output
}

pub(crate) fn decode(
    input: &[u8],
    plan_digest: &[u8; 32],
    planned_files: u64,
) -> Result<Vec<VerifiedEvent>> {
    ensure!(input.len() <= MAX_BYTES, "journal size limit exceeded");
    ensure!(input.starts_with(MAGIC), "journal magic/version mismatch");
    ensure!(
        input.len() >= MAGIC.len() + PLAN_DIGEST_BYTES,
        "torn plan binding"
    );
    ensure!(
        &input[MAGIC.len()..MAGIC.len() + PLAN_DIGEST_BYTES] == plan_digest,
        "journal belongs to a different plan"
    );
    let mut remaining = &input[MAGIC.len() + PLAN_DIGEST_BYTES..];
    let mut previous: Option<u64> = None;
    let mut events = Vec::new();

    while !remaining.is_empty() {
        ensure!(remaining.len() >= 4, "torn journal length");
        let length = u32::from_le_bytes(remaining[..4].try_into()?) as usize;
        ensure!(length == PAYLOAD_BYTES, "unknown journal record size");
        ensure!(remaining.len() >= FRAME_BYTES, "torn journal record");
        let frame = &remaining[..FRAME_BYTES];
        let claimed_checksum = &frame[4 + PAYLOAD_BYTES..];
        ensure!(
            blake3::hash(&frame[..4 + PAYLOAD_BYTES]).as_bytes() == claimed_checksum,
            "journal checksum mismatch"
        );
        ensure!(frame[4] == VERIFIED_EVENT, "unknown journal event type");
        let index = u64::from_le_bytes(frame[5..13].try_into()?);
        ensure!(index < planned_files, "journal index is outside job plan");
        if let Some(last) = previous {
            ensure!(index > last, "duplicate or out-of-order journal record");
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&frame[13..45]);
        events.push(VerifiedEvent {
            file_index: index,
            full_file_digest: digest,
        });
        previous = Some(index);
        remaining = &remaining[FRAME_BYTES..];
    }
    if events.len() as u64 > planned_files {
        bail!("too many journal records for plan");
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_digest() -> [u8; 32] {
        *blake3::hash(b"source/target plan: test").as_bytes()
    }

    fn sample() -> Vec<VerifiedEvent> {
        vec![
            VerifiedEvent {
                file_index: 0,
                full_file_digest: *blake3::hash(b"one").as_bytes(),
            },
            VerifiedEvent {
                file_index: 2,
                full_file_digest: *blake3::hash(b"two").as_bytes(),
            },
        ]
    }

    #[test]
    fn seeded_journal_corpus_round_trips_and_rejects_bit_errors() {
        let mut seed = 0x517cc1b727220a95u64;
        for case in 0..2048u64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let plan = *blake3::hash(&case.to_le_bytes()).as_bytes();
            let items: Vec<_> = (0..seed % 17)
                .map(|index| VerifiedEvent {
                    file_index: index * 2,
                    full_file_digest: *blake3::hash(&(seed ^ index).to_le_bytes()).as_bytes(),
                })
                .collect();
            let mut bytes = encode(&items, &plan);
            assert_eq!(decode(&bytes, &plan, 34).unwrap(), items);
            let offset = (seed as usize) % bytes.len();
            bytes[offset] ^= 1 << (case % 8);
            assert!(decode(&bytes, &plan, 34).is_err());
        }
    }

    #[test]
    fn ordered_events_round_trip() {
        let items = sample();
        assert_eq!(
            decode(&encode(&items, &plan_digest()), &plan_digest(), 3).unwrap(),
            items
        );
        assert!(
            decode(&encode(&[], &plan_digest()), &plan_digest(), 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn every_truncated_frame_is_rejected() {
        let bytes = encode(&sample()[..1], &plan_digest());
        for end in MAGIC.len() + PLAN_DIGEST_BYTES + 1..bytes.len() {
            assert!(
                decode(&bytes[..end], &plan_digest(), 3).is_err(),
                "accepted length {end}"
            );
        }
    }

    #[test]
    fn corruption_and_unknown_type_are_rejected() {
        let mut bytes = encode(&sample(), &plan_digest());
        bytes[MAGIC.len() + PLAN_DIGEST_BYTES + 13] ^= 0x40;
        assert!(decode(&bytes, &plan_digest(), 3).is_err());
        let mut bytes = encode(&sample()[..1], &plan_digest());
        let offset = MAGIC.len() + PLAN_DIGEST_BYTES;
        bytes[offset + 4] = 255;
        let checksum_start = offset + 4 + PAYLOAD_BYTES;
        let checksum = blake3::hash(&bytes[offset..checksum_start]);
        bytes[checksum_start..checksum_start + 32].copy_from_slice(checksum.as_bytes());
        assert!(decode(&bytes, &plan_digest(), 3).is_err());
    }

    #[test]
    fn duplicate_reordered_and_out_of_plan_entries_are_rejected() {
        let mut items = sample();
        items[1].file_index = 0;
        assert!(decode(&encode(&items, &plan_digest()), &plan_digest(), 3).is_err());
        items[1].file_index = 1;
        items.swap(0, 1);
        assert!(decode(&encode(&items, &plan_digest()), &plan_digest(), 3).is_err());
        assert!(decode(&encode(&sample(), &plan_digest()), &plan_digest(), 2).is_err());
    }

    #[test]
    fn missing_or_extra_header_bytes_fail_closed() {
        let good = plan_digest();
        let bytes = encode(&[], &good);
        for end in MAGIC.len()..bytes.len() {
            assert!(decode(&bytes[..end], &good, 0).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(decode(&extra, &good, 0).is_err());
    }

    #[test]
    fn mismatched_plan_and_modified_header_are_rejected() {
        let good = plan_digest();
        let mut wrong = good;
        wrong[0] ^= 1;
        let bytes = encode(&sample(), &good);
        assert!(decode(&bytes, &wrong, 3).is_err());
        let mut corrupted = bytes;
        corrupted[MAGIC.len()] ^= 1;
        assert!(decode(&corrupted, &good, 3).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_is_bound_to_exact_filesystem_plan() {
        use crate::batch_plan::JobPlan;
        let temp = tempfile::tempdir().unwrap();
        let physical = std::fs::canonicalize(temp.path()).unwrap();
        let src = physical.join("source");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("one"), b"content").unwrap();
        let p1 = JobPlan::build(&src, &physical.join("target1"))
            .unwrap()
            .fingerprint();
        let p2 = JobPlan::build(&src, &physical.join("target2"))
            .unwrap()
            .fingerprint();
        assert_ne!(p1, p2);
        let bytes = encode(&sample()[..1], &p1);
        assert!(decode(&bytes, &p1, 1).is_ok());
        assert!(decode(&bytes, &p2, 1).is_err());
    }

    #[test]
    fn invalid_magic_and_oversized_journal_are_rejected() {
        assert!(decode(b"invalid", &plan_digest(), 3).is_err());
        assert!(decode(&vec![0u8; MAX_BYTES + 1], &plan_digest(), 3).is_err());
    }
}
