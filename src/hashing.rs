// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::HashAlg;
use anyhow::{Context, Result};
use sha2::Digest;
use std::fs::File;
use std::io::Read;
use std::path::Path;

// An interrupted read is not EOF or corrupted data; try the same read again.
fn read_retry(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match file.read(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

pub(crate) fn hash_file(path: &Path, algorithm: HashAlg) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open for hashing: {}", path.display()))?;
    let mut buffer = vec![0_u8; 1024 * 1024];

    macro_rules! hash_digest {
        ($type:ty) => {{
            let mut hasher = <$type>::new();
            loop {
                let n = read_retry(&mut file, &mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }};
    }

    match algorithm {
        HashAlg::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = read_retry(&mut file, &mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlg::Sha256 => hash_digest!(sha2::Sha256),
        HashAlg::Sha512 => hash_digest!(sha2::Sha512),
        HashAlg::Sha3_256 => hash_digest!(sha3::Sha3_256),
        HashAlg::Sha3_512 => hash_digest!(sha3::Sha3_512),
        HashAlg::Blake2b => hash_digest!(blake2::Blake2b512),
        HashAlg::Blake2s => hash_digest!(blake2::Blake2s256),
        HashAlg::Xxh3 => {
            let mut hasher = xxhash_rust::xxh3::Xxh3::new();
            loop {
                let n = read_retry(&mut file, &mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Ok(format!("{:016x}", hasher.digest()))
        }
    }
}
