# MCH Release Integrity Policy (from v0.2.3)

- Repository setting **Enable release immutability** must be enabled **before** any release is published (verified 2026-10-22 through GitHub's `/immutable-releases` API).
- Release pipeline starts only on a new stable `vX.Y.Z` tag pushed from an ancestor of public `main`. Manual reruns targeting already published releases are deliberately unsupported.
- `verify` rejects pre-existing published releases, tags older than v0.2.3, malformed versions, tags not on `main`, and tags disagreeing with the package version.
- Five platform binaries and the two source archives are built with the exact Rust toolchain version **1.99.1** and pinned GitHub Actions versions. Android output is cross-compiled with Bionic and its dynamic linker explicitly inspected.
- A **draft** release is created only after every build job and archive validation passed. Seven archives and a SHA256SUMS are uploaded **without overwriting** prior assets.
- Exactly eight remote asset digests are rechecked before the draft is made public. GitHub's `immutable` property must be true after publication.
- Incomplete or failed draft builds are deliberately not automatically published. Manual inspection and a **new tag / patch release** are safer than overwriting immutable downloads.
- Old v0.2.2 and earlier artifacts remain mutable: repository immutability changes apply to future releases only. Never use this new workflow to re-upload their assets.
- Releasing code still requires explicit review, independent CI and actual target-platform testing; workflow safeguards do not substitute for review.

Do not create a published release manually before the tag-triggered pipeline completes: GitHub will immediately seal an immutable empty release, preventing attachments.
