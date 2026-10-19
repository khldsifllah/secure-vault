# Changelog

Notable project changes are documented here. This changelog describes the current source baseline; it is not a statement that every browser has completed runtime certification.

## [1.0.1] — 2026-10-18 (security and reliability release)

### Security and reliability fixes

- Manual lock now broadcasts to other open Secure Vault extension views, including the popup and full-tab vault.
- A per-view lock generation invalidates pending unlock, recovery, account-write, backup, and restore operations so stale async results cannot repopulate decrypted in-memory state after a lock.
- Lock clears Master Password, Recovery Key, account-password, generated-password, recovery-display, and restore credential inputs, and closes sensitive modals.
- Lock no longer cancels an already scheduled password clipboard-expiry timer; clipboard clearing remains best-effort and may be interrupted by page or browser closure.
- Successful vault reset and backup restore now request a global lock in other open extension views.
- Pending autofill tab queries and backup-file reads now check the lock generation before continuing; stale completion notices are suppressed after a lock.
- Clipboard-copy handlers retain an existing password-expiry timer until a replacement clipboard write succeeds, and clear newly written content when the lock wins the async race.

### Validation status

- JavaScript syntax, manifest structure, archive integrity, and focused Web Crypto/domain-matching regression checks passed in the build environment.
- The maintainer reports that the release was manually tested in Helium Browser and that the tested features worked without problems. The exact browser version and a detailed test log were not recorded; this is not an independent certification.

## [1.0.0] — 2026-10-17

### Added

- Manifest V3 Chromium extension with a dedicated full-tab vault and popup launcher.
- Master Password setup, unlock, change, and Recovery Key recovery flows.
- AES-256-GCM vault encryption and PBKDF2-SHA-256 key derivation.
- Local encrypted vault storage and schema validation.
- Account creation, editing, deletion, search, filtering, and sorting.
- Password generator using the browser's cryptographic random number generator.
- Password copy, temporary reveal, and best-effort clipboard clearing.
- Configurable auto-lock, system-lock handling, and manual lock.
- Encrypted backup export and authenticated restore.
- Conservative domain matching and user-triggered website autofill without automatic form submission.
- Keyboard shortcuts, themes, extension icons, and source-install instructions.
- Public project documentation and MIT license.

### Packaging

- Kept the canonical extension source at the repository root.
- Excluded the AI Studio React/Vite development workbench and duplicate nested extension ZIP from the source repository.
