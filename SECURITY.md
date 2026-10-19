# Security Policy

## Supported version

Security work should target the latest code on the repository's default branch and the latest published release. The current source release is version **1.0.1** (`manifest.json`). The maintainer reports successful manual testing in Helium Browser; the exact browser version and a reproducible test log were not recorded, and no independent security certification is claimed.

## Reporting a vulnerability

Please do not publish exploitable vulnerability details, credentials, Recovery Keys, decrypted vault data, or private backup files in a public issue.

Use GitHub's **Report a vulnerability** / private vulnerability reporting feature for this repository when it is enabled. If private reporting is not enabled, open a minimal public issue asking for a private contact channel without including exploit details. The maintainer can then coordinate a private disclosure path.

Please include, where safe:

- A concise description of the issue and its potential impact.
- The affected browser and version.
- The affected Secure Vault version or commit.
- Reproduction steps using dummy credentials and a disposable test vault.
- Any proposed mitigation.

Please allow time for investigation and a fix before publicly disclosing details.

## Security design notes

The current implementation uses:

- Web Crypto API PBKDF2-SHA-256 with 600,000 iterations for Master Password key derivation.
- AES-256-GCM authenticated encryption for vault data and wrapped keys.
- Random salts and IVs generated with `crypto.getRandomValues()`.
- A non-extractable VEK `CryptoKey` while the vault is unlocked.
- Encrypted local vault persistence through `chrome.storage.local`.
- A separate Recovery Key mechanism.
- Manual lock broadcasts across open extension views. Lock-generation checks prevent stale asynchronous operations from restoring decrypted state after a lock signal.
- User-triggered, non-auto-submitting autofill with conservative hostname matching.

These are implementation details, not a guarantee that the extension is free of vulnerabilities. The project has not been represented as independently audited or formally verified.

## Known security limitations

- A Master Password of 4 characters is accepted for user convenience, but is weak. Use a unique password or passphrase of at least 12 characters where practical.
- If both the Master Password and Recovery Key are lost, the vault may be permanently unrecoverable.
- While unlocked, decrypted credentials are present in browser memory. A compromised browser profile, malicious extension, malware, or physical access to an unlocked device can expose them.
- JavaScript cannot guarantee secure forensic wiping of strings or memory.
- Clipboard auto-clear is best-effort. An already scheduled password-clear timer is retained when locking, but page closure, popup closure, browser suspension, or shutdown can still prevent it from running.
- Exported Recovery Key text files are plaintext and must be protected separately.
- Browser-specific extension API behavior can vary between browser versions. The maintainer reports that the 1.0.1 build worked in their Helium Browser testing, but the exact browser version and detailed results were not recorded, and the result is not an independent certification.
- Lock-generation checks stop pending work before later stages and suppress stale completion UI, but a browser API operation already accepted by the browser (for example, a `chrome.scripting.executeScript` autofill injection or a storage write) cannot always be cancelled after dispatch. Users should avoid starting an operation and immediately locking if the operation must not complete.
- The extension's website autofill feature intentionally places credentials into the selected page. Always verify the domain before using it.

## Changes that need security review

Changes to cryptographic algorithms or parameters, key wrapping, AAD, vault schema, local storage, backup/restore, permissions, background message handling, domain matching, or autofill execution should receive focused review and regression testing. Do not introduce remote dependencies, analytics, or broader permissions without documenting the reason and updating the privacy policy.
