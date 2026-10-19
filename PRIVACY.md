# Privacy Policy — Secure Vault

**Effective date:** 17 October 2026  
**Project:** Secure Vault — Personal Offline Password Manager  
**Maintainer:** Khalid Saifullah

## Summary

Secure Vault is designed as a local-first password manager. In the inspected source snapshot, the extension does not implement an account system, cloud vault synchronization, remote password storage, analytics, or telemetry. No remote API or remote script dependency was identified during static inspection of the extension source.

Your browser and operating system still control the security of the device and the websites you visit. When you explicitly use autofill, Secure Vault places the selected credentials into the website's form fields. The website may receive those values if you submit the form.

## Information handled by the extension

### Vault data

The vault can contain account/service names, usernames, passwords, categories, website addresses, notes, and account timestamps. In an installed Chromium extension, the vault record is stored locally using `chrome.storage.local` in an encrypted form.

The encryption metadata stored with the record includes algorithm identifiers, a PBKDF2 salt, AES-GCM initialization vectors, and wrapped-key ciphertext. These values are needed to unlock and decrypt the vault; Base64 is used for serialization and is not itself encryption.

### Master Password and Recovery Key

- The Master Password is used locally to derive a key through PBKDF2-SHA-256. It is not intended to be sent to a server or saved in the vault record.
- A separate cryptographically random Recovery Key is generated during setup. The extension does not store the Recovery Key in its normal encrypted vault record.
- If you choose to download the Recovery Key, the browser saves a plaintext text file at your direction. You are responsible for protecting and deleting that file when appropriate.
- If you lose both the Master Password and Recovery Key, the vault cannot be recovered by the project maintainer.

### Settings and temporary data

The auto-lock preference is stored locally and is not part of the encrypted account payload. The theme preference is stored in extension-page `localStorage`. Decrypted account values and cryptographic key handles are used in application memory while the vault is unlocked. The code attempts to clear sensitive UI and drop in-memory references when locking, but browser JavaScript cannot guarantee forensic erasure of memory.

The storage module also contains a `localStorage` fallback for non-extension/testing contexts where the Chromium extension storage API is unavailable. An installed extension is expected to use `chrome.storage.local` for its vault record.

## How information is used

- To create, unlock, decrypt, display, edit, and save your local vault.
- To generate passwords using the browser's cryptographic random number generator.
- To copy information only when you select a copy action.
- To perform website autofill only after you explicitly select an account and request Fill.
- To enforce your selected inactivity auto-lock setting and manual lock actions. Manual lock is broadcast to other open Secure Vault extension views so their in-memory sessions and sensitive UI are also cleared.
- To export an encrypted backup or restore a backup you select.

Secure Vault does not automatically submit website login forms. You remain responsible for checking the destination website before filling credentials and before submitting a login form.

## Sharing and third parties

The inspected extension source does not contain an implemented cloud service, analytics SDK, telemetry endpoint, or remote API integration. The extension does not request clipboard-read access. It does not have a central account database or password synchronization service.

When you choose website autofill, credentials are inserted into fields in the active website page. That is an intentional transfer to the page you selected. A website may process or transmit those credentials when you submit its form; its own privacy policy then applies.

Your browser, installed extensions, operating system, malware, device backups, and anyone with access to your unlocked device may also affect the confidentiality of your information. Local encryption at rest does not protect a vault that is already unlocked on a compromised device.

## Permissions

| Permission | Why it is requested |
| --- | --- |
| `storage` | Store the encrypted vault record and local settings. |
| `clipboardWrite` | Support user-requested copying. No clipboard-read permission is requested. |
| `alarms` | Schedule auto-lock notifications in the Manifest V3 service worker. |
| `idle` | Detect a system-locked idle state and request locking. |
| `activeTab` | Temporary access to the user-invoked active tab. |
| `scripting` | Inject the autofill routine into a selected website after a user action. |

The manifest does not declare broad host permissions or `<all_urls>`.

## Backups and clipboard

- Exported `.svault.json` files contain an encrypted vault record. Anyone obtaining a backup file may attempt offline password guessing, so use a strong Master Password and keep backups private.
- Restore replaces the current local vault; it does not merge data.
- Password clipboard auto-clear is best-effort. Locking no longer cancels an already scheduled password-clear timer, but it may still not run if the page or popup closes, the browser stops the page, or clipboard access is unavailable. Do not assume copied passwords are automatically removed in every circumstance.
- The Recovery Key download is plaintext and is not the same as an encrypted vault backup.

## Retention and deletion

The encrypted vault record remains in the browser's local extension storage until you reset/delete the vault, clear the relevant browser profile or extension data, or uninstall the extension in a way that removes its stored data. Browser behavior may vary. Export an encrypted backup before removing the extension or clearing browser data if you need to preserve your vault.

Secure Vault does not have a remote account or server-side copy that the maintainer can delete or restore.

## Children's privacy

Secure Vault is a general-purpose password manager and is not designed to collect information from children. The project does not operate a remote collection service in this source snapshot.

## Changes to this policy

This policy may be updated when the extension's behavior, permissions, or data handling changes. The effective date at the top will be revised when that happens. Review this document when installing a new version.

## Contact

For privacy questions, use the repository's GitHub Discussions or issue tracker for non-sensitive questions. Do not post passwords, Recovery Keys, backup files, or other private account information.
