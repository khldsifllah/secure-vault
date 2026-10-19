# Contributing

Thank you for your interest in improving Secure Vault. This project handles highly sensitive data, so correctness, minimal permissions, and compatibility are more important than adding features quickly.

## Before making a change

1. Open an issue for a bug or proposed feature where practical.
2. Describe the user-visible behavior and any security or privacy impact.
3. Keep changes focused and avoid unrelated refactoring.
4. Do not include real credentials, Recovery Keys, vault backups, browser profile data, or personal information in issues or pull requests.

## Development setup

Secure Vault is a self-contained Manifest V3 extension. It does not require a build step or package installation for normal development.

1. Clone or download the repository.
2. Open `chrome://extensions` in a compatible Chromium-based browser.
3. Enable Developer mode and select **Load unpacked**.
4. Select the repository root containing `manifest.json`.
5. Use a disposable test vault and dummy credentials for testing.

Helium Browser is the primary target, but changes should be checked in the browser versions they claim to support.

## Change guidelines

- Keep runtime code self-contained and local. Do not add remote scripts, CDNs, analytics, telemetry, or cloud credential services.
- Do not add a dependency or asset copied from another project without checking its license and preserving any required notice.
- Do not broaden permissions or add host permissions without a clear technical need, user-facing explanation, and corresponding README/PRIVACY updates.
- Never log Master Passwords, Recovery Keys, VEKs, plaintext credentials, or decrypted vault records.
- Preserve the current minimum Master Password length of 4 characters, the recommendation of 12+ characters, and the absence of a configured maximum unless a separately reviewed product decision changes them.
- Preserve backup compatibility and existing vault records unless a migration is explicitly designed and tested.
- Autofill must remain user-triggered and must not submit forms automatically.
- Prefer safe DOM APIs and avoid injecting untrusted HTML.

## Testing checklist

At minimum, test the relevant flows with a disposable profile and dummy data:

- Manifest JSON parses and the extension loads without errors.
- First-time vault creation, Recovery Key display, and unlock.
- Minimum-length and longer Master Password setup/change/recovery behavior.
- Add, edit, delete, search, filter, sort, and password reveal/hide.
- Password generation at boundary lengths and selected character sets.
- Manual lock, inactivity auto-lock, system lock, and keyboard shortcuts.
- Encrypted backup export; restore with the correct credential; reject incorrect credentials and malformed/tampered backup files.
- Domain-matching positive and negative cases, including spoofed domains and sibling subdomains.
- User-triggered autofill into supported test forms; verify that no automatic form submission occurs.
- Locking and restore clear sensitive interface state and leave restored vaults locked.

There is no claim that this repository currently includes an automated test suite. Record the browser/version and manual test results in the pull request.

## Pull requests

A useful pull request includes:

- What changed and why.
- Screenshots for UI changes where helpful (with dummy data only).
- Browser/version and steps used to test.
- Permission, privacy, storage-schema, or cryptographic impact.
- Documentation updates where behavior or setup changed.

The MIT License applies to contributions unless a different arrangement is agreed in writing. By submitting a contribution, you confirm that you have the right to submit it under that license.
