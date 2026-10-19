# Testing and Release Validation

**Release:** Secure Vault 1.0.1  
**Validation date:** 2026-10-18  
**Status:** Source-level checks passed; the maintainer reports successful manual testing in Helium Browser.

This report distinguishes reproducible source-level checks from maintainer-reported browser testing. The exact Helium version and a detailed device-side test log were not recorded, so this is not an independent browser certification.

## Automated checks completed

- All 8 JavaScript source files passed `node --check` syntax validation.
- `manifest.json` parsed as valid JSON; manifest version is `1.0.1` and the six declared permissions match the permission documentation.
- The release ZIP passed archive integrity testing and contains the extension source plus project documentation only; no nested ZIP, AI Studio React/Vite workbench, `node_modules`, or local build output is included.
- 31 focused assertions passed in an isolated test harness:
  - PBKDF2-SHA-256 Master Password key derivation and non-extractable key properties.
  - 256-bit Recovery Key parse, key wrapping and unwrapping.
  - AES-256-GCM encrypted-vault round trip, tamper rejection, and Master Password re-wrap.
  - Strict encrypted-record validation and wrong-password rejection.
  - 13 conservative domain-matching cases, including spoofed-domain and unrelated-service rejection.
  - Cryptographic password generation and invalid-option rejection.
  - Source regression checks for lock-generation invalidation, sensitive-form clearing, cross-view lock messaging, clipboard-timer retention, autofill/backup async guards.

## Manual browser testing (maintainer-reported)

The maintainer reports that they tested the extension in Helium Browser and that everything worked without problems. The exact Helium version, operating system build, and per-test evidence were not recorded in this report. The following checklist describes the key runtime areas that should be rechecked after significant changes or when validating another browser version:

1. Install the unpacked extension and confirm Manifest V3 service worker startup.
2. Create a vault with a 4-character Master Password; confirm that 12+ characters are recommended but not mandatory.
3. Open the popup and two full-tab vault views, unlock them, manually lock from each view in turn, and verify all other open views return to the locked screen and clear sensitive fields.
4. Trigger Lock while unlock, account save/delete, Recovery Key recovery, backup verification, backup restore, and active-tab lookup are pending; verify stale callbacks do not restore decrypted UI or show stale success notices.
5. Copy a password, lock the vault, and verify the scheduled best-effort clipboard expiry still runs at its original deadline. Repeat after copying a username or a generated password.
6. Test account create/edit/delete, search, category filtering, password show/hide, password change, Recovery Key recovery, encrypted backup export/import, and wrong-credential handling.
7. Test inactivity auto-lock, OS/system-lock behavior, keyboard shortcuts, and popup close/reopen behavior.
8. Test user-triggered autofill on representative sites and confirm it never submits forms automatically or fills unrelated text fields.
9. Re-check the extension permissions and browser-console/service-worker logs for errors.

Clipboard clearing is best-effort; browsers may restrict clipboard access or suspend/close a page before its timer fires. An already-dispatched browser API operation cannot always be cancelled after Lock.

## Release decision

The maintainer-reported Helium test is recorded as passed with no problems reported. This supports publishing the 1.0.1 source, while noting that the test was not independently reproduced and the exact browser version was not recorded. This project has not undergone an independent professional security audit or formal verification.
