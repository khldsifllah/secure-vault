# Secure Vault

**A local-first password manager for Chromium-based browsers.** Secure Vault is a Manifest V3 browser extension designed to keep your vault encrypted on your device and make website autofill an explicit user action.

- **Version:** 1.0.1
- **License:** MIT
- **Author / copyright notice:** Khalid Saifullah
- **Primary target:** Helium Browser
- **Other intended browsers:** compatible Chromium-based browsers, subject to local testing

> **Important:** This repository contains the extension source code at its root. There is no build step, Node.js runtime, React/Vite workbench, nested release ZIP, or external runtime package dependency required to load the extension.

## Features

- Master Password protected vault with a separate Recovery Key.
- AES-256-GCM authenticated encryption using the browser's Web Crypto API.
- PBKDF2-SHA-256 key derivation (600,000 iterations, 16-byte random salt).
- Local encrypted vault storage through `chrome.storage.local`.
- Add, edit, delete, search, filter, and sort saved accounts.
- Password generator using `crypto.getRandomValues()` with supported lengths from 8 to 128 characters.
- Copy username/password and best-effort password clipboard clearing; locking no longer cancels an already scheduled password-clear timer.
- Manual lock broadcast across open Secure Vault extension views, with lock-generation guards for pending asynchronous work.
- Configurable inactivity auto-lock (1, 5, 10, 15, 30, 60 minutes, or Never).
- Encrypted JSON backup and authenticated restore.
- Conservative, user-triggered website autofill; it does not submit forms.
- Keyboard shortcuts for opening and locking the vault.
- Light/dark theme support.

## Security model at a glance

### Master Password

- The minimum accepted length for creating or changing a Master Password is **4 characters**.
- **12 or more characters are recommended**. A short password or PIN is substantially easier to guess, especially if it is numeric.
- There is no configured fixed maximum length in the current UI validation.
- Choose a unique password that you do not use elsewhere.

### Encryption and key handling

- Vault data is encrypted with AES-256-GCM.
- The Master Password is processed with PBKDF2-SHA-256 (600,000 iterations) to derive a key that wraps the Vault Encryption Key (VEK).
- A cryptographically random Recovery Key provides a separate way to wrap the VEK.
- The VEK is imported as a non-extractable Web Crypto `CryptoKey` while the vault is unlocked.
- Random salts and 96-bit AES-GCM IVs are generated with the browser's cryptographic random number generator.
- Base64 in the stored record is an encoding format, not encryption.

### What is stored

The extension stores the encrypted vault record in `chrome.storage.local`. Non-sensitive settings such as the auto-lock preference are also stored locally. The current theme preference is stored in extension-page `localStorage`. Plaintext account data is present in application memory while the vault is unlocked so the interface can display and use it.

The extension source contains a `localStorage` fallback for non-extension/testing contexts. In an installed Chromium extension, the browser extension storage API is used for the vault record.

### Recovery Key and backups

- The Recovery Key is shown during initial vault creation. Save it somewhere secure and separate from the device.
- The extension does not persist the Recovery Key as part of its normal local vault record.
- Choosing the Recovery Key download action creates a **plaintext text file containing the Recovery Key**. Protect that file as you would protect a password.
- Exported `.svault.json` backup files contain the encrypted vault record, not plaintext account credentials. Keep backups private and store them safely.
- Restore replaces the current vault; it does not merge accounts. A successful restore leaves the vault locked.

> If you lose both your Master Password and Recovery Key, there is no server-side reset or recovery service. Your encrypted vault may be permanently inaccessible.

## Website autofill

Autofill is initiated by the user from the extension UI. The extension checks the stored website for an account against the current tab and uses conservative hostname matching. It looks for likely username and password fields and fills them only after the user chooses an account and requests Fill.

- Credentials are not automatically injected when a page loads or when navigating between sites.
- Secure Vault does **not** click a website's sign-in button or submit the form.
- When you choose autofill, the credentials are placed into fields on the website you are visiting. That website may receive them if you subsequently submit the form.
- Autofill may not work on browser-internal pages, restricted pages, unusual forms, or sites that prevent extension scripting.

Always verify the website's address before filling credentials.

## Install from source (Load unpacked)

1. Download or clone this repository.
2. Extract the repository if you downloaded a ZIP.
3. Open `chrome://extensions` in Helium Browser or another compatible Chromium browser.
4. Enable **Developer mode**.
5. Choose **Load unpacked**.
6. Select the repository folder that contains `manifest.json` directly.
7. Open Secure Vault and follow the first-time setup flow. Save the Recovery Key before continuing.

This is an unpacked developer installation. Availability and review status on the Chrome Web Store are separate and are not implied by this repository.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+Shift+L` (`Command+Shift+L` on macOS) | Open Secure Vault |
| `Ctrl+Shift+K` (`Command+Shift+K` on macOS) | Lock Secure Vault |

Shortcuts may be changed in the browser's extension-shortcuts settings page. Browser or operating-system conflicts may require choosing another shortcut.

## Manifest permissions

The current `manifest.json` (version 1.0.1) requests the following six permissions:

| Permission | Purpose |
| --- | --- |
| `storage` | Store the encrypted vault record and non-sensitive settings locally using `chrome.storage.local`. |
| `clipboardWrite` | Copy usernames, passwords, and Recovery Keys when the user requests it. The extension does not request clipboard-read access. |
| `alarms` | Schedule background auto-lock notifications. |
| `idle` | Detect the browser's system-locked idle state and request a vault lock. |
| `activeTab` | Obtain temporary access to the active tab in supported user-invoked flows. |
| `scripting` | Run the autofill routine in the active website tab after an explicit user action. |

The manifest does not declare `tabs`, `clipboardRead`, `downloads`, `cookies`, `history`, `webRequest`, `webNavigation`, `nativeMessaging`, broad host permissions, or `<all_urls>`. The extension does query the active tab through the Tabs API in its user-invoked extension flows; sensitive tab information remains subject to Chromium's permission and user-activation rules.

## Project structure

```text
secure-vault/
├── assets/icons/          # Extension icons
├── pages/vault.html       # Full-tab vault interface
├── scripts/
│   ├── autofill.js        # User-triggered form autofill
│   ├── crypto.js          # Web Crypto operations
│   ├── domain-matcher.js  # Conservative website matching
│   ├── password-generator.js
│   ├── storage.js         # Local encrypted-record storage
│   └── vault.js           # Main vault controller
├── styles/
│   ├── theme.css
│   └── vault.css
├── background.js          # Manifest V3 service worker
├── manifest.json
├── popup.html
├── popup.css
├── popup.js
├── README.md
├── LICENSE
├── PRIVACY.md
├── SECURITY.md
├── TESTING.md
├── CONTRIBUTING.md
└── CHANGELOG.md
```

## Compatibility and testing status

The extension uses Chromium Manifest V3 APIs and standard Web Crypto APIs. Helium Browser is the primary target, but actual runtime behavior can vary by browser version and browser-specific extension support.

The maintainer reports that the 1.0.1 build was manually tested in Helium Browser and that the tested features worked without problems. The exact browser version and a reproducible device-side test log were not recorded in this repository, and this is not an independent security certification. The package also passed static checks and 31 focused cryptographic, domain-matching, password-generator, and lock-path regression assertions. See [TESTING.md](TESTING.md) for the scope and limitations of the recorded checks. A successful runtime test does not replace an independent security audit.

## Privacy

See [PRIVACY.md](PRIVACY.md) for the data-handling summary and permission explanations. In this source snapshot, no remote API, analytics, telemetry, or remote script dependency was identified during static inspection. Autofill intentionally inserts the selected credentials into the website you explicitly choose; see the privacy policy for details and limitations.

## Reporting a security issue

Please read [SECURITY.md](SECURITY.md). Do not publish exploitable details or real vault data in a public issue.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Changes to cryptography, storage formats, permission requests, or autofill behavior require particular care and compatibility testing.

## License

This project is distributed under the [MIT License](LICENSE). The copyright notice identifies Khalid Saifullah. Any future third-party components or assets must retain their own required notices and license terms.
