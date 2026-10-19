/**
 * Secure Vault - Dedicated Vault Page Script (Manifest V3 - Stage 3 Final Hardened)
 *
 * Architecture Role (Single Source of Truth):
 * - First-time Master Password setup
 * - 256-bit Recovery Key generation, display, copy & download
 * - Native PBKDF2-SHA-256 (600,000 iterations) key derivation
 * - Hardened VEK handling: VEK is strictly non-extractable in memory
 * - AES-256-GCM vault encryption & decryption
 * - Recovery flow with new Master Password establishment
 * - Change Master Password (re-wrapping existing VEK via rewrapVaultKey)
 * - Destructive Vault Reset (permanent erasure)
 * - Manual Lock action
 * - STAGE 3 ACCOUNT MANAGEMENT (Final Hardened):
 *   * Never treat a malformed existing vault as "no vault" (Case A, B, C, D distinct handling)
 *   * Existing records (even if malformed) strictly prevent accidental overwrite in createVault
 *   * Form submit events are the SINGLE source of truth; zero duplicate click handlers on submit buttons
 *   * Async submission guards (isSavingAccount, isUnlocking, etc.) prevent double execution
 *   * Multi-tab safety: Web Locks API ('secure-vault-write') serializes vault writes across tabs
 *   * Inside write lock: loads latest stored record, decrypts, applies candidate, encrypts with new IV, saves, commits
 *   * Candidate-first transaction safety: failures keep decryptedVault 100% unchanged
 *   * Protocol-validated website URLs (http: and https: only; reject javascript:, data:, etc.)
 *   * Safe DOM rendering via document.createElement & textContent for website links
 *   * Categories: Gmail, Social, Work, Other (default Other) with backward-compatible display
 *
 * NEVER persists or logs secrets (Master Password, Recovery Key, VEK, or decrypted accounts).
 */

import {
  generateSalt,
  generateRecoveryKey,
  parseRecoveryKey,
  importAesGcmKey,
  deriveMasterKey,
  createAndWrapVaultKey,
  unwrapVaultKey,
  rewrapVaultKey,
  encryptVault,
  decryptVault,
  bytesToBase64,
  base64ToBytes,
  AAD_VAULT,
  AAD_MASTER_KEY,
  AAD_RECOVERY_KEY
} from './crypto.js';

import { StorageModule } from './storage.js';

import {
  generatePassword,
  validateGeneratorOptions,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  DEFAULT_PASSWORD_LENGTH
} from './password-generator.js';

import {
  extractHostname,
  findMatchingAccounts,
  isDomainMatch
} from './domain-matcher.js';

import { triggerTabAutofill } from './autofill.js';

document.addEventListener('DOMContentLoaded', async () => {
  // In-Memory Secrets (Strictly cleared on Lock / Reset)
  let activeVek = null; // Non-extractable CryptoKey
  let decryptedVault = null; // { schemaVersion: 2, accounts: [] }
  let tempRecoveryCryptoKey = null;
  let generatedRecoveryKeyFormatted = '';
  let currentEditAccountId = null;
  let currentDeleteAccountId = null;
  let currentVaultRevision = 1; // Non-secret metadata tracking
  let noticeTimeout = null;

  // Stage 4 In-Memory State (Never persisted)
  const revealedPasswordAccountIds = new Set(); // accountId Set for unmasked passwords
  const passwordRevealTimers = new Map(); // accountId -> timerId (30-second auto-masking)
  let clipboardClearTimer = null; // Active timer for 30-second password clipboard auto-clear
  let clipboardCopyVersion = 0; // Monotonic token to avoid timer race conditions
  let currentCategoryFilter = 'All'; // Filter chip: All, Gmail, Social, Work, Other
  let currentSearchQuery = ''; // Case-insensitive query
  let currentSortOption = 'recently-updated'; // recently-updated, recently-added, name-asc, name-desc, category-asc

  // Async Submission Guards (Prevent concurrent double-execution)
  let isCreatingVault = false;
  let isUnlocking = false;
  let isRecovering = false;
  let isSavingNewPass = false;
  let isChangingPassword = false;
  let isSavingAccount = false;
  let isDeletingAccount = false;
  let isResettingVault = false;

  // Stage 6 In-Memory State (Never persisted)
  let lastActivityAt = Date.now();
  let autoLockMinutes = 5; // Options: 1, 5, 10, 15, 30, 60, 0 (0 = Never)
  let autoLockTimer = null;
  let activityThrottleTimer = null;
  let pendingRestoreRecord = null;
  let pendingRestoreDecrypted = null;
  let restoreAuthMode = 'password'; // 'password' | 'recovery'
  let isExportingBackup = false;
  let isRestoringBackup = false;
  let failedUnlockAttempts = 0; // In-memory progressive delay counter for wrong Master Password

  // A lock generation invalidates asynchronous work that started before a lock event.
  let lockGeneration = 0;
  const viewInstanceId = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `vault-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  function isLockGenerationCurrent(generation, vekReference) {
    return generation === lockGeneration &&
      (vekReference === undefined || activeVek === vekReference);
  }

  function clearSensitiveFormInputs() {
    const sensitiveElements = [
      vaultPageUnlockPassword, vaultPageSetupPassword, vaultPageSetupConfirm,
      vaultPageRecoveryKeyInput, vaultPageNewPass, vaultPageNewPassConfirm,
      modalCurPass, modalNewPass, modalConfirmPass,
      accountFormPassword, generatorPreviewInput,
      restoreMasterPasswordInput, restoreRecoveryKeyInput,
      vaultPageRecoveryKeyText
    ];

    for (const element of sensitiveElements) {
      if (!element) continue;
      if ('value' in element) element.value = '';
      if (element === vaultPageRecoveryKeyText) element.textContent = '';
    }

    // Also clear password inputs added by future UI changes unless explicitly exempted.
    document.querySelectorAll('input[type="password"], [data-sensitive="true"]').forEach((element) => {
      if ('value' in element) element.value = '';
      if (element.isContentEditable) element.textContent = '';
    });
  }

  function broadcastGlobalLock(reason = 'manual') {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'LOCK_VAULT',
          sourceId: viewInstanceId,
          reason
        }).catch(() => {});
      }
    } catch (_) {}
  }

  /**
   * Progressive delay schedule for repeated Master Password failures:
   * 1st failure: 0 ms
   * 2nd failure: 500 ms
   * 3rd failure: 1000 ms
   * 4th failure: 2000 ms
   * 5th and later: 5000 ms maximum
   */
  function getUnlockDelay(attempts) {
    if (attempts <= 0) return 0;
    if (attempts === 1) return 500;
    if (attempts === 2) return 1000;
    if (attempts === 3) return 2000;
    return 5000;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // Issue 3: Master Password policy (Minimum 4 characters; 12+ recommended)
  const MIN_MASTER_PASSWORD_LENGTH = 4;

  function validateMasterPassword(password) {
    if (!password || typeof password !== 'string' || password.length < MIN_MASTER_PASSWORD_LENGTH) {
      return {
        valid: false,
        error: `Master Password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`
      };
    }
    return { valid: true, error: null };
  }

  // DOM Elements - Shell & Navbar
  const htmlRoot = document.documentElement;
  const vaultThemeToggleBtn = document.getElementById('vaultThemeToggleBtn');
  const vaultThemeIconDark = document.getElementById('vaultThemeIconDark');
  const vaultThemeIconLight = document.getElementById('vaultThemeIconLight');
  const lockVaultBtn = document.getElementById('lockVaultBtn');
  const vaultOpenChangePassBtn = document.getElementById('vaultOpenChangePassBtn');
  const vaultOpenResetBtn = document.getElementById('vaultOpenResetBtn');
  const vaultAddAccountBtn = document.getElementById('vaultAddAccountBtn');

  // Stage 4 Search & Filter Controls
  const vaultSearchInput = document.getElementById('vaultSearchInput');
  const vaultFilterSortToolbar = document.getElementById('vaultFilterSortToolbar');
  const categoryChipsGroup = document.getElementById('categoryChipsGroup');
  const vaultSortSelect = document.getElementById('vaultSortSelect');
  const vaultSearchEmptyState = document.getElementById('vaultSearchEmptyState');

  // Notification Toast Elements (Stage 3 compact toast system)
  const vaultNotification = document.getElementById('vaultNotification');
  const vaultNotificationText = document.getElementById('vaultNotificationText');
  const vaultNotificationIcon = document.getElementById('vaultNotificationIcon');
  const vaultNotificationCloseBtn = document.getElementById('vaultNotificationCloseBtn');

  // Accounts Section & Empty State
  const accountCountLabel = document.getElementById('accountCountLabel');
  const vaultEmptyState = document.getElementById('vaultEmptyState');
  const emptyAddAccountBtn = document.getElementById('emptyAddAccountBtn');
  const vaultAccountsSection = document.getElementById('vaultAccountsSection');
  const accountsListContainer = document.getElementById('accountsListContainer');

  // Auth Overlay & Cards
  const vaultAuthOverlay = document.getElementById('vaultAuthOverlay');
  const vaultLockedCard = document.getElementById('vaultLockedCard');
  const vaultSetupCard = document.getElementById('vaultSetupCard');
  const vaultRecoveryDisplayCard = document.getElementById('vaultRecoveryDisplayCard');
  const vaultRecoveryInputCard = document.getElementById('vaultRecoveryInputCard');
  const vaultSetNewPassCard = document.getElementById('vaultSetNewPassCard');

  // Forms (Single source of truth for form submits)
  const vaultPageUnlockForm = document.getElementById('vaultPageUnlockForm');
  const vaultPageSetupForm = document.getElementById('vaultPageSetupForm');
  const vaultPageSetNewPassForm = document.getElementById('vaultPageSetNewPassForm');
  const vaultChangePassForm = document.getElementById('vaultChangePassForm');
  const vaultAccountForm = document.getElementById('vaultAccountForm');

  // Unlock Controls
  const vaultPageUnlockPassword = document.getElementById('vaultPageUnlockPassword');
  const vaultPageUnlockBtn = document.getElementById('vaultPageUnlockBtn');
  const vaultPageGotoRecoverBtn = document.getElementById('vaultPageGotoRecoverBtn');
  const vaultPageGotoResetBtn = document.getElementById('vaultPageGotoResetBtn');

  // Setup Controls
  const vaultPageSetupPassword = document.getElementById('vaultPageSetupPassword');
  const vaultPageSetupConfirm = document.getElementById('vaultPageSetupConfirm');
  const vaultPageCreateBtn = document.getElementById('vaultPageCreateBtn');

  // Recovery Display Controls
  const vaultPageRecoveryKeyText = document.getElementById('vaultPageRecoveryKeyText');
  const vaultPageCopyRecoveryBtn = document.getElementById('vaultPageCopyRecoveryBtn');
  const vaultPageDownloadRecoveryBtn = document.getElementById('vaultPageDownloadRecoveryBtn');
  const vaultPageConfirmSavedRecoveryBtn = document.getElementById('vaultPageConfirmSavedRecoveryBtn');

  // Recovery Input Controls
  const vaultPageRecoveryKeyInput = document.getElementById('vaultPageRecoveryKeyInput');
  const vaultPageSubmitRecoveryBtn = document.getElementById('vaultPageSubmitRecoveryBtn');
  const vaultPageCancelRecoveryBtn = document.getElementById('vaultPageCancelRecoveryBtn');

  // Set New Password Controls
  const vaultPageNewPass = document.getElementById('vaultPageNewPass');
  const vaultPageNewPassConfirm = document.getElementById('vaultPageNewPassConfirm');
  const vaultPageSaveNewPassBtn = document.getElementById('vaultPageSaveNewPassBtn');

  // Modals - Change Password
  const vaultChangePassModal = document.getElementById('vaultChangePassModal');
  const vaultCloseChangePassBtn = document.getElementById('vaultCloseChangePassBtn');
  const modalCancelChangePassBtn = document.getElementById('modalCancelChangePassBtn');
  const modalSubmitChangePassBtn = document.getElementById('modalSubmitChangePassBtn');
  const modalCurPass = document.getElementById('modalCurPass');
  const modalNewPass = document.getElementById('modalNewPass');
  const modalConfirmPass = document.getElementById('modalConfirmPass');

  // Modals - Reset Vault
  const vaultResetModal = document.getElementById('vaultResetModal');
  const vaultCloseResetBtn = document.getElementById('vaultCloseResetBtn');
  const vaultCancelResetBtn = document.getElementById('vaultCancelResetBtn');
  const vaultConfirmResetBtn = document.getElementById('vaultConfirmResetBtn');
  const vaultPageResetInput = document.getElementById('vaultPageResetInput');

  // Modals - Add / Edit Account (Stage 3)
  const vaultAccountModal = document.getElementById('vaultAccountModal');
  const vaultAccountModalTitle = document.getElementById('vaultAccountModalTitle');
  const vaultCloseAccountModalBtn = document.getElementById('vaultCloseAccountModalBtn');
  const accountFormName = document.getElementById('accountFormName');
  const accountFormUsername = document.getElementById('accountFormUsername');
  const accountFormPassword = document.getElementById('accountFormPassword');
  const accountFormCategory = document.getElementById('accountFormCategory');
  const accountFormWebsite = document.getElementById('accountFormWebsite');
  const accountFormNotes = document.getElementById('accountFormNotes');
  const accountFormCancelBtn = document.getElementById('accountFormCancelBtn');
  const accountFormSubmitBtn = document.getElementById('accountFormSubmitBtn');

  // Modals - Delete Account (Stage 3)
  const vaultDeleteModal = document.getElementById('vaultDeleteModal');
  const vaultCloseDeleteModalBtn = document.getElementById('vaultCloseDeleteModalBtn');
  const deleteAccountTargetName = document.getElementById('deleteAccountTargetName');
  const vaultCancelDeleteBtn = document.getElementById('vaultCancelDeleteBtn');
  const vaultConfirmDeleteBtn = document.getElementById('vaultConfirmDeleteBtn');

  // Modals - Password Generator (Stage 5)
  const vaultOpenGeneratorBtn = document.getElementById('vaultOpenGeneratorBtn');
  const accountFormGenerateBtn = document.getElementById('accountFormGenerateBtn');
  const vaultGeneratorModal = document.getElementById('vaultGeneratorModal');
  const vaultCloseGeneratorBtn = document.getElementById('vaultCloseGeneratorBtn');
  const generatorPreviewInput = document.getElementById('generatorPreviewInput');
  const generatorRegenBtn = document.getElementById('generatorRegenBtn');
  const generatorCopyBtn = document.getElementById('generatorCopyBtn');
  const generatorErrorBanner = document.getElementById('generatorErrorBanner');
  const generatorErrorText = document.getElementById('generatorErrorText');
  const generatorLengthInput = document.getElementById('generatorLengthInput');
  const generatorLengthRange = document.getElementById('generatorLengthRange');
  const genOptUppercase = document.getElementById('genOptUppercase');
  const genOptLowercase = document.getElementById('genOptLowercase');
  const genOptNumbers = document.getElementById('genOptNumbers');
  const genOptSymbols = document.getElementById('genOptSymbols');
  const generatorUseInFormBtn = document.getElementById('generatorUseInFormBtn');
  const generatorDoneBtn = document.getElementById('generatorDoneBtn');

  // Stage 5 Generator State (In-memory only)
  let generatorTargetInputField = null;

  // Stage 6 DOM Elements - Settings Modal
  const vaultOpenSettingsBtn = document.getElementById('vaultOpenSettingsBtn');
  const vaultSettingsModal = document.getElementById('vaultSettingsModal');
  const vaultCloseSettingsBtn = document.getElementById('vaultCloseSettingsBtn');
  const vaultCloseSettingsBtn2 = document.getElementById('vaultCloseSettingsBtn2');
  const autoLockSelect = document.getElementById('autoLockSelect');
  const settingsLockNowBtn = document.getElementById('settingsLockNowBtn');
  const settingsExportBackupBtn = document.getElementById('settingsExportBackupBtn');
  const settingsRestoreBackupBtn = document.getElementById('settingsRestoreBackupBtn');

  // Stage 6 DOM Elements - Restore Modal
  const vaultRestoreModal = document.getElementById('vaultRestoreModal');
  const vaultCloseRestoreBtn = document.getElementById('vaultCloseRestoreBtn');
  const backupFileInput = document.getElementById('backupFileInput');
  const selectBackupFileBtn = document.getElementById('selectBackupFileBtn');
  const backupFileInfo = document.getElementById('backupFileInfo');
  const restoreErrorBanner = document.getElementById('restoreErrorBanner');
  const restoreErrorText = document.getElementById('restoreErrorText');
  const restoreStepFile = document.getElementById('restoreStepFile');
  const restoreStepAuth = document.getElementById('restoreStepAuth');
  const restoreFileMetaText = document.getElementById('restoreFileMetaText');
  const restoreAuthModePassBtn = document.getElementById('restoreAuthModePassBtn');
  const restoreAuthModeRecoveryBtn = document.getElementById('restoreAuthModeRecoveryBtn');
  const restorePassGroup = document.getElementById('restorePassGroup');
  const restoreMasterPasswordInput = document.getElementById('restoreMasterPasswordInput');
  const restoreRecoveryGroup = document.getElementById('restoreRecoveryGroup');
  const restoreRecoveryKeyInput = document.getElementById('restoreRecoveryKeyInput');
  const restoreVerifyBtn = document.getElementById('restoreVerifyBtn');
  const restoreStepConfirm = document.getElementById('restoreStepConfirm');
  const restoreCancelBtn = document.getElementById('restoreCancelBtn');
  const restoreCommitBtn = document.getElementById('restoreCommitBtn');

  // Stage 6 DOM Elements - Auth Screen Restore Triggers & Error Cards
  const vaultLockedRestoreBtn = document.getElementById('vaultLockedRestoreBtn');
  const vaultSetupRestoreBtn = document.getElementById('vaultSetupRestoreBtn');
  const vaultCorruptedCard = document.getElementById('vaultCorruptedCard');
  const vaultCorruptedRetryBtn = document.getElementById('vaultCorruptedRetryBtn');
  const vaultCorruptedRestoreBtn = document.getElementById('vaultCorruptedRestoreBtn');
  const vaultStorageErrorCard = document.getElementById('vaultStorageErrorCard');
  const vaultStorageRetryBtn = document.getElementById('vaultStorageRetryBtn');

  // --- MULTI-TAB WEB LOCKS API HELPER ---
  async function withVaultWriteLock(callback) {
    if (typeof navigator !== 'undefined' && navigator.locks && typeof navigator.locks.request === 'function') {
      return await navigator.locks.request('secure-vault-write', callback);
    }
    // Graceful fallback if Web Locks is unavailable
    return await callback();
  }

  // --- HTML ESCAPE HELPER ---
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // --- STRICT URL PROTOCOL VALIDATION (http and https only) ---
  function validateHttpUrl(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return { valid: true, cleanUrl: '' };
    const trimmed = urlStr.trim();
    if (!trimmed) return { valid: true, cleanUrl: '' };
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return { valid: true, cleanUrl: parsed.href };
      }
      return { valid: false, cleanUrl: '' };
    } catch (_) {
      return { valid: false, cleanUrl: '' };
    }
  }

  // --- THEME SYSTEM ---
  function initTheme() {
    const savedTheme = localStorage.getItem('secure_vault_theme') || 'dark';
    applyTheme(savedTheme);
  }

  function applyTheme(theme) {
    htmlRoot.setAttribute('data-theme', theme);
    if (theme === 'light') {
      vaultThemeIconDark.classList.add('hidden');
      vaultThemeIconLight.classList.remove('hidden');
    } else {
      vaultThemeIconDark.classList.remove('hidden');
      vaultThemeIconLight.classList.add('hidden');
    }
  }

  if (vaultThemeToggleBtn) {
    vaultThemeToggleBtn.addEventListener('click', () => {
      const currentTheme = htmlRoot.getAttribute('data-theme') || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(newTheme);
      try {
        localStorage.setItem('secure_vault_theme', newTheme);
      } catch (_) {}
    });
  }

  // --- COMPACT TOAST NOTIFICATION SYSTEM (Stage 3) ---
  const TOAST_ICONS = {
    success: '<svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error: '<svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    warning: '<svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
  };

  function inferToastType(message) {
    if (!message || typeof message !== 'string') return 'info';
    const lower = message.toLowerCase();
    if (
      lower.includes('fail') ||
      lower.includes('incorrect') ||
      lower.includes('corrupt') ||
      lower.includes('error') ||
      lower.includes('invalid') ||
      lower.includes('unable') ||
      lower.includes('could not') ||
      lower.includes('cannot') ||
      lower.includes('mismatch') ||
      lower.includes('not match') ||
      lower.includes('required') ||
      lower.includes('refusing') ||
      lower.includes('no verified backup')
    ) {
      return 'error';
    }
    if (
      lower.includes('success') ||
      lower.includes('unlocked') ||
      lower.includes('copied') ||
      lower.includes('saved') ||
      lower.includes('updated') ||
      lower.includes('restored') ||
      lower.includes('downloaded') ||
      lower.includes('verified') ||
      lower.includes('applied') ||
      lower.includes('ready')
    ) {
      return 'success';
    }
    if (
      lower.includes('warning') ||
      lower.includes('locked') ||
      lower.includes('caution') ||
      lower.includes('notice') ||
      lower.includes('reset') ||
      lower.includes('confirm')
    ) {
      return 'warning';
    }
    return 'info';
  }

  function dismissNotification() {
    if (noticeTimeout) {
      clearTimeout(noticeTimeout);
      noticeTimeout = null;
    }
    if (vaultNotification) {
      vaultNotification.classList.add('hidden');
    }
  }

  function showNotification(message, typeOrDuration = 'info', explicitDuration = 3500) {
    if (!vaultNotification || !vaultNotificationText) return;

    let toastType = 'info';
    let duration = 3500;

    if (typeof typeOrDuration === 'number') {
      duration = typeOrDuration;
      toastType = inferToastType(message);
    } else if (typeof typeOrDuration === 'string' && ['success', 'error', 'warning', 'info'].includes(typeOrDuration)) {
      toastType = typeOrDuration;
      duration = typeof explicitDuration === 'number' ? explicitDuration : 3500;
    } else {
      toastType = inferToastType(message);
      duration = typeof explicitDuration === 'number' ? explicitDuration : 3500;
    }

    if (noticeTimeout) {
      clearTimeout(noticeTimeout);
      noticeTimeout = null;
    }

    vaultNotificationText.textContent = message || '';

    const iconTarget = vaultNotificationIcon || document.getElementById('vaultNotificationIcon');
    if (iconTarget) {
      iconTarget.innerHTML = TOAST_ICONS[toastType] || TOAST_ICONS.info;
    }

    vaultNotification.classList.remove('toast-success', 'toast-error', 'toast-warning', 'toast-info', 'hidden');
    vaultNotification.classList.add(`toast-${toastType}`);

    if (toastType === 'error') {
      vaultNotification.setAttribute('role', 'alert');
    } else {
      vaultNotification.setAttribute('role', 'status');
    }

    noticeTimeout = setTimeout(() => {
      dismissNotification();
    }, duration);
  }

  if (vaultNotificationCloseBtn) {
    vaultNotificationCloseBtn.addEventListener('click', () => {
      dismissNotification();
    });
  }

  // --- SHOW / HIDE PASSWORD TOGGLES FOR INPUT FIELDS ---
  document.querySelectorAll('.input-toggle-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
      }
    });
  });

  // --- OVERLAY STATE SWITCHER ---
  function showAuthCard(cardToShow) {
    vaultAuthOverlay.classList.remove('hidden');
    [
      vaultLockedCard,
      vaultSetupCard,
      vaultRecoveryDisplayCard,
      vaultRecoveryInputCard,
      vaultSetNewPassCard,
      vaultCorruptedCard,
      vaultStorageErrorCard
    ].forEach((card) => {
      if (card) card.classList.add('hidden');
    });
    if (cardToShow) cardToShow.classList.remove('hidden');
  }

  function hideAuthOverlay() {
    vaultAuthOverlay.classList.add('hidden');
  }

  // ==================================================
  // 1. VAULT STATUS CHECK (NEVER TREAT MALFORMED AS NO VAULT)
  // ==================================================
  async function checkVaultStatus() {
    try {
      // Check if key exists in storage (regardless of validity)
      const recordExists = await StorageModule.hasVaultRecord();

      if (!recordExists) {
        // CASE A: No storage record exists at all -> First-Time Setup
        showAuthCard(vaultSetupCard);
        return;
      }

      // Record exists: load and validate its encrypted schema
      const record = await StorageModule.loadVaultRecord();
      if (StorageModule.validateVaultRecord(record)) {
        // CASE B: Record exists and is structurally valid -> Locked screen
        showAuthCard(vaultLockedCard);
        if (vaultPageUnlockPassword) vaultPageUnlockPassword.focus();
      } else {
        // CASE C: Record exists but is corrupted / malformed
        // MUST NOT show First-Time Setup! MUST NOT allow vault creation!
        showAuthCard(vaultCorruptedCard);
        showNotification(
          'Your encrypted vault appears to be corrupted or incomplete. Do not reset unless you intend to permanently delete the vault.',
          6000
        );
      }
    } catch (_) {
      // CASE D: Storage read failed
      // MUST NOT show First-Time Setup!
      showAuthCard(vaultStorageErrorCard);
      showNotification('Unable to access your encrypted vault. Please try again.');
    }
  }

  // ==================================================
  // 2. FIRST-TIME VAULT CREATION (REFUSES OVERWRITE IF RECORD EXISTS)
  // ==================================================
  async function createVault() {
    if (isCreatingVault) return;
    const operationGeneration = lockGeneration;

    const pass = vaultPageSetupPassword.value;
    const confirm = vaultPageSetupConfirm.value;

    const passCheck = validateMasterPassword(pass);
    if (!passCheck.valid) {
      showNotification(passCheck.error);
      return;
    }
    if (pass !== confirm) {
      showNotification('Passwords do not match. Please re-enter.');
      return;
    }

    try {
      // Refuse creation whenever ANY existing vault record exists, even if malformed!
      const keyExists = await StorageModule.hasVaultRecord();
      if (!isLockGenerationCurrent(operationGeneration)) return;
      if (keyExists) {
        showNotification('An existing vault record was found. Refusing to overwrite.');
        showAuthCard(vaultLockedCard);
        return;
      }
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Unable to access storage. Please try again.');
      }
      return;
    }

    try {
      isCreatingVault = true;
      vaultPageCreateBtn.disabled = true;
      vaultPageCreateBtn.textContent = 'Creating Vault...';

      // 1. Generate salt and derive Master KEK
      const salt = generateSalt();
      const masterKek = await deriveMasterKey(pass, salt);
      if (!isLockGenerationCurrent(operationGeneration)) return;

      // 2. Generate Recovery Key
      const recoveryKey = generateRecoveryKey();
      const recoveryCryptoKey = await importAesGcmKey(recoveryKey.rawBytes, false);
      if (!isLockGenerationCurrent(operationGeneration)) return;

      // 3. Create VEK and wrap with both keys; VEK returned as non-extractable (extractable = false)
      const { vek, masterWrapped, recoveryWrapped } = await createAndWrapVaultKey(masterKek, recoveryCryptoKey);
      if (!isLockGenerationCurrent(operationGeneration)) return;

      // 4. Initial empty vault payload with schemaVersion 2
      const initialVault = {
        schemaVersion: 2,
        accounts: []
      };

      // 5. Encrypt initial vault payload with VEK
      const encryptedVault = await encryptVault(initialVault, vek);
      if (!isLockGenerationCurrent(operationGeneration)) return;

      // 6. Construct persistent record with non-secret revision metadata
      const record = {
        schemaVersion: 2,
        vaultRevision: 1,
        vault: encryptedVault,
        masterProtection: {
          kdf: 'PBKDF2',
          hash: 'SHA-256',
          iterations: 600000,
          salt: bytesToBase64(salt),
          algorithm: 'AES-256-GCM',
          iv: masterWrapped.iv,
          aad: AAD_MASTER_KEY,
          wrappedVaultKey: masterWrapped.wrappedVaultKey
        },
        recoveryProtection: {
          algorithm: 'AES-256-GCM',
          iv: recoveryWrapped.iv,
          aad: AAD_RECOVERY_KEY,
          wrappedVaultKey: recoveryWrapped.wrappedVaultKey
        }
      };

      if (!isLockGenerationCurrent(operationGeneration)) return;
      await StorageModule.saveVaultRecord(record);
      if (!isLockGenerationCurrent(operationGeneration)) return;

      // In-memory non-extractable VEK & decrypted payload
      activeVek = vek;
      decryptedVault = initialVault;
      currentVaultRevision = 1;
      generatedRecoveryKeyFormatted = recoveryKey.formatted;

      // Clear password inputs
      vaultPageSetupPassword.value = '';
      vaultPageSetupConfirm.value = '';

      // Format recovery key in 4 lines
      const groups = recoveryKey.formatted.split('-');
      const line1 = groups.slice(0, 4).join('-');
      const line2 = groups.slice(4, 8).join('-');
      const line3 = groups.slice(8, 12).join('-');
      const line4 = groups.slice(12, 16).join('-');
      vaultPageRecoveryKeyText.textContent = `${line1}\n${line2}\n${line3}\n${line4}`;

      showAuthCard(vaultRecoveryDisplayCard);
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Vault creation failed. Please try again.');
      }
    } finally {
      isCreatingVault = false;
      vaultPageCreateBtn.disabled = false;
      vaultPageCreateBtn.textContent = 'Create Secure Vault';
    }
  }

  // Form submit listener for vaultPageSetupForm (SINGLE source of truth; no duplicate click handler)
  if (vaultPageSetupForm) {
    vaultPageSetupForm.addEventListener('submit', (e) => {
      e.preventDefault();
      createVault();
    });
  }

  // --- RECOVERY KEY ACTIONS ---
  vaultPageCopyRecoveryBtn.addEventListener('click', async () => {
    if (generatedRecoveryKeyFormatted) {
      const operationGeneration = lockGeneration;
      const recoveryKeyToCopy = generatedRecoveryKeyFormatted;
      try {
        await navigator.clipboard.writeText(recoveryKeyToCopy);
        if (!isLockGenerationCurrent(operationGeneration)) {
          try { await navigator.clipboard.writeText(''); } catch (_) {}
          return;
        }
        showNotification('Recovery Key copied to clipboard.');
      } catch (_) {
        if (isLockGenerationCurrent(operationGeneration)) {
          showNotification('Copy failed. Please manually select and copy.');
        }
      }
    }
  });

  vaultPageDownloadRecoveryBtn.addEventListener('click', () => {
    if (generatedRecoveryKeyFormatted) {
      const text = `SECURE VAULT - RECOVERY KEY\n\n` +
        `Recovery Key:\n${generatedRecoveryKeyFormatted}\n\n` +
        `IMPORTANT:\n` +
        `- Keep this key safe and offline.\n` +
        `- It can unlock your vault if you forget your Master Password.\n` +
        `- Secure Vault does NOT store this key anywhere.\n`;
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'secure-vault-recovery-key.txt';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showNotification('Recovery key file downloaded.');
    }
  });

  vaultPageConfirmSavedRecoveryBtn.addEventListener('click', () => {
    vaultPageRecoveryKeyText.textContent = '';
    generatedRecoveryKeyFormatted = '';

    currentSearchQuery = '';
    if (vaultSearchInput) vaultSearchInput.value = '';
    currentCategoryFilter = 'All';
    if (categoryChipsGroup) {
      categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
        const isAll = c.getAttribute('data-category') === 'All';
        c.classList.toggle('active', isAll);
        c.setAttribute('aria-selected', isAll ? 'true' : 'false');
      });
    }
    currentSortOption = 'recently-updated';
    if (vaultSortSelect) vaultSortSelect.value = 'recently-updated';
    clearAllRevealedPasswords();

    hideAuthOverlay();
    renderAccounts();
    resetActivity();
    showNotification('Vault ready & unlocked.');
  });

  // ==================================================
  // 3. UNLOCK VAULT (HARDENED 6-STAGE UNLOCK PIPELINE)
  // ==================================================
  async function performUnlock() {
    if (isUnlocking) return;
    const operationGeneration = lockGeneration;

    // Byte-for-byte Master Password: never trimmed, normalized, or transformed
    const password = vaultPageUnlockPassword.value;
    if (!password) {
      showNotification('Please enter your Master Password.');
      return;
    }

    let failureStage = null; // Internal classification: STORAGE_LOAD_FAILED, INVALID_VAULT_RECORD, etc.

    try {
      isUnlocking = true;
      vaultPageUnlockBtn.disabled = true;
      vaultPageUnlockBtn.textContent = 'Verifying...';

      // Progressive delay for repeated failed Master Password attempts
      const delayMs = getUnlockDelay(failedUnlockAttempts);
      if (delayMs > 0) {
        await sleep(delayMs);
        if (!isLockGenerationCurrent(operationGeneration)) return;
      }

      // STAGE 1: Storage load
      let record;
      try {
        record = await StorageModule.loadVaultRecord();
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'STORAGE_LOAD_FAILED';
        showNotification('Unable to access your vault storage. Please try again.');
        return;
      }

      // STAGE 2: Vault record validation
      if (!record || !StorageModule.validateVaultRecord(record)) {
        failureStage = 'INVALID_VAULT_RECORD';
        showNotification('Your vault data appears corrupted or incomplete.');
        return;
      }

      // STAGE 3: Master key derivation
      let masterKek;
      try {
        const salt = base64ToBytes(record.masterProtection.salt);
        masterKek = await deriveMasterKey(password, salt);
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'MASTER_KEY_DERIVATION_FAILED';
        showNotification('Unable to access your vault storage. Please try again.');
        return;
      }

      // STAGE 4: VEK unwrap (Cryptographic authentication of Master Password)
      let vek;
      try {
        vek = await unwrapVaultKey(
          record.masterProtection.wrappedVaultKey,
          record.masterProtection.iv,
          masterKek,
          record.masterProtection.aad || AAD_MASTER_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        // Authenticated unwrap failed -> incorrect Master Password
        failureStage = 'VEK_UNWRAP_FAILED';
        failedUnlockAttempts++;
        if (vaultPageUnlockPassword) vaultPageUnlockPassword.value = '';
        showNotification('Incorrect Master Password.');
        return;
      }

      // STAGE 5: Vault decryption
      let vaultData;
      try {
        vaultData = await decryptVault(record.vault, vek);
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'VAULT_DECRYPT_FAILED';
        showNotification('Your vault data appears corrupted or incomplete.');
        return;
      }

      // STAGE 6: Vault payload validation
      if (!vaultData || typeof vaultData !== 'object' || !Array.isArray(vaultData.accounts)) {
        failureStage = 'VAULT_PAYLOAD_INVALID';
        showNotification('Your vault data appears corrupted or incomplete.');
        return;
      }

      // Commit to volatile memory only if no lock arrived during authentication.
      if (!isLockGenerationCurrent(operationGeneration)) return;
      activeVek = vek;
      decryptedVault = vaultData;
      currentVaultRevision = record.vaultRevision || 1;
      vaultPageUnlockPassword.value = '';
      failedUnlockAttempts = 0; // Reset counter on success

      // Stage 4: Reset UI state on unlock
      currentSearchQuery = '';
      if (vaultSearchInput) vaultSearchInput.value = '';
      currentCategoryFilter = 'All';
      if (categoryChipsGroup) {
        categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
          const isAll = c.getAttribute('data-category') === 'All';
          c.classList.toggle('active', isAll);
          c.setAttribute('aria-selected', isAll ? 'true' : 'false');
        });
      }
      currentSortOption = 'recently-updated';
      if (vaultSortSelect) vaultSortSelect.value = 'recently-updated';

      // Clear any stale revealed password tracking
      clearAllRevealedPasswords();

      hideAuthOverlay();
      renderAccounts();
      showNotification('Vault unlocked successfully.');

      // Check if opened with addSite / website query param
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const autoSite = (urlParams.get('addSite') || urlParams.get('website') || '').trim();
        if (autoSite) {
          openAddAccountModal(autoSite);
        }
      } catch (_) {}
    } catch (_) {
      if (vaultPageUnlockPassword) vaultPageUnlockPassword.value = '';
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Incorrect Master Password.');
      }
    } finally {
      isUnlocking = false;
      vaultPageUnlockBtn.disabled = false;
      vaultPageUnlockBtn.textContent = 'Unlock';
    }
  }

  // Form submit listener for vaultPageUnlockForm (SINGLE source of truth; no duplicate click handler)
  if (vaultPageUnlockForm) {
    vaultPageUnlockForm.addEventListener('submit', (e) => {
      e.preventDefault();
      performUnlock();
    });
  }

  // --- GLOBAL MANUAL LOCK ---
  function lockVault(options = {}) {
    const { broadcast = true, notify = true, reason = 'manual' } = options;
    const hadSensitiveSession = Boolean(
      activeVek || decryptedVault || tempRecoveryCryptoKey || generatedRecoveryKeyFormatted
    );

    // Invalidate all in-flight async operations before clearing any state.
    lockGeneration += 1;
    activeVek = null;
    decryptedVault = null;
    tempRecoveryCryptoKey = null;
    generatedRecoveryKeyFormatted = '';
    pendingRestoreRecord = null;
    pendingRestoreDecrypted = null;
    failedUnlockAttempts = 0;
    currentEditAccountId = null;
    currentDeleteAccountId = null;
    generatorTargetInputField = null;

    // Cancel auto-lock scheduling in this view and the background worker.
    if (autoLockTimer) {
      clearTimeout(autoLockTimer);
      autoLockTimer = null;
    }
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'CLEAR_AUTO_LOCK' }).catch(() => {});
    }

    // Do not cancel the pending password clipboard expiry timer here. It must still
    // clear a copied password at its original deadline even if the vault is locked.
    // The timer is invalidated only when the user explicitly copies different content.

    currentSearchQuery = '';
    if (vaultSearchInput) vaultSearchInput.value = '';
    currentCategoryFilter = 'All';
    if (categoryChipsGroup) {
      categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
        const isAll = c.getAttribute('data-category') === 'All';
        c.classList.toggle('active', isAll);
        c.setAttribute('aria-selected', isAll ? 'true' : 'false');
      });
    }
    currentSortOption = 'recently-updated';
    if (vaultSortSelect) vaultSortSelect.value = 'recently-updated';

    clearAllRevealedPasswords();
    clearSensitiveFormInputs();

    if (vaultFilterSortToolbar) vaultFilterSortToolbar.classList.add('hidden');
    if (vaultSearchEmptyState) vaultSearchEmptyState.classList.add('hidden');
    if (vaultAccountsSection) vaultAccountsSection.classList.add('hidden');
    if (vaultEmptyState) vaultEmptyState.classList.remove('hidden');

    closeAccountModal();
    closeDeleteModal();
    closeGeneratorModal();
    closeSettingsModal();
    closeRestoreModal();
    if (vaultChangePassModal && !vaultChangePassModal.classList.contains('hidden')) closeChangePassModal();
    if (vaultResetModal && !vaultResetModal.classList.contains('hidden')) closeResetModal();

    if (accountsListContainer) accountsListContainer.innerHTML = '';
    updateItemCount(0);

    if (hadSensitiveSession) {
      showAuthCard(vaultLockedCard);
    }

    if (broadcast) broadcastGlobalLock(reason);
    if (notify && hadSensitiveSession) showNotification('Vault locked.');
  }

  if (lockVaultBtn) lockVaultBtn.addEventListener('click', lockVault);

  // --- RECOVERY FLOW ---
  vaultPageGotoRecoverBtn.addEventListener('click', () => {
    vaultPageRecoveryKeyInput.value = '';
    showAuthCard(vaultRecoveryInputCard);
    vaultPageRecoveryKeyInput.focus();
  });

  vaultPageCancelRecoveryBtn.addEventListener('click', () => {
    vaultPageRecoveryKeyInput.value = '';
    showAuthCard(vaultLockedCard);
  });

  vaultPageSubmitRecoveryBtn.addEventListener('click', async () => {
    if (isRecovering) return;
    const operationGeneration = lockGeneration;

    const rawInput = vaultPageRecoveryKeyInput.value.trim();
    if (!rawInput) {
      showNotification('Please enter your Recovery Key.');
      return;
    }

    try {
      isRecovering = true;
      vaultPageSubmitRecoveryBtn.disabled = true;
      vaultPageSubmitRecoveryBtn.textContent = 'Verifying...';

      const keyBytes = parseRecoveryKey(rawInput);
      const recoveryCryptoKey = await importAesGcmKey(keyBytes, false);
      if (!isLockGenerationCurrent(operationGeneration)) return;

      const record = await StorageModule.loadVaultRecord();
      if (!isLockGenerationCurrent(operationGeneration)) return;
      if (!StorageModule.validateVaultRecord(record)) {
        throw new Error('No valid recovery protection found.');
      }

      // Verify that recovery key decrypts VEK and vault
      const vek = await unwrapVaultKey(
        record.recoveryProtection.wrappedVaultKey,
        record.recoveryProtection.iv,
        recoveryCryptoKey,
        record.recoveryProtection.aad || AAD_RECOVERY_KEY
      );
      if (!isLockGenerationCurrent(operationGeneration)) return;

      const vaultData = await decryptVault(record.vault, vek);
      if (!isLockGenerationCurrent(operationGeneration)) return;
      if (!vaultData.accounts || !Array.isArray(vaultData.accounts)) {
        vaultData.accounts = [];
      }

      tempRecoveryCryptoKey = recoveryCryptoKey;
      decryptedVault = vaultData;
      currentVaultRevision = record.vaultRevision || 1;
      vaultPageRecoveryKeyInput.value = '';

      showAuthCard(vaultSetNewPassCard);
      showNotification('Recovery Key verified! Set a new Master Password.');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Invalid Recovery Key. Please check the key and try again.');
      }
    } finally {
      isRecovering = false;
      vaultPageSubmitRecoveryBtn.disabled = false;
      vaultPageSubmitRecoveryBtn.textContent = 'Recover Vault';
    }
  });

  // --- SET NEW MASTER PASSWORD (POST-RECOVERY) ---
  async function saveNewPassAfterRecovery() {
    if (isSavingNewPass) return;
    const operationGeneration = lockGeneration;
    const recoveryKeyForOperation = tempRecoveryCryptoKey;

    const pass = vaultPageNewPass.value;
    const confirm = vaultPageNewPassConfirm.value;

    const passCheck = validateMasterPassword(pass);
    if (!passCheck.valid) {
      showNotification(`New ${passCheck.error.charAt(0).toLowerCase() + passCheck.error.slice(1)}`);
      return;
    }
    if (pass !== confirm) {
      showNotification('Passwords do not match.');
      return;
    }
    if (!recoveryKeyForOperation) {
      showNotification('Recovery session expired. Please start over.');
      showAuthCard(vaultLockedCard);
      return;
    }

    try {
      isSavingNewPass = true;
      vaultPageSaveNewPassBtn.disabled = true;
      vaultPageSaveNewPassBtn.textContent = 'Saving...';

      await withVaultWriteLock(async () => {
        const record = await StorageModule.loadVaultRecord();
        if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== recoveryKeyForOperation) return;
        if (!StorageModule.validateVaultRecord(record)) {
          throw new Error('Corrupted record during password update.');
        }

        const newSalt = generateSalt();
        const newMasterKek = await deriveMasterKey(pass, newSalt);
        if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== recoveryKeyForOperation) return;

        // Re-wrap VEK from Recovery Key to new Master KEK without extractable keys
        const newMasterWrapped = await rewrapVaultKey(
          record.recoveryProtection.wrappedVaultKey,
          record.recoveryProtection.iv,
          recoveryKeyForOperation,
          record.recoveryProtection.aad || AAD_RECOVERY_KEY,
          newMasterKek,
          AAD_MASTER_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== recoveryKeyForOperation) return;

        const nextRevision = (record.vaultRevision || currentVaultRevision || 1) + 1;
        record.vaultRevision = nextRevision;
        record.masterProtection = {
          kdf: 'PBKDF2',
          hash: 'SHA-256',
          iterations: 600000,
          salt: bytesToBase64(newSalt),
          algorithm: 'AES-256-GCM',
          iv: newMasterWrapped.iv,
          aad: AAD_MASTER_KEY,
          wrappedVaultKey: newMasterWrapped.wrappedVaultKey
        };

        if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== recoveryKeyForOperation) return;
        await StorageModule.saveVaultRecord(record);
        if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== recoveryKeyForOperation) return;

        // Activate vault with non-extractable VEK
        const recoveredVek = await unwrapVaultKey(
          newMasterWrapped.wrappedVaultKey,
          newMasterWrapped.iv,
          newMasterKek,
          AAD_MASTER_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== recoveryKeyForOperation) return;
        activeVek = recoveredVek;
        currentVaultRevision = nextRevision;
        tempRecoveryCryptoKey = null;
      });
      if (!isLockGenerationCurrent(operationGeneration) || tempRecoveryCryptoKey !== null) return;

      vaultPageNewPass.value = '';
      vaultPageNewPassConfirm.value = '';

      currentSearchQuery = '';
      if (vaultSearchInput) vaultSearchInput.value = '';
      currentCategoryFilter = 'All';
      if (categoryChipsGroup) {
        categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
          const isAll = c.getAttribute('data-category') === 'All';
          c.classList.toggle('active', isAll);
          c.setAttribute('aria-selected', isAll ? 'true' : 'false');
        });
      }
      currentSortOption = 'recently-updated';
      if (vaultSortSelect) vaultSortSelect.value = 'recently-updated';
      clearAllRevealedPasswords();

      hideAuthOverlay();
      renderAccounts();
      resetActivity();
      showNotification('New Master Password set! Vault unlocked.');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Failed to update Master Password.');
      }
    } finally {
      isSavingNewPass = false;
      vaultPageSaveNewPassBtn.disabled = false;
      vaultPageSaveNewPassBtn.textContent = 'Save & Unlock Vault';
    }
  }

  // Form submit listener for vaultPageSetNewPassForm (SINGLE source of truth; no duplicate click handler)
  if (vaultPageSetNewPassForm) {
    vaultPageSetNewPassForm.addEventListener('submit', (e) => {
      e.preventDefault();
      saveNewPassAfterRecovery();
    });
  }

  // --- CHANGE MASTER PASSWORD MODAL (HARDENED RE-WRAP) ---
  function openChangePassModal() {
    modalCurPass.value = '';
    modalNewPass.value = '';
    modalConfirmPass.value = '';
    vaultChangePassModal.classList.remove('hidden');
    modalCurPass.focus();
  }

  function closeChangePassModal() {
    vaultChangePassModal.classList.add('hidden');
    modalCurPass.value = '';
    modalNewPass.value = '';
    modalConfirmPass.value = '';
  }

  if (vaultOpenChangePassBtn) vaultOpenChangePassBtn.addEventListener('click', openChangePassModal);
  if (vaultCloseChangePassBtn) vaultCloseChangePassBtn.addEventListener('click', closeChangePassModal);
  if (modalCancelChangePassBtn) modalCancelChangePassBtn.addEventListener('click', closeChangePassModal);

  async function handleChangePassword() {
    if (isChangingPassword) return;
    const operationGeneration = lockGeneration;
    const operationVek = activeVek;

    const curPass = modalCurPass.value;
    const newPass = modalNewPass.value;
    const confirm = modalConfirmPass.value;

    if (!curPass) {
      showNotification('Enter your current Master Password.');
      return;
    }
    const newPassCheck = validateMasterPassword(newPass);
    if (!newPassCheck.valid) {
      showNotification(`New ${newPassCheck.error.charAt(0).toLowerCase() + newPassCheck.error.slice(1)}`);
      return;
    }
    if (newPass !== confirm) {
      showNotification('New passwords do not match.');
      return;
    }
    if (!activeVek) {
      showNotification('Vault is locked.');
      closeChangePassModal();
      return;
    }

    try {
      isChangingPassword = true;
      modalSubmitChangePassBtn.disabled = true;
      modalSubmitChangePassBtn.textContent = 'Verifying...';

      await withVaultWriteLock(async () => {
        const record = await StorageModule.loadVaultRecord();
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
        if (!StorageModule.validateVaultRecord(record)) {
          throw new Error('Corrupted record during password change.');
        }

        const currentSalt = base64ToBytes(record.masterProtection.salt);
        const currentKek = await deriveMasterKey(curPass, currentSalt);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;

        // Verify current password by unwrapping VEK
        await unwrapVaultKey(
          record.masterProtection.wrappedVaultKey,
          record.masterProtection.iv,
          currentKek,
          record.masterProtection.aad || AAD_MASTER_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;

        // Current password verified: generate new salt and new KEK
        modalSubmitChangePassBtn.textContent = 'Re-wrapping Key...';
        const newSalt = generateSalt();
        const newKek = await deriveMasterKey(newPass, newSalt);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;

        // Re-wrap VEK directly without requiring an extractable key
        const newMasterWrapped = await rewrapVaultKey(
          record.masterProtection.wrappedVaultKey,
          record.masterProtection.iv,
          currentKek,
          record.masterProtection.aad || AAD_MASTER_KEY,
          newKek,
          AAD_MASTER_KEY
        );

        const nextRevision = (record.vaultRevision || currentVaultRevision || 1) + 1;
        record.vaultRevision = nextRevision;
        record.masterProtection = {
          kdf: 'PBKDF2',
          hash: 'SHA-256',
          iterations: 600000,
          salt: bytesToBase64(newSalt),
          algorithm: 'AES-256-GCM',
          iv: newMasterWrapped.iv,
          aad: AAD_MASTER_KEY,
          wrappedVaultKey: newMasterWrapped.wrappedVaultKey
        };

        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
        await StorageModule.saveVaultRecord(record);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
        currentVaultRevision = nextRevision;
      });

      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      closeChangePassModal();
      showNotification('Master Password changed successfully.');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration, operationVek)) {
        showNotification('Current Master Password incorrect.');
      }
    } finally {
      isChangingPassword = false;
      modalSubmitChangePassBtn.disabled = false;
      modalSubmitChangePassBtn.textContent = 'Update Password';
    }
  }

  // Form submit listener for vaultChangePassForm (SINGLE source of truth; no duplicate click handler)
  if (vaultChangePassForm) {
    vaultChangePassForm.addEventListener('submit', (e) => {
      e.preventDefault();
      handleChangePassword();
    });
  }

  // --- DESTRUCTIVE RESET VAULT ---
  function openResetModal() {
    vaultPageResetInput.value = '';
    vaultResetModal.classList.remove('hidden');
    vaultPageResetInput.focus();
  }

  function closeResetModal() {
    vaultResetModal.classList.add('hidden');
    vaultPageResetInput.value = '';
  }

  if (vaultPageGotoResetBtn) vaultPageGotoResetBtn.addEventListener('click', openResetModal);
  if (vaultOpenResetBtn) vaultOpenResetBtn.addEventListener('click', openResetModal);
  if (vaultCloseResetBtn) vaultCloseResetBtn.addEventListener('click', closeResetModal);
  if (vaultCancelResetBtn) vaultCancelResetBtn.addEventListener('click', closeResetModal);

  vaultConfirmResetBtn.addEventListener('click', async () => {
    if (isResettingVault) return;

    if (vaultPageResetInput.value.trim() !== 'RESET') {
      showNotification('Type RESET exactly to confirm vault deletion.');
      return;
    }

    try {
      isResettingVault = true;
      vaultConfirmResetBtn.disabled = true;
      vaultConfirmResetBtn.textContent = 'Deleting...';

      await StorageModule.deleteVault();

      lockGeneration += 1;
      activeVek = null;
      decryptedVault = null;
      tempRecoveryCryptoKey = null;
      currentEditAccountId = null;
      currentDeleteAccountId = null;
      currentVaultRevision = 1;
      broadcastGlobalLock('reset');

      // Stage 4 UI resets on delete
      currentSearchQuery = '';
      if (vaultSearchInput) vaultSearchInput.value = '';
      currentCategoryFilter = 'All';
      if (categoryChipsGroup) {
        categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
          const isAll = c.getAttribute('data-category') === 'All';
          c.classList.toggle('active', isAll);
          c.setAttribute('aria-selected', isAll ? 'true' : 'false');
        });
      }
      currentSortOption = 'recently-updated';
      if (vaultSortSelect) vaultSortSelect.value = 'recently-updated';

      clearAllRevealedPasswords();
      // Keep an already scheduled clipboard expiry alive across destructive reset.

      if (vaultFilterSortToolbar) vaultFilterSortToolbar.classList.add('hidden');
      if (vaultSearchEmptyState) vaultSearchEmptyState.classList.add('hidden');
      if (vaultAccountsSection) vaultAccountsSection.classList.add('hidden');
      if (vaultEmptyState) vaultEmptyState.classList.remove('hidden');

      closeAccountModal();
      closeDeleteModal();
      closeGeneratorModal();
      if (accountsListContainer) accountsListContainer.innerHTML = '';
      updateItemCount(0);

      closeResetModal();
      showAuthCard(vaultSetupCard);
      showNotification('Vault permanently deleted.');
    } catch (_) {
      showNotification('Failed to delete vault.');
    } finally {
      isResettingVault = false;
      vaultConfirmResetBtn.disabled = false;
      vaultConfirmResetBtn.textContent = 'Permanently Delete Vault';
    }
  });

  // ==================================================
  // 4. STAGE 4 ACCOUNT MANAGEMENT, SEARCH, FILTER, SORT & CLIPBOARD
  // ==================================================

  function updateItemCount(count) {
    if (accountCountLabel) {
      accountCountLabel.textContent = `${count} ${count === 1 ? 'account' : 'accounts'}`;
    }
  }

  // --- STAGE 4 CLIPBOARD AUTO-CLEAR & COPY HELPERS ---

  /**
   * Schedule 30-second clipboard clearing for passwords (best effort).
   * Monotonically incremented token prevents race conditions between consecutive copies.
   */
  function schedulePasswordClipboardClear() {
    clipboardCopyVersion++;
    const currentVersion = clipboardCopyVersion;

    if (clipboardClearTimer) {
      clearTimeout(clipboardClearTimer);
      clipboardClearTimer = null;
    }

    clipboardClearTimer = setTimeout(async () => {
      clipboardClearTimer = null;
      if (currentVersion === clipboardCopyVersion) {
        try {
          if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText('');
          }
        } catch (_) {
          // Best effort; no technical error leaked
        }
      }
    }, 30000);
  }

  /**
   * Cancel any pending password clipboard clearing timer.
   */
  function cancelPasswordClipboardClear() {
    clipboardCopyVersion++;
    if (clipboardClearTimer) {
      clearTimeout(clipboardClearTimer);
      clipboardClearTimer = null;
    }
  }

  /**
   * Copy username from decrypted in-memory account only.
   * Cancels any pending password clipboard auto-clear timer so it cannot erase the copied username.
   */
  async function copyUsername(accountId) {
    if (!activeVek || !decryptedVault) {
      showNotification('Vault is locked.');
      return;
    }
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) return;

    const operationGeneration = lockGeneration;

    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
        throw new Error('Clipboard API unavailable');
      }
      await navigator.clipboard.writeText(account.username || '');
      if (!isLockGenerationCurrent(operationGeneration)) {
        try { await navigator.clipboard.writeText(''); } catch (_) {}
        return;
      }
      // The clipboard now contains the username, so the previous password timer
      // must not erase this newer user-requested content.
      cancelPasswordClipboardClear();
      showNotification('Username copied');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) showNotification('Could not copy username.');
    }
  }

  /**
   * Copy password from decrypted in-memory account only and schedule auto-clear.
   */
  async function copyPassword(accountId) {
    if (!activeVek || !decryptedVault) {
      showNotification('Vault is locked.');
      return;
    }
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) return;

    const operationGeneration = lockGeneration;
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
        throw new Error('Clipboard API unavailable');
      }
      await navigator.clipboard.writeText(account.password || '');
      if (!isLockGenerationCurrent(operationGeneration)) {
        try { await navigator.clipboard.writeText(''); } catch (_) {}
        return;
      }
      schedulePasswordClipboardClear();
      showNotification('Password copied. Clipboard will be cleared in about 30 seconds.');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) showNotification('Could not copy password.');
    }
  }

  // --- STAGE 4 PASSWORD SHOW / HIDE & 30-SECOND AUTO-HIDING ---

  /**
   * Toggle temporary in-memory password visibility for a single account.
   * Never persisted; auto-hides after 30 seconds.
   */
  function togglePasswordVisibility(accountId) {
    if (!activeVek || !decryptedVault) {
      showNotification('Vault is locked.');
      return;
    }
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) return;

    if (revealedPasswordAccountIds.has(accountId)) {
      // User requested Hide
      revealedPasswordAccountIds.delete(accountId);
      if (passwordRevealTimers.has(accountId)) {
        clearTimeout(passwordRevealTimers.get(accountId));
        passwordRevealTimers.delete(accountId);
      }
      const passEl = document.getElementById(`pass-val-${accountId}`);
      const btn = document.getElementById(`btn-toggle-pass-${accountId}`);
      if (passEl) {
        passEl.className = 'account-masked-pass';
        passEl.textContent = '••••••••••••••';
      }
      if (btn) {
        btn.setAttribute('aria-label', 'Show password');
        btn.classList.remove('active-show');
        btn.innerHTML = `
          <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
          <span>Show</span>
        `;
      }
    } else {
      // User requested Show
      revealedPasswordAccountIds.add(accountId);
      if (passwordRevealTimers.has(accountId)) {
        clearTimeout(passwordRevealTimers.get(accountId));
      }

      // Schedule 30-second automatic password hiding
      const timerId = setTimeout(() => {
        revealedPasswordAccountIds.delete(accountId);
        passwordRevealTimers.delete(accountId);
        const passEl = document.getElementById(`pass-val-${accountId}`);
        const btn = document.getElementById(`btn-toggle-pass-${accountId}`);
        if (passEl) {
          passEl.className = 'account-masked-pass';
          passEl.textContent = '••••••••••••••';
        }
        if (btn) {
          btn.setAttribute('aria-label', 'Show password');
          btn.classList.remove('active-show');
          btn.innerHTML = `
            <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
            <span>Show</span>
          `;
        }
      }, 30000);
      passwordRevealTimers.set(accountId, timerId);

      const passEl = document.getElementById(`pass-val-${accountId}`);
      const btn = document.getElementById(`btn-toggle-pass-${accountId}`);
      if (passEl) {
        passEl.className = 'account-revealed-pass';
        passEl.textContent = account.password || ''; // Safe textContent; never innerHTML
      }
      if (btn) {
        btn.setAttribute('aria-label', 'Hide password');
        btn.classList.add('active-show');
        btn.innerHTML = `
          <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
            <line x1="1" y1="1" x2="23" y2="23"></line>
          </svg>
          <span>Hide</span>
        `;
      }
    }
  }

  /**
   * Cancel all password reveal timers and reset revealed tracking.
   */
  function clearAllRevealedPasswords() {
    for (const timer of passwordRevealTimers.values()) {
      clearTimeout(timer);
    }
    passwordRevealTimers.clear();
    revealedPasswordAccountIds.clear();
  }

  // --- STAGE 4 SEARCH, FILTER & STABLE SORT PIPELINE ---

  /**
   * Combined in-memory pipeline: accounts -> category filter -> text search -> stable sort.
   * Never mutates underlying decryptedVault.accounts array.
   */
  function getFilteredAndSortedAccounts() {
    if (!decryptedVault || !Array.isArray(decryptedVault.accounts)) return [];

    let result = [...decryptedVault.accounts];

    // 1. Category Filter
    if (currentCategoryFilter && currentCategoryFilter !== 'All') {
      result = result.filter(
        (a) => (a.category || 'Other').toLowerCase() === currentCategoryFilter.toLowerCase()
      );
    }

    // 2. Case-insensitive Text Search (name, username, category, website, notes - NEVER PASSWORD!)
    const query = (currentSearchQuery || '').trim().toLowerCase();
    if (query) {
      result = result.filter((a) => {
        const name = (a.name || '').toLowerCase();
        const username = (a.username || '').toLowerCase();
        const category = (a.category || '').toLowerCase();
        const website = (a.website || '').toLowerCase();
        const notes = (a.notes || '').toLowerCase();
        return (
          name.includes(query) ||
          username.includes(query) ||
          category.includes(query) ||
          website.includes(query) ||
          notes.includes(query)
        );
      });
    }

    // 3. Stable Sorting
    result.sort((a, b) => {
      let cmp = 0;
      if (currentSortOption === 'recently-updated') {
        const timeA = new Date(a.updatedAt || a.createdAt || 0).getTime();
        const timeB = new Date(b.updatedAt || b.createdAt || 0).getTime();
        cmp = timeB - timeA;
      } else if (currentSortOption === 'recently-added') {
        const timeA = new Date(a.createdAt || 0).getTime();
        const timeB = new Date(b.createdAt || 0).getTime();
        cmp = timeB - timeA;
      } else if (currentSortOption === 'name-asc') {
        cmp = (a.name || '').localeCompare(b.name || '');
      } else if (currentSortOption === 'name-desc') {
        cmp = (b.name || '').localeCompare(a.name || '');
      } else if (currentSortOption === 'category-asc') {
        cmp = (a.category || '').localeCompare(b.category || '');
      }

      // Stable secondary tie-breakers: name, then id
      if (cmp === 0) {
        cmp = (a.name || '').localeCompare(b.name || '');
      }
      if (cmp === 0) {
        cmp = (a.id || '').localeCompare(b.id || '');
      }
      return cmp;
    });

    return result;
  }

  /**
   * Render real decrypted accounts to DOM.
   * Cleared whenever vault is locked or reset.
   * Renders masked password (••••••••••••••) by default unless explicitly revealed.
   * Website links rendered via DOM APIs with strict http/https validation.
   */
  function renderAccounts() {
    if (!decryptedVault || !Array.isArray(decryptedVault.accounts) || decryptedVault.accounts.length === 0) {
      if (vaultEmptyState) vaultEmptyState.classList.remove('hidden');
      if (vaultFilterSortToolbar) vaultFilterSortToolbar.classList.add('hidden');
      if (vaultSearchEmptyState) vaultSearchEmptyState.classList.add('hidden');
      if (vaultAccountsSection) vaultAccountsSection.classList.add('hidden');
      if (accountsListContainer) accountsListContainer.innerHTML = '';
      updateItemCount(0);
      return;
    }

    // Vault has accounts
    if (vaultEmptyState) vaultEmptyState.classList.add('hidden');
    if (vaultFilterSortToolbar) vaultFilterSortToolbar.classList.remove('hidden');
    updateItemCount(decryptedVault.accounts.length);

    const visibleAccounts = getFilteredAndSortedAccounts();

    if (visibleAccounts.length === 0) {
      // 0 accounts match current search/filter combination
      if (vaultSearchEmptyState) vaultSearchEmptyState.classList.remove('hidden');
      if (vaultAccountsSection) vaultAccountsSection.classList.add('hidden');
      if (accountsListContainer) accountsListContainer.innerHTML = '';
      return;
    }

    if (vaultSearchEmptyState) vaultSearchEmptyState.classList.add('hidden');
    if (vaultAccountsSection) vaultAccountsSection.classList.remove('hidden');

    if (!accountsListContainer) return;
    accountsListContainer.innerHTML = '';

    visibleAccounts.forEach((account) => {
      const isRevealed = revealedPasswordAccountIds.has(account.id);
      const initial = (account.name || 'A').trim().charAt(0).toUpperCase() || 'A';
      const card = document.createElement('div');
      card.className = 'account-card-real';
      card.setAttribute('data-id', account.id);

      // Top Header Row
      const topRow = document.createElement('div');
      topRow.className = 'account-card-top';

      const brandDiv = document.createElement('div');
      brandDiv.className = 'account-card-brand';

      const avatar = document.createElement('div');
      avatar.className = 'account-avatar-badge';
      avatar.textContent = initial;

      const titleGroup = document.createElement('div');
      titleGroup.className = 'account-card-title-group';

      const nameEl = document.createElement('h4');
      nameEl.className = 'account-card-name';
      nameEl.textContent = account.name || 'Untitled Account';

      const catBadge = document.createElement('span');
      catBadge.className = 'account-category-chip';
      catBadge.textContent = account.category || 'Other';

      titleGroup.appendChild(nameEl);
      titleGroup.appendChild(catBadge);
      brandDiv.appendChild(avatar);
      brandDiv.appendChild(titleGroup);

      topRow.appendChild(brandDiv);

      // Body Section (Username & Password)
      const bodyDiv = document.createElement('div');
      bodyDiv.className = 'account-card-body';

      const userItem = document.createElement('div');
      userItem.className = 'account-field-item';
      const userLabel = document.createElement('span');
      userLabel.className = 'account-field-label';
      userLabel.textContent = 'Username / Email';
      const userVal = document.createElement('span');
      userVal.className = 'account-field-value';
      userVal.textContent = account.username || '';
      userItem.appendChild(userLabel);
      userItem.appendChild(userVal);

      const passItem = document.createElement('div');
      passItem.className = 'account-field-item';
      const passLabel = document.createElement('span');
      passLabel.className = 'account-field-label';
      passLabel.textContent = 'Password';

      const passVal = document.createElement('span');
      passVal.id = `pass-val-${account.id}`;
      if (isRevealed) {
        passVal.className = 'account-revealed-pass';
        passVal.textContent = account.password || ''; // Safe textContent
      } else {
        passVal.className = 'account-masked-pass';
        passVal.textContent = '••••••••••••••';
      }

      passItem.appendChild(passLabel);
      passItem.appendChild(passVal);

      bodyDiv.appendChild(userItem);
      bodyDiv.appendChild(passItem);

      // Card Action Bar (Show/Hide, Copy Username, Copy Password, Edit, Delete)
      const actionBar = document.createElement('div');
      actionBar.className = 'account-card-action-bar';

      const mainActionsGroup = document.createElement('div');
      mainActionsGroup.className = 'account-card-action-group';

      // 1. Show / Hide Password Button
      const togglePassBtn = document.createElement('button');
      togglePassBtn.id = `btn-toggle-pass-${account.id}`;
      togglePassBtn.className = `btn-card-action btn-toggle-pass ${isRevealed ? 'active-show' : ''}`;
      togglePassBtn.setAttribute('data-id', account.id);
      togglePassBtn.type = 'button';
      togglePassBtn.setAttribute('aria-label', isRevealed ? 'Hide password' : 'Show password');
      togglePassBtn.innerHTML = isRevealed
        ? `<svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
             <line x1="1" y1="1" x2="23" y2="23"></line>
           </svg>
           <span>Hide</span>`
        : `<svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
             <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
             <circle cx="12" cy="12" r="3"></circle>
           </svg>
           <span>Show</span>`;

      // 2. Copy Username Button
      const copyUserBtn = document.createElement('button');
      copyUserBtn.className = 'btn-card-action btn-copy-username';
      copyUserBtn.setAttribute('data-id', account.id);
      copyUserBtn.type = 'button';
      copyUserBtn.setAttribute('aria-label', 'Copy username');
      copyUserBtn.innerHTML = `
        <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
        <span>Copy Username</span>
      `;

      // 3. Copy Password Button
      const copyPassBtn = document.createElement('button');
      copyPassBtn.className = 'btn-card-action btn-copy-password';
      copyPassBtn.setAttribute('data-id', account.id);
      copyPassBtn.type = 'button';
      copyPassBtn.setAttribute('aria-label', 'Copy password');
      copyPassBtn.innerHTML = `
        <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
        <span>Copy Password</span>
      `;

      // 4. Autofill Button (Stage 7 User-Triggered Autofill)
      const autofillBtn = document.createElement('button');
      autofillBtn.className = 'btn-card-action btn-autofill';
      autofillBtn.setAttribute('data-id', account.id);
      autofillBtn.type = 'button';
      autofillBtn.setAttribute('aria-label', 'Autofill active tab');
      autofillBtn.innerHTML = `
        <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 2l-2 2m-1-1l-3 3m2-2l-3 3m-2-2l-3 3M3 21l9-9"></path>
          <circle cx="7.5" cy="7.5" r="4.5"></circle>
        </svg>
        <span>Autofill</span>
      `;
      autofillBtn.addEventListener('click', async () => {
        resetActivity();
        await handleAutofillFromVaultPage(account.id);
      });

      mainActionsGroup.appendChild(togglePassBtn);
      mainActionsGroup.appendChild(copyUserBtn);
      mainActionsGroup.appendChild(copyPassBtn);
      mainActionsGroup.appendChild(autofillBtn);

      // Edit and Delete buttons group
      const editDeleteGroup = document.createElement('div');
      editDeleteGroup.className = 'account-card-action-group';

      const editBtn = document.createElement('button');
      editBtn.className = 'btn-card-action btn-edit-account';
      editBtn.setAttribute('data-id', account.id);
      editBtn.type = 'button';
      editBtn.setAttribute('aria-label', 'Edit account');
      editBtn.innerHTML = `
        <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
          <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
        </svg>
        <span>Edit</span>
      `;

      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'btn-card-action btn-action-danger btn-delete-account';
      deleteBtn.setAttribute('data-id', account.id);
      deleteBtn.type = 'button';
      deleteBtn.setAttribute('aria-label', 'Delete account');
      deleteBtn.innerHTML = `
        <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
        </svg>
        <span>Delete</span>
      `;

      editDeleteGroup.appendChild(editBtn);
      editDeleteGroup.appendChild(deleteBtn);

      actionBar.appendChild(mainActionsGroup);
      actionBar.appendChild(editDeleteGroup);

      card.appendChild(topRow);
      card.appendChild(bodyDiv);

      // Extra Section: Safe Website Anchor & Notes
      const urlCheck = validateHttpUrl(account.website);
      const hasValidWebsite = Boolean(account.website && urlCheck.valid && urlCheck.cleanUrl);
      const hasNotes = Boolean(account.notes && account.notes.trim().length > 0);

      if (hasValidWebsite || hasNotes) {
        const extraDiv = document.createElement('div');
        extraDiv.className = 'account-card-extra';

        if (hasValidWebsite) {
          const webRow = document.createElement('div');
          webRow.className = 'account-website-row';

          const webIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
          webIcon.setAttribute('class', 'icon-svg-sm');
          webIcon.setAttribute('viewBox', '0 0 24 24');
          webIcon.setAttribute('fill', 'none');
          webIcon.setAttribute('stroke', 'currentColor');
          webIcon.setAttribute('stroke-width', '2');
          webIcon.innerHTML = '<circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>';

          const anchor = document.createElement('a');
          anchor.href = urlCheck.cleanUrl;
          anchor.textContent = account.website;
          anchor.target = '_blank';
          anchor.rel = 'noopener noreferrer';
          anchor.style.color = 'var(--primary)';
          anchor.style.textDecoration = 'none';
          anchor.style.wordBreak = 'break-all';

          webRow.appendChild(webIcon);
          webRow.appendChild(anchor);
          extraDiv.appendChild(webRow);
        }

        if (hasNotes) {
          const notesBox = document.createElement('div');
          notesBox.className = 'account-notes-box';
          notesBox.textContent = account.notes;
          extraDiv.appendChild(notesBox);
        }

        card.appendChild(extraDiv);
      }

      card.appendChild(actionBar);
      accountsListContainer.appendChild(card);
    });
  }

  // --- STAGE 7 USER-TRIGGERED AUTOFILL FROM VAULT PAGE (Requirement 17) ---
  async function handleAutofillFromVaultPage(accountId) {
    if (!activeVek || !decryptedVault || !Array.isArray(decryptedVault.accounts)) {
      showNotification('Vault is locked.');
      return;
    }

    const operationGeneration = lockGeneration;
    const operationVek = activeVek;
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) {
      showNotification('Website changed. Please select the account again.');
      return;
    }

    try {
      let targetTab = null;
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        // Query active tab in the last focused window
        const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
        if (tabs && tabs.length > 0) {
          const cand = tabs[0];
          if (cand.url && !cand.url.includes(chrome.runtime?.id || '') &&
              (cand.url.startsWith('http://') || cand.url.startsWith('https://'))) {
            targetTab = cand;
          }
        }

        // If current window is dedicated vault page, find active tab in other windows
        if (!targetTab) {
          const allTabs = await chrome.tabs.query({ active: true });
          if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
          targetTab = allTabs.find((t) => t.url && !t.url.includes(chrome.runtime?.id || '') &&
              (t.url.startsWith('http://') || t.url.startsWith('https://')));
        }
      }

      if (!targetTab || !targetTab.url) {
        showNotification('No active webpage tab found to autofill.');
        return;
      }

      // Revalidate active tab hostname
      const host = extractHostname(targetTab.url);
      if (!host) {
        showNotification('Website changed. Please select the account again.');
        return;
      }

      // Revalidate account still exists in memory
      if (!decryptedVault.accounts.some((a) => a.id === accountId)) {
        showNotification('Website changed. Please select the account again.');
        return;
      }

      // Revalidate account matches current active tab hostname (Requirement 17)
      if (!account.website || !isDomainMatch(account.website, host)) {
        showNotification('Website changed. Please select the account again.');
        return;
      }

      // Revalidate the exact unlock session before reading credentials or injecting.
      if (!isLockGenerationCurrent(operationGeneration, operationVek) || !decryptedVault) return;

      // Only now retrieve credentials
      const credentials = {
        username: account.username || '',
        password: account.password || ''
      };

      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      const result = await triggerTabAutofill(targetTab.id, targetTab.url, credentials);
      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      if (result.success) {
        showNotification(`Autofilled into ${host}!`);
      } else {
        showNotification(result.message || 'No login fields found on active tab.');
      }
    } catch (err) {
      if (isLockGenerationCurrent(operationGeneration, operationVek)) {
        showNotification(`Autofill failed: ${err.message || 'Script execution error'}`);
      }
    }
  }

  // --- ADD / EDIT ACCOUNT MODAL HANDLERS ---
  function removeDynamicCategoryOptions() {
    Array.from(accountFormCategory.options).forEach((opt) => {
      if (opt.dataset.dynamic === 'true') {
        opt.remove();
      }
    });
  }

  function openAddAccountModal(prefillWebsite = '') {
    if (!activeVek || !decryptedVault) {
      showNotification('Please unlock your vault first.');
      return;
    }
    currentEditAccountId = null;
    removeDynamicCategoryOptions();

    // Defensive check: ensure prefillWebsite is a string; treat accidental event objects as empty string
    let siteStr = typeof prefillWebsite === 'string' ? prefillWebsite.trim() : '';

    // Check query params if siteStr not supplied
    if (!siteStr) {
      try {
        const params = new URLSearchParams(window.location.search);
        siteStr = (params.get('addSite') || params.get('website') || '').trim();
      } catch (_) {}
    }

    vaultAccountModalTitle.textContent = 'Add Account';
    accountFormName.value = siteStr ? siteStr.replace(/^https?:\/\//i, '').split('/')[0] : '';
    accountFormUsername.value = '';
    accountFormPassword.value = '';
    accountFormPassword.type = 'password';
    accountFormCategory.value = 'Other';
    accountFormWebsite.value = siteStr ? (siteStr.startsWith('http://') || siteStr.startsWith('https://') ? siteStr : `https://${siteStr}`) : '';
    accountFormNotes.value = '';
    accountFormSubmitBtn.textContent = 'Save Account';
    vaultAccountModal.classList.remove('hidden');
    accountFormName.focus();
  }

  function openEditAccountModal(accountId) {
    if (!activeVek || !decryptedVault) {
      showNotification('Vault is locked.');
      return;
    }
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) return;

    currentEditAccountId = account.id;
    removeDynamicCategoryOptions();

    vaultAccountModalTitle.textContent = 'Edit Account';
    accountFormName.value = account.name || '';
    accountFormUsername.value = account.username || '';
    accountFormPassword.value = account.password || ''; // Exact preserved password
    accountFormPassword.type = 'password';

    // Handle backward compatibility for custom or old category values
    const storedCat = account.category || 'Other';
    const hasCategoryOption = Array.from(accountFormCategory.options).some((o) => o.value === storedCat);
    if (!hasCategoryOption && storedCat) {
      const dynamicOpt = document.createElement('option');
      dynamicOpt.value = storedCat;
      dynamicOpt.textContent = storedCat;
      dynamicOpt.dataset.dynamic = 'true';
      accountFormCategory.appendChild(dynamicOpt);
    }
    accountFormCategory.value = storedCat;

    accountFormWebsite.value = account.website || '';
    accountFormNotes.value = account.notes || '';
    accountFormSubmitBtn.textContent = 'Update Account';
    vaultAccountModal.classList.remove('hidden');
    accountFormName.focus();
  }

  function closeAccountModal() {
    vaultAccountModal.classList.add('hidden');
    currentEditAccountId = null;
    removeDynamicCategoryOptions();
    accountFormName.value = '';
    accountFormUsername.value = '';
    accountFormPassword.value = '';
    accountFormWebsite.value = '';
    accountFormNotes.value = '';
  }

  /**
   * TRANSACTION-SAFE ACCOUNT SAVE (ADD & EDIT) WITH WEB LOCKS MULTI-TAB SAFETY
   *
   * Flow inside Web Locks write lock:
   * 1. Load the LATEST encrypted vault record from storage.
   * 2. Decrypt that latest vault using the active unlocked VEK.
   * 3. Re-apply the candidate Add/Edit operation to that latest decrypted state.
   * 4. Encrypt with VEK (generates unique fresh 96-bit random IV).
   * 5. Increment vaultRevision.
   * 6. Save encrypted record to chrome.storage.local.
   * 7. ONLY after successful persistence: commit to decryptedVault and render UI.
   *
   * On Failure:
   * - decryptedVault remains 100% untouched.
   * - Visible UI cards remain untouched.
   * - Modal stays open so user can retry or adjust without data loss.
   */
  async function handleSaveAccount() {
    if (isSavingAccount) return;

    if (!activeVek || !decryptedVault) {
      showNotification('Vault is locked. Cannot save account.');
      closeAccountModal();
      return;
    }

    // Capture the current session identity before any asynchronous boundary.
    const operationGeneration = lockGeneration;
    const operationVek = activeVek;

    // Capture edit mode and target ID before any asynchronous boundary
    const isEdit = Boolean(currentEditAccountId);
    const targetEditId = currentEditAccountId;

    const name = accountFormName.value.trim();
    const username = accountFormUsername.value.trim();
    // CRITICAL: Account passwords must be stored EXACTLY as entered. NO trim, NO case changes.
    const password = accountFormPassword.value;
    const category = accountFormCategory.value.trim();
    const websiteInput = accountFormWebsite.value.trim();
    const notes = accountFormNotes.value.trim();

    if (!name) {
      showNotification('Account / Service Name is required.');
      accountFormName.focus();
      return;
    }
    if (!username) {
      showNotification('Username / Email is required.');
      accountFormUsername.focus();
      return;
    }
    if (!password) {
      showNotification('Password is required.');
      accountFormPassword.focus();
      return;
    }
    if (!category) {
      showNotification('Category is required.');
      accountFormCategory.focus();
      return;
    }

    // Validate website URL: optional, but if present must be http or https
    if (websiteInput) {
      const urlCheck = validateHttpUrl(websiteInput);
      if (!urlCheck.valid) {
        showNotification('Please enter a valid HTTP or HTTPS website URL.');
        accountFormWebsite.focus();
        return;
      }
    }

    try {
      isSavingAccount = true;
      accountFormSubmitBtn.disabled = true;
      accountFormSubmitBtn.textContent = 'Encrypting & Saving...';

      const now = new Date().toISOString();

      await withVaultWriteLock(async () => {
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        // 1. Load latest stored encrypted record
        const record = await StorageModule.loadVaultRecord();
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        if (!StorageModule.validateVaultRecord(record)) {
          throw new Error('Encrypted vault record is missing or corrupted.');
        }

        // 2. Decrypt latest stored vault state with active VEK
        const latestVault = await decryptVault(record.vault, operationVek);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        if (!latestVault || !Array.isArray(latestVault.accounts)) {
          latestVault.accounts = [];
        }

        // 3. Build candidate NEXT STATE from latest decrypted data
        let nextAccounts;
        if (isEdit) {
          const idx = latestVault.accounts.findIndex((a) => a.id === targetEditId);
          if (idx === -1) {
            throw new Error('Account not found in latest vault state.');
          }

          const existingAccount = latestVault.accounts[idx];
          const updatedCandidate = {
            ...existingAccount,
            name,
            username,
            password, // Byte-exact preservation
            category,
            website: websiteInput || '',
            notes: notes || '',
            updatedAt: now
          };

          nextAccounts = [...latestVault.accounts];
          nextAccounts[idx] = updatedCandidate;
        } else {
          const newCandidate = {
            id: crypto.randomUUID(),
            name,
            username,
            password, // Byte-exact preservation
            category,
            website: websiteInput || '',
            notes: notes || '',
            createdAt: now,
            updatedAt: now
          };

          nextAccounts = [...latestVault.accounts, newCandidate];
        }

        const nextVault = {
          ...latestVault,
          schemaVersion: 2,
          accounts: nextAccounts
        };

        // 4. Encrypt candidate next vault (generates unique fresh 96-bit random IV)
        const encryptedVault = await encryptVault(nextVault, operationVek);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');

        // 5. Increment vaultRevision
        const nextRevision = (record.vaultRevision || currentVaultRevision || 1) + 1;
        record.vault = encryptedVault;
        record.vaultRevision = nextRevision;

        // 6. Persist to storage
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        await StorageModule.saveVaultRecord(record);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');

        // 7. COMMIT ONLY AFTER PERSISTENCE SUCCEEDS AND THE SESSION IS STILL CURRENT
        decryptedVault = nextVault;
        currentVaultRevision = nextRevision;
      });

      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      if (isEdit && targetEditId) {
        if (passwordRevealTimers.has(targetEditId)) {
          clearTimeout(passwordRevealTimers.get(targetEditId));
          passwordRevealTimers.delete(targetEditId);
        }
        revealedPasswordAccountIds.delete(targetEditId);
      }

      closeAccountModal();
      renderAccounts();
      showNotification(isEdit ? 'Account updated successfully.' : 'Account saved to encrypted vault.');
    } catch (_) {
      // A lock invalidates the operation; do not show stale failure UI after locking.
      if (isLockGenerationCurrent(operationGeneration, operationVek)) {
        showNotification(isEdit ? 'Failed to update account. Changes not saved.' : 'Failed to save account to encrypted vault.');
      }
    } finally {
      isSavingAccount = false;
      accountFormSubmitBtn.disabled = false;
      accountFormSubmitBtn.textContent = isEdit ? 'Update Account' : 'Save Account';
    }
  }

  // Form submit listener for vaultAccountForm (SINGLE source of truth; no duplicate click handler)
  if (vaultAccountForm) {
    vaultAccountForm.addEventListener('submit', (e) => {
      e.preventDefault();
      handleSaveAccount();
    });
  }

  // Prevent Enter key in multiline Notes textarea from submitting the form
  if (accountFormNotes) {
    accountFormNotes.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.stopPropagation();
      }
    });
  }

  // --- DELETE ACCOUNT CONFIRMATION HANDLERS (MULTI-TAB SAFE & TRANSACTION SAFE) ---
  function openDeleteModal(accountId) {
    if (!activeVek || !decryptedVault) {
      showNotification('Vault is locked.');
      return;
    }
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) return;

    currentDeleteAccountId = account.id;
    deleteAccountTargetName.textContent = account.name;
    vaultDeleteModal.classList.remove('hidden');
  }

  function closeDeleteModal() {
    vaultDeleteModal.classList.add('hidden');
    currentDeleteAccountId = null;
    deleteAccountTargetName.textContent = '';
  }

  async function handleConfirmDelete() {
    if (isDeletingAccount) return;

    if (!activeVek || !decryptedVault || !currentDeleteAccountId) {
      closeDeleteModal();
      return;
    }

    const targetId = currentDeleteAccountId;
    const operationGeneration = lockGeneration;
    const operationVek = activeVek;

    try {
      isDeletingAccount = true;
      vaultConfirmDeleteBtn.disabled = true;
      vaultConfirmDeleteBtn.textContent = 'Deleting...';

      await withVaultWriteLock(async () => {
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        // 1. Load latest stored encrypted record
        const record = await StorageModule.loadVaultRecord();
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        if (!StorageModule.validateVaultRecord(record)) {
          throw new Error('Encrypted vault record is missing or corrupted.');
        }

        // 2. Decrypt latest vault with active VEK
        const latestVault = await decryptVault(record.vault, operationVek);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        if (!latestVault || !Array.isArray(latestVault.accounts)) {
          latestVault.accounts = [];
        }

        // 3. Remove target account from latest accounts
        const nextAccounts = latestVault.accounts.filter((a) => a.id !== targetId);
        const nextVault = {
          ...latestVault,
          schemaVersion: 2,
          accounts: nextAccounts
        };

        // 4. Encrypt candidate next state (unique random IV)
        const encryptedVault = await encryptVault(nextVault, operationVek);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');

        // 5. Increment revision
        const nextRevision = (record.vaultRevision || currentVaultRevision || 1) + 1;
        record.vault = encryptedVault;
        record.vaultRevision = nextRevision;

        // 6. Save to storage
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        await StorageModule.saveVaultRecord(record);
        if (!isLockGenerationCurrent(operationGeneration, operationVek)) throw new Error('VAULT_LOCKED_DURING_OPERATION');

        // 7. COMMIT ONLY ON SUCCESS AND CURRENT SESSION
        decryptedVault = nextVault;
        currentVaultRevision = nextRevision;
      });

      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      // Clear revealed timer for deleted account
      if (passwordRevealTimers.has(targetId)) {
        clearTimeout(passwordRevealTimers.get(targetId));
        passwordRevealTimers.delete(targetId);
      }
      revealedPasswordAccountIds.delete(targetId);

      closeDeleteModal();
      renderAccounts();
      showNotification('Account removed from vault.');
    } catch (_) {
      // A lock invalidates the operation; suppress stale post-lock failure UI.
      if (isLockGenerationCurrent(operationGeneration, operationVek)) {
        showNotification('Failed to delete account from encrypted vault.');
      }
    } finally {
      isDeletingAccount = false;
      vaultConfirmDeleteBtn.disabled = false;
      vaultConfirmDeleteBtn.textContent = 'Delete Account';
    }
  }

  // ==================================================
  // 5. STAGE 5 PASSWORD GENERATOR
  // ==================================================

  /**
   * Read generator options from the UI controls.
   */
  function getGeneratorOptionsFromUI() {
    const rawLen = generatorLengthInput ? parseInt(generatorLengthInput.value, 10) : DEFAULT_PASSWORD_LENGTH;
    const length = isNaN(rawLen) ? DEFAULT_PASSWORD_LENGTH : rawLen;
    const useUppercase = genOptUppercase ? genOptUppercase.checked : true;
    const useLowercase = genOptLowercase ? genOptLowercase.checked : true;
    const useNumbers = genOptNumbers ? genOptNumbers.checked : true;
    const useSymbols = genOptSymbols ? genOptSymbols.checked : true;

    return {
      length,
      useUppercase,
      useLowercase,
      useNumbers,
      useSymbols
    };
  }

  /**
   * Regenerate and render password based on current generator controls.
   * Handles validation errors gracefully by displaying clear UI feedback.
   */
  function refreshGeneratedPassword() {
    try {
      const options = getGeneratorOptionsFromUI();
      const validated = validateGeneratorOptions(options);

      // Hide error banner when options are valid
      if (generatorErrorBanner) generatorErrorBanner.classList.add('hidden');
      if (generatorCopyBtn) generatorCopyBtn.disabled = false;
      if (generatorUseInFormBtn) generatorUseInFormBtn.disabled = false;

      const password = generatePassword(validated);
      if (generatorPreviewInput) {
        generatorPreviewInput.value = password;
      }
      return password;
    } catch (err) {
      // Display validation error to user
      if (generatorErrorBanner && generatorErrorText) {
        generatorErrorText.textContent = err.message || 'Invalid generator settings.';
        generatorErrorBanner.classList.remove('hidden');
      }
      if (generatorPreviewInput) {
        generatorPreviewInput.value = '';
      }
      if (generatorCopyBtn) generatorCopyBtn.disabled = true;
      if (generatorUseInFormBtn) generatorUseInFormBtn.disabled = true;
      return null;
    }
  }

  /**
   * Open the Password Generator modal.
   * If targetInput is provided (e.g. accountFormPassword), displays "Use in Account" button.
   * Resets all generator settings to Stage 5 defaults every time it opens.
   */
  function openGeneratorModal(targetInput = null) {
    generatorTargetInputField = targetInput;

    if (generatorUseInFormBtn) {
      if (targetInput) {
        generatorUseInFormBtn.classList.remove('hidden');
      } else {
        generatorUseInFormBtn.classList.add('hidden');
      }
    }

    // Reset generator controls to defaults every time the modal opens
    if (generatorLengthInput) generatorLengthInput.value = '20';
    if (generatorLengthRange) generatorLengthRange.value = '20';

    if (genOptUppercase) genOptUppercase.checked = true;
    if (genOptLowercase) genOptLowercase.checked = true;
    if (genOptNumbers) genOptNumbers.checked = true;
    if (genOptSymbols) genOptSymbols.checked = true;

    if (generatorErrorBanner) generatorErrorBanner.classList.add('hidden');
    if (generatorErrorText) generatorErrorText.textContent = '';

    refreshGeneratedPassword();

    if (vaultGeneratorModal) {
      vaultGeneratorModal.classList.remove('hidden');
    }
  }

  /**
   * Close the Password Generator modal.
   * Clears generator preview input, error messages, and target input reference.
   * Plaintext generated password never remains in the hidden DOM.
   */
  function closeGeneratorModal() {
    if (vaultGeneratorModal) {
      vaultGeneratorModal.classList.add('hidden');
    }

    // 1. Clear preview value so no plaintext generated password remains in the hidden DOM
    if (generatorPreviewInput) {
      generatorPreviewInput.value = '';
    }

    // 2. Clear any generator error message
    if (generatorErrorBanner) {
      generatorErrorBanner.classList.add('hidden');
    }
    if (generatorErrorText) {
      generatorErrorText.textContent = '';
    }

    // 3. Reset target input field reference
    generatorTargetInputField = null;
  }

  /**
   * Copy the generated password to clipboard (1-click copy).
   * Cancels any pending password clipboard timer, copies newest password,
   * starts a fresh 30-second best-effort clear timer, and gives visual feedback.
   */
  async function handleCopyGeneratedPassword() {
    if (!generatorPreviewInput || !generatorPreviewInput.value) {
      showNotification('No password generated to copy.');
      return;
    }

    const password = generatorPreviewInput.value;
    const operationGeneration = lockGeneration;

    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
        throw new Error('Clipboard API unavailable');
      }

      await navigator.clipboard.writeText(password);
      if (!isLockGenerationCurrent(operationGeneration)) {
        try { await navigator.clipboard.writeText(''); } catch (_) {}
        return;
      }
      schedulePasswordClipboardClear();

      // Button feedback
      if (generatorCopyBtn) {
        const originalHtml = generatorCopyBtn.innerHTML;
        generatorCopyBtn.innerHTML = `
          <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          <span>Copied!</span>
        `;
        setTimeout(() => {
          if (generatorCopyBtn) generatorCopyBtn.innerHTML = originalHtml;
        }, 1800);
      }

      showNotification('Generated password copied to clipboard. Clipboard will be cleared in about 30 seconds.');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Could not copy generated password.');
      }
    }
  }

  /**
   * Apply generated password to the active target form input and close modal.
   */
  function handleUseGeneratedPasswordInForm() {
    if (!generatorPreviewInput || !generatorPreviewInput.value) {
      showNotification('No password generated.');
      return;
    }

    const password = generatorPreviewInput.value;
    if (generatorTargetInputField) {
      generatorTargetInputField.value = password;
      // Dispatch input event so any form validation is notified
      generatorTargetInputField.dispatchEvent(new Event('input', { bubbles: true }));
      showNotification('Generated password applied to account form.');
    }
    closeGeneratorModal();
  }

  // Modal Buttons & Triggers (Non-submit actions)
  if (vaultAddAccountBtn) {
    vaultAddAccountBtn.addEventListener('click', () => openAddAccountModal());
  }
  if (emptyAddAccountBtn) {
    emptyAddAccountBtn.addEventListener('click', () => openAddAccountModal());
  }

  if (vaultCloseAccountModalBtn) vaultCloseAccountModalBtn.addEventListener('click', closeAccountModal);
  if (accountFormCancelBtn) accountFormCancelBtn.addEventListener('click', closeAccountModal);

  if (vaultCloseDeleteModalBtn) vaultCloseDeleteModalBtn.addEventListener('click', closeDeleteModal);
  if (vaultCancelDeleteBtn) vaultCancelDeleteBtn.addEventListener('click', closeDeleteModal);
  if (vaultConfirmDeleteBtn) vaultConfirmDeleteBtn.addEventListener('click', handleConfirmDelete);

  // Stage 5 Generator Triggers & Buttons
  if (vaultOpenGeneratorBtn) {
    vaultOpenGeneratorBtn.addEventListener('click', () => openGeneratorModal(null));
  }
  if (accountFormGenerateBtn) {
    accountFormGenerateBtn.addEventListener('click', () => openGeneratorModal(accountFormPassword));
  }

  if (vaultCloseGeneratorBtn) vaultCloseGeneratorBtn.addEventListener('click', closeGeneratorModal);
  if (generatorDoneBtn) generatorDoneBtn.addEventListener('click', closeGeneratorModal);
  if (generatorRegenBtn) generatorRegenBtn.addEventListener('click', refreshGeneratedPassword);
  if (generatorCopyBtn) generatorCopyBtn.addEventListener('click', handleCopyGeneratedPassword);
  if (generatorUseInFormBtn) generatorUseInFormBtn.addEventListener('click', handleUseGeneratedPasswordInForm);

  if (generatorLengthRange && generatorLengthInput) {
    generatorLengthRange.addEventListener('input', () => {
      generatorLengthInput.value = generatorLengthRange.value;
      refreshGeneratedPassword();
    });

    generatorLengthInput.addEventListener('input', () => {
      const val = parseInt(generatorLengthInput.value, 10);
      if (!isNaN(val) && val >= MIN_PASSWORD_LENGTH && val <= MAX_PASSWORD_LENGTH) {
        generatorLengthRange.value = String(val);
      }
      refreshGeneratedPassword();
    });

    generatorLengthInput.addEventListener('change', () => {
      let val = parseInt(generatorLengthInput.value, 10);
      if (isNaN(val) || val < MIN_PASSWORD_LENGTH) {
        val = MIN_PASSWORD_LENGTH;
      } else if (val > MAX_PASSWORD_LENGTH) {
        val = MAX_PASSWORD_LENGTH;
      }
      generatorLengthInput.value = String(val);
      generatorLengthRange.value = String(val);
      refreshGeneratedPassword();
    });
  }

  [genOptUppercase, genOptLowercase, genOptNumbers, genOptSymbols].forEach((cb) => {
    if (cb) {
      cb.addEventListener('change', refreshGeneratedPassword);
    }
  });

  if (vaultGeneratorModal) {
    vaultGeneratorModal.addEventListener('click', (e) => {
      if (e.target === vaultGeneratorModal) {
        closeGeneratorModal();
      }
    });
  }

  // Delegated clicks for account card actions (Toggle Password, Copy Username, Copy Password, Edit & Delete)
  if (accountsListContainer) {
    accountsListContainer.addEventListener('click', (e) => {
      const toggleBtn = e.target.closest('.btn-toggle-pass');
      if (toggleBtn) {
        const id = toggleBtn.getAttribute('data-id');
        if (id) togglePasswordVisibility(id);
        return;
      }

      const copyUserBtn = e.target.closest('.btn-copy-username');
      if (copyUserBtn) {
        const id = copyUserBtn.getAttribute('data-id');
        if (id) copyUsername(id);
        return;
      }

      const copyPassBtn = e.target.closest('.btn-copy-password');
      if (copyPassBtn) {
        const id = copyPassBtn.getAttribute('data-id');
        if (id) copyPassword(id);
        return;
      }

      const editBtn = e.target.closest('.btn-edit-account');
      if (editBtn) {
        const id = editBtn.getAttribute('data-id');
        if (id) openEditAccountModal(id);
        return;
      }

      const deleteBtn = e.target.closest('.btn-delete-account');
      if (deleteBtn) {
        const id = deleteBtn.getAttribute('data-id');
        if (id) openDeleteModal(id);
        return;
      }
    });
  }

  // Stage 4: Live search input listener
  if (vaultSearchInput) {
    vaultSearchInput.addEventListener('input', () => {
      currentSearchQuery = vaultSearchInput.value;
      clearAllRevealedPasswords();
      renderAccounts();
    });
  }

  // Stage 4: Category filter chips listener
  if (categoryChipsGroup) {
    categoryChipsGroup.addEventListener('click', (e) => {
      const chip = e.target.closest('.chip');
      if (!chip) return;
      const category = chip.getAttribute('data-category') || 'All';
      currentCategoryFilter = category;
      categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
        const isMatch = c === chip;
        c.classList.toggle('active', isMatch);
        c.setAttribute('aria-selected', isMatch ? 'true' : 'false');
      });
      clearAllRevealedPasswords();
      renderAccounts();
    });
  }

  // Stage 4: Sorting select dropdown listener
  if (vaultSortSelect) {
    vaultSortSelect.addEventListener('change', () => {
      currentSortOption = vaultSortSelect.value;
      clearAllRevealedPasswords();
      renderAccounts();
    });
  }

  // ==================================================
  // 6. STAGE 6 AUTO-LOCK, SETTINGS, EXPORT & RESTORE
  // ==================================================

  /**
   * Load non-sensitive UI settings from storage (e.g. autoLockMinutes)
   */
  async function initSecuritySettings() {
    try {
      const settings = await StorageModule.getSettings();
      if (settings && typeof settings.autoLockMinutes === 'number') {
        const val = [1, 5, 10, 15, 30, 60, 0].includes(settings.autoLockMinutes) ? settings.autoLockMinutes : 5;
        autoLockMinutes = val;
      }
      if (autoLockSelect) {
        autoLockSelect.value = String(autoLockMinutes);
      }
    } catch (_) {}
  }

  /**
   * Reset in-memory activity timestamp and schedule auto-lock.
   * Never stores lastActivityAt in persistent storage.
   */
  function resetActivity() {
    if (!activeVek) return;

    lastActivityAt = Date.now();

    if (autoLockTimer) {
      clearTimeout(autoLockTimer);
      autoLockTimer = null;
    }

    if (autoLockMinutes === 0) {
      // Inactivity lock explicitly disabled by user ("Never")
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'CLEAR_AUTO_LOCK' }).catch(() => {});
      }
      return;
    }

    const durationMs = autoLockMinutes * 60 * 1000;
    const deadline = lastActivityAt + durationMs;

    autoLockTimer = setTimeout(() => {
      checkAutoLockDeadline();
    }, durationMs + 50);

    // Communicate non-sensitive deadline to background service worker for alarm trigger
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'SCHEDULE_AUTO_LOCK', deadline }).catch(() => {});
    }
  }

  /**
   * Checks whether the inactivity auto-lock deadline has expired.
   * Protects against tab suspension, throttling, or sleep delays.
   */
  function checkAutoLockDeadline(options = {}) {
    if (!activeVek) return;
    if (autoLockMinutes === 0) return;

    const now = Date.now();
    const deadline = lastActivityAt + autoLockMinutes * 60 * 1000;

    if (now >= deadline) {
      lockVault({ broadcast: options.broadcast !== false, notify: true, reason: 'inactivity' });
      showNotification('Vault locked due to inactivity.');
    } else {
      const remainingMs = Math.max(deadline - now, 1000);
      if (autoLockTimer) clearTimeout(autoLockTimer);
      autoLockTimer = setTimeout(() => {
        checkAutoLockDeadline();
      }, remainingMs + 50);
    }
  }

  // Activity listeners for meaningful user actions (never on passive pointermove)
  const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'touchstart', 'focusin'];
  function handleUserActivity() {
    if (!activeVek) return;
    if (!activityThrottleTimer) {
      resetActivity();
      activityThrottleTimer = setTimeout(() => {
        activityThrottleTimer = null;
      }, 500);
    }
  }

  ACTIVITY_EVENTS.forEach((evt) => {
    window.addEventListener(evt, handleUserActivity, { passive: true });
  });

  // Re-check deadline immediately upon tab visibility, focus, or pageshow resume
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && activeVek) {
      checkAutoLockDeadline();
    }
  });

  window.addEventListener('focus', () => {
    if (activeVek) {
      checkAutoLockDeadline();
    }
  });

  window.addEventListener('pageshow', () => {
    if (activeVek) {
      checkAutoLockDeadline();
    }
  });

  // Listen for signals from background service worker (AUTO_LOCK alarm or SYSTEM_LOCK screen lock)
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message) => {
      if (!message || typeof message !== 'object') return;
      if (message.type === 'AUTO_LOCK') {
        if (activeVek && autoLockMinutes !== 0) {
          checkAutoLockDeadline({ broadcast: false });
        }
      } else if (message.type === 'SYSTEM_LOCK') {
        // Background already broadcasts this event to every extension view.
        lockVault({ broadcast: false, notify: false, reason: 'system' });
      } else if (message.type === 'LOCK_VAULT') {
        // Ignore our own broadcast; every other view invalidates its session and UI.
        if (message.sourceId !== viewInstanceId) {
          lockVault({ broadcast: false, notify: false, reason: message.reason || 'remote' });
        }
      }
    });
  }

  // --- SETTINGS MODAL ---
  function openSettingsModal() {
    if (!activeVek) {
      showNotification('Unlock your vault to access settings.');
      return;
    }
    if (autoLockSelect) autoLockSelect.value = String(autoLockMinutes);
    if (vaultSettingsModal) vaultSettingsModal.classList.remove('hidden');
    resetActivity();
  }

  function closeSettingsModal() {
    if (vaultSettingsModal) vaultSettingsModal.classList.add('hidden');
  }

  async function handleAutoLockChange() {
    if (!autoLockSelect) return;
    const minutes = parseInt(autoLockSelect.value, 10);
    const validMinutes = [1, 5, 10, 15, 30, 60, 0].includes(minutes) ? minutes : 5;
    autoLockMinutes = validMinutes;
    await StorageModule.saveSettings({ autoLockMinutes: validMinutes });
    resetActivity();
    const label = validMinutes === 0 ? 'Inactivity auto-lock disabled.' : `Auto-lock set to ${validMinutes} minutes.`;
    showNotification(label);
  }

  // --- ENCRYPTED EXPORT / BACKUP ---
  async function handleExportBackup() {
    if (isExportingBackup) return;
    const operationGeneration = lockGeneration;
    const operationVek = activeVek;
    try {
      isExportingBackup = true;
      resetActivity();

      // Requirement 16: Require unlocked vault
      if (!activeVek) {
        showNotification('Please unlock the vault before exporting a backup.');
        return;
      }

      const record = await StorageModule.loadVaultRecord();
      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      if (!record || !StorageModule.validateVaultRecord(record)) {
        showNotification('Cannot export: No valid encrypted vault record exists.');
        return;
      }

      // Requirement 4: Final backup file format
      const backupData = {
        backupFormat: 'secure-vault-backup',
        backupVersion: 1,
        exportedAt: new Date().toISOString(),
        vaultRecord: {
          schemaVersion: record.schemaVersion || 2,
          vaultRevision: record.vaultRevision || 1,
          vault: record.vault,
          masterProtection: record.masterProtection,
          recoveryProtection: record.recoveryProtection
        }
      };

      if (!isLockGenerationCurrent(operationGeneration, operationVek)) return;
      const jsonStr = JSON.stringify(backupData, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const dateStr = new Date().toISOString().slice(0, 10);
      const filename = `secure-vault-backup-${dateStr}.svault.json`;

      const downloadLink = document.createElement('a');
      downloadLink.href = url;
      downloadLink.download = filename;
      document.body.appendChild(downloadLink);
      downloadLink.click();
      document.body.removeChild(downloadLink);

      setTimeout(() => URL.revokeObjectURL(url), 2000);

      showNotification('Encrypted backup exported successfully.');
    } catch (_) {
      showNotification('Failed to export backup. Please try again.');
    } finally {
      isExportingBackup = false;
    }
  }

  // --- ENCRYPTED RESTORE / IMPORT ---
  function openRestoreModal() {
    closeSettingsModal();
    resetRestoreModalState();
    if (vaultRestoreModal) vaultRestoreModal.classList.remove('hidden');
  }

  function closeRestoreModal() {
    if (vaultRestoreModal) vaultRestoreModal.classList.add('hidden');
    resetRestoreModalState();
  }

  function resetRestoreModalState() {
    pendingRestoreRecord = null;
    pendingRestoreDecrypted = null;
    restoreAuthMode = 'password';

    if (backupFileInput) backupFileInput.value = '';
    if (restoreMasterPasswordInput) restoreMasterPasswordInput.value = '';
    if (restoreRecoveryKeyInput) restoreRecoveryKeyInput.value = '';

    if (restoreErrorBanner) restoreErrorBanner.classList.add('hidden');
    if (restoreErrorText) restoreErrorText.textContent = '';

    if (restoreStepFile) restoreStepFile.classList.remove('hidden');
    if (restoreStepAuth) restoreStepAuth.classList.add('hidden');
    if (restoreStepConfirm) restoreStepConfirm.classList.add('hidden');

    setRestoreAuthMode('password');
  }

  function setRestoreAuthMode(mode) {
    restoreAuthMode = mode;
    if (mode === 'password') {
      if (restoreAuthModePassBtn) {
        restoreAuthModePassBtn.className = 'btn btn-primary btn-sm';
      }
      if (restoreAuthModeRecoveryBtn) {
        restoreAuthModeRecoveryBtn.className = 'btn btn-secondary btn-sm';
      }
      if (restorePassGroup) restorePassGroup.classList.remove('hidden');
      if (restoreRecoveryGroup) restoreRecoveryGroup.classList.add('hidden');
      if (restoreMasterPasswordInput) restoreMasterPasswordInput.focus();
    } else {
      if (restoreAuthModePassBtn) {
        restoreAuthModePassBtn.className = 'btn btn-secondary btn-sm';
      }
      if (restoreAuthModeRecoveryBtn) {
        restoreAuthModeRecoveryBtn.className = 'btn btn-primary btn-sm';
      }
      if (restorePassGroup) restorePassGroup.classList.add('hidden');
      if (restoreRecoveryGroup) restoreRecoveryGroup.classList.remove('hidden');
      if (restoreRecoveryKeyInput) restoreRecoveryKeyInput.focus();
    }
  }

  function showRestoreError(message) {
    if (restoreErrorBanner && restoreErrorText) {
      restoreErrorText.textContent = message;
      restoreErrorBanner.classList.remove('hidden');
    }
  }

  function hideRestoreError() {
    if (restoreErrorBanner) restoreErrorBanner.classList.add('hidden');
    if (restoreErrorText) restoreErrorText.textContent = '';
  }

  // Handle backup file selection (Requirement 5)
  async function handleBackupFileSelected(file) {
    hideRestoreError();
    if (!file) return;
    const operationGeneration = lockGeneration;

    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB max
    if (file.size > MAX_FILE_SIZE) {
      showRestoreError('Backup file exceeds the 5 MB limit.');
      return;
    }

    try {
      const text = await file.text();
      if (!isLockGenerationCurrent(operationGeneration)) return;
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch (_) {
        showRestoreError('Unsupported or invalid backup file.');
        return;
      }

      // Requirement 5: Strict validation of final backup format envelope
      if (
        !parsed ||
        typeof parsed !== 'object' ||
        parsed.backupFormat !== 'secure-vault-backup' ||
        parsed.backupVersion !== 1 ||
        !parsed.vaultRecord ||
        typeof parsed.vaultRecord !== 'object' ||
        !StorageModule.validateVaultRecord(parsed.vaultRecord)
      ) {
        showRestoreError('Unsupported or invalid backup file.');
        return;
      }

      pendingRestoreRecord = parsed.vaultRecord;

      // Update meta text
      if (restoreFileMetaText) {
        const dateStr = parsed.exportedAt ? ` (${parsed.exportedAt.slice(0, 10)})` : '';
        restoreFileMetaText.textContent = `${file.name}${dateStr}`;
      }

      // Transition to Step 2: Authenticate backup
      if (restoreStepFile) restoreStepFile.classList.add('hidden');
      if (restoreStepAuth) restoreStepAuth.classList.remove('hidden');
      setRestoreAuthMode('password');
    } catch (_) {
      if (isLockGenerationCurrent(operationGeneration)) {
        showRestoreError('Unsupported or invalid backup file.');
      }
    }
  }

  // Verify backup credentials (Master Password or Recovery Key)
  async function handleVerifyBackup() {
    if (isRestoringBackup || !pendingRestoreRecord) return;
    const operationGeneration = lockGeneration;
    const backupRecordForOperation = pendingRestoreRecord;
    hideRestoreError();

    try {
      isRestoringBackup = true;
      if (restoreVerifyBtn) {
        restoreVerifyBtn.disabled = true;
        restoreVerifyBtn.textContent = 'Verifying...';
      }

      let vek = null;

      if (restoreAuthMode === 'password') {
        const pass = restoreMasterPasswordInput ? restoreMasterPasswordInput.value : '';
        if (!pass) {
          showRestoreError('Please enter the Master Password for this backup.');
          return;
        }

        const salt = base64ToBytes(backupRecordForOperation.masterProtection.salt);
        const masterKek = await deriveMasterKey(pass, salt);
        if (!isLockGenerationCurrent(operationGeneration) || pendingRestoreRecord !== backupRecordForOperation) return;

        vek = await unwrapVaultKey(
          backupRecordForOperation.masterProtection.wrappedVaultKey,
          backupRecordForOperation.masterProtection.iv,
          masterKek,
          backupRecordForOperation.masterProtection.aad || AAD_MASTER_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration) || pendingRestoreRecord !== backupRecordForOperation) return;
      } else {
        const rawKey = restoreRecoveryKeyInput ? restoreRecoveryKeyInput.value.trim() : '';
        if (!rawKey) {
          showRestoreError('Please enter the Recovery Key for this backup.');
          return;
        }

        const recoveryBytes = parseRecoveryKey(rawKey);
        if (!recoveryBytes) {
          showRestoreError('Invalid Recovery Key format. Must be 64 hexadecimal characters.');
          return;
        }

        const recoveryCryptoKey = await importAesGcmKey(recoveryBytes, false);
        if (!isLockGenerationCurrent(operationGeneration) || pendingRestoreRecord !== backupRecordForOperation) return;

        vek = await unwrapVaultKey(
          backupRecordForOperation.recoveryProtection.wrappedVaultKey,
          backupRecordForOperation.recoveryProtection.iv,
          recoveryCryptoKey,
          backupRecordForOperation.recoveryProtection.aad || AAD_RECOVERY_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration) || pendingRestoreRecord !== backupRecordForOperation) return;
      }

      // Decrypt vault payload with verified VEK
      const decryptedData = await decryptVault(backupRecordForOperation.vault, vek);
      if (!isLockGenerationCurrent(operationGeneration) || pendingRestoreRecord !== backupRecordForOperation) return;

      // Validate decrypted structure and accounts
      if (!StorageModule.validateDecryptedVault(decryptedData)) {
        throw new Error('Decrypted backup content failed integrity checks.');
      }

      // Authentication and integrity check succeeded
      pendingRestoreDecrypted = {
        vek,
        vaultData: decryptedData
      };

      // Requirement 6: Immediately clear plaintext credential inputs after verification
      if (restoreMasterPasswordInput) restoreMasterPasswordInput.value = '';
      if (restoreRecoveryKeyInput) restoreRecoveryKeyInput.value = '';

      // Transition to Step 3: Confirmation
      if (restoreStepAuth) restoreStepAuth.classList.add('hidden');
      if (restoreStepConfirm) restoreStepConfirm.classList.remove('hidden');
    } catch (_) {
      // Requirement 9: Generic message on backup authentication failure
      if (isLockGenerationCurrent(operationGeneration) && pendingRestoreRecord === backupRecordForOperation) {
        showRestoreError('Incorrect backup credentials or corrupted backup.');
      }
    } finally {
      isRestoringBackup = false;
      if (restoreVerifyBtn) {
        restoreVerifyBtn.disabled = false;
        restoreVerifyBtn.textContent = 'Verify Backup';
      }
    }
  }

  // Commit restore and replace current vault (Requirements 1, 2, 3, 9, 10, 11, 12, 13)
  async function handleCommitRestore() {
    const operationGeneration = lockGeneration;
    // Requirement 3: Double-click / concurrency protection
    if (isRestoringBackup) return;
    if (!pendingRestoreRecord || !pendingRestoreDecrypted) {
      showNotification('No verified backup to restore.');
      return;
    }

    try {
      isRestoringBackup = true;
      if (restoreCommitBtn) {
        restoreCommitBtn.disabled = true;
        restoreCommitBtn.textContent = 'Restoring...';
      }

      // Requirement 2: Wrap entire commit in withVaultWriteLock
      await withVaultWriteLock(async () => {
        if (!isLockGenerationCurrent(operationGeneration)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        // Requirement 11: Re-verify pending backup still exists
        if (!pendingRestoreRecord || !pendingRestoreDecrypted) {
          throw new Error('Restore data expired.');
        }

        // Requirement 11: Revalidate record structure
        if (!StorageModule.validateVaultRecord(pendingRestoreRecord)) {
          throw new Error('Backup record failed revalidation.');
        }

        // Requirement 12: Retain backup record fields without artificial revision increment
        const cleanRecord = {
          schemaVersion: pendingRestoreRecord.schemaVersion || 2,
          vaultRevision: pendingRestoreRecord.vaultRevision || 1,
          vault: pendingRestoreRecord.vault,
          masterProtection: pendingRestoreRecord.masterProtection,
          recoveryProtection: pendingRestoreRecord.recoveryProtection
        };

        // Requirement 10: Commit encrypted backup record to storage
        if (!isLockGenerationCurrent(operationGeneration)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
        await StorageModule.saveVaultRecord(cleanRecord);
        if (!isLockGenerationCurrent(operationGeneration)) throw new Error('VAULT_LOCKED_DURING_OPERATION');
      });
      if (!isLockGenerationCurrent(operationGeneration)) return;

      // Requirement 1 & 13: Full sensitive-state cleanup and transition to LOCKED SCREEN
      lockGeneration += 1;
      broadcastGlobalLock('restore');
      activeVek = null;
      decryptedVault = null;
      tempRecoveryCryptoKey = null;
      pendingRestoreRecord = null;
      pendingRestoreDecrypted = null;
      currentEditAccountId = null;
      currentDeleteAccountId = null;
      failedUnlockAttempts = 0;

      // Cancel auto-lock timer & clear background alarm
      if (autoLockTimer) {
        clearTimeout(autoLockTimer);
        autoLockTimer = null;
      }
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'CLEAR_AUTO_LOCK' }).catch(() => {});
      }

      // Reset search, filter, and sorting
      currentSearchQuery = '';
      if (vaultSearchInput) vaultSearchInput.value = '';
      currentCategoryFilter = 'All';
      if (categoryChipsGroup) {
        categoryChipsGroup.querySelectorAll('.chip').forEach((c) => {
          const isAll = c.getAttribute('data-category') === 'All';
          c.classList.toggle('active', isAll);
          c.setAttribute('aria-selected', isAll ? 'true' : 'false');
        });
      }
      currentSortOption = 'recently-updated';
      if (vaultSortSelect) vaultSortSelect.value = 'recently-updated';

      // Clear revealed passwords & cancel clipboard timers
      clearAllRevealedPasswords();
      // Keep an already scheduled clipboard expiry alive across restore/lock.

      // Hide toolbars and empty states
      if (vaultFilterSortToolbar) vaultFilterSortToolbar.classList.add('hidden');
      if (vaultSearchEmptyState) vaultSearchEmptyState.classList.add('hidden');
      if (vaultAccountsSection) vaultAccountsSection.classList.add('hidden');
      if (vaultEmptyState) vaultEmptyState.classList.remove('hidden');

      // Close all modals
      closeAccountModal();
      closeDeleteModal();
      closeGeneratorModal();
      closeSettingsModal();
      closeRestoreModal();
      if (!vaultChangePassModal.classList.contains('hidden')) closeChangePassModal();
      if (!vaultResetModal.classList.contains('hidden')) closeResetModal();

      if (accountsListContainer) accountsListContainer.innerHTML = '';
      updateItemCount(0);

      if (vaultPageUnlockPassword) vaultPageUnlockPassword.value = '';
      if (modalCurPass) modalCurPass.value = '';
      if (modalNewPass) modalNewPass.value = '';
      if (modalConfirmPass) modalConfirmPass.value = '';
      if (backupFileInput) backupFileInput.value = '';
      if (restoreMasterPasswordInput) restoreMasterPasswordInput.value = '';
      if (restoreRecoveryKeyInput) restoreRecoveryKeyInput.value = '';

      // Transition strictly to locked card
      showAuthCard(vaultLockedCard);
      showNotification('Vault restored successfully. Unlock with your backup credentials.');
    } catch (_) {
      // Requirement 9: Generic restore failure message, current vault preserved
      if (isLockGenerationCurrent(operationGeneration)) {
        showNotification('Restore failed. Your current vault is unchanged.');
      }
    } finally {
      isRestoringBackup = false;
      if (restoreCommitBtn) {
        restoreCommitBtn.disabled = false;
        restoreCommitBtn.textContent = 'Replace Current Vault';
      }
    }
  }

  // Stage 6 Buttons & Event Listeners
  if (vaultOpenSettingsBtn) vaultOpenSettingsBtn.addEventListener('click', openSettingsModal);
  if (vaultCloseSettingsBtn) vaultCloseSettingsBtn.addEventListener('click', closeSettingsModal);
  if (vaultCloseSettingsBtn2) vaultCloseSettingsBtn2.addEventListener('click', closeSettingsModal);
  if (settingsLockNowBtn) settingsLockNowBtn.addEventListener('click', lockVault);
  if (autoLockSelect) autoLockSelect.addEventListener('change', handleAutoLockChange);

  if (settingsExportBackupBtn) settingsExportBackupBtn.addEventListener('click', handleExportBackup);
  if (settingsRestoreBackupBtn) settingsRestoreBackupBtn.addEventListener('click', openRestoreModal);

  // Restore Modal Buttons & Triggers
  if (vaultCloseRestoreBtn) vaultCloseRestoreBtn.addEventListener('click', closeRestoreModal);
  if (restoreCancelBtn) restoreCancelBtn.addEventListener('click', closeRestoreModal);

  if (selectBackupFileBtn) {
    selectBackupFileBtn.addEventListener('click', () => {
      if (backupFileInput) backupFileInput.click();
    });
  }

  if (backupFileInput) {
    backupFileInput.addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) handleBackupFileSelected(file);
    });
  }

  if (restoreAuthModePassBtn) {
    restoreAuthModePassBtn.addEventListener('click', () => setRestoreAuthMode('password'));
  }
  if (restoreAuthModeRecoveryBtn) {
    restoreAuthModeRecoveryBtn.addEventListener('click', () => setRestoreAuthMode('recovery'));
  }

  if (restoreVerifyBtn) restoreVerifyBtn.addEventListener('click', handleVerifyBackup);
  if (restoreCommitBtn) restoreCommitBtn.addEventListener('click', handleCommitRestore);

  // Restore triggers from Auth screens & Error cards
  if (vaultLockedRestoreBtn) vaultLockedRestoreBtn.addEventListener('click', openRestoreModal);
  if (vaultSetupRestoreBtn) vaultSetupRestoreBtn.addEventListener('click', openRestoreModal);
  if (vaultCorruptedRestoreBtn) vaultCorruptedRestoreBtn.addEventListener('click', openRestoreModal);

  if (vaultCorruptedRetryBtn) vaultCorruptedRetryBtn.addEventListener('click', checkVaultStatus);
  if (vaultStorageRetryBtn) vaultStorageRetryBtn.addEventListener('click', checkVaultStatus);

  // Backdrop clicks for Settings and Restore modals
  if (vaultSettingsModal) {
    vaultSettingsModal.addEventListener('click', (e) => {
      if (e.target === vaultSettingsModal) closeSettingsModal();
    });
  }
  if (vaultRestoreModal) {
    vaultRestoreModal.addEventListener('click', (e) => {
      if (e.target === vaultRestoreModal) closeRestoreModal();
    });
  }

  // Close modals on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (vaultAccountModal && !vaultAccountModal.classList.contains('hidden')) closeAccountModal();
      if (vaultDeleteModal && !vaultDeleteModal.classList.contains('hidden')) closeDeleteModal();
      if (vaultChangePassModal && !vaultChangePassModal.classList.contains('hidden')) closeChangePassModal();
      if (vaultResetModal && !vaultResetModal.classList.contains('hidden')) closeResetModal();
      if (vaultGeneratorModal && !vaultGeneratorModal.classList.contains('hidden')) closeGeneratorModal();
      if (vaultSettingsModal && !vaultSettingsModal.classList.contains('hidden')) closeSettingsModal();
      if (vaultRestoreModal && !vaultRestoreModal.classList.contains('hidden')) closeRestoreModal();
    } else if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'K' || e.key === 'k')) {
      e.preventDefault();
      if (activeVek) {
        lockVault();
        showNotification('Vault locked.');
      }
    }
  });

  // Initialize
  initTheme();
  dismissNotification();
  updateItemCount(0);
  await initSecuritySettings();
  await checkVaultStatus();
});
