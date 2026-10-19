/**
 * Secure Vault - Storage Architecture Module (Stage 3 Hardened)
 *
 * Persists ONLY the encrypted vault record to chrome.storage.local.
 *
 * Distinguishes strictly between:
 * 1. No record exists (First-Time Setup allowed)
 * 2. Valid vault record exists (Unlock / Locked state)
 * 3. Malformed / corrupted record exists (Safe corruption error; creation refused; no silent overwrite)
 * 4. Storage read failure (Storage error state; setup NOT shown; creation refused)
 *
 * NEVER persists:
 * - Master Password
 * - Recovery Key
 * - Plaintext Vault Encryption Key (VEK)
 * - Decrypted credentials / accounts
 */

export const STORAGE_KEY = 'secure_vault_encrypted_record_v2';
export const LEGACY_STORAGE_KEYS = [
  'secure_vault_encrypted_record_v1',
  'secure_vault_record',
  'secureVaultData'
];
const SETTINGS_KEY = 'secureVaultSettings';

const AAD_VAULT = 'Secure Vault|Vault|v2';
const AAD_MASTER_KEY = 'Secure Vault|MasterKey|v2';
const AAD_RECOVERY_KEY = 'Secure Vault|RecoveryKey|v2';

/**
 * Safely decode Base64 string to Uint8Array without throwing.
 * Returns null if invalid or malformed Base64.
 */
function safeBase64ToBytes(base64) {
  if (typeof base64 !== 'string' || !base64.trim()) return null;
  try {
    const clean = base64.trim();
    // Quick regex sanity check for valid Base64 characters
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null;
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (_) {
    return null;
  }
}

/**
 * Check if Chromium chrome.storage.local API is active
 */
function isChromeStorageAvailable() {
  return typeof chrome !== 'undefined' && Boolean(chrome.storage && chrome.storage.local);
}

export const StorageModule = {
  /**
   * Returns true whenever the storage key exists in storage,
   * regardless of whether the record content is valid or malformed.
   * Returns false ONLY when no record exists at all.
   * Throws if storage access fails.
   */
  async hasVaultRecord() {
    if (isChromeStorageAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.storage.local.get([STORAGE_KEY, ...LEGACY_STORAGE_KEYS], (result) => {
          if (chrome.runtime && chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            const hasPrimary = Boolean(
              result &&
              Object.prototype.hasOwnProperty.call(result, STORAGE_KEY) &&
              result[STORAGE_KEY] !== undefined &&
              result[STORAGE_KEY] !== null
            );
            if (hasPrimary) {
              resolve(true);
              return;
            }
            // Check legacy keys to prevent silent overwrite of older records
            for (const legKey of LEGACY_STORAGE_KEYS) {
              if (
                result &&
                Object.prototype.hasOwnProperty.call(result, legKey) &&
                result[legKey] !== undefined &&
                result[legKey] !== null
              ) {
                resolve(true);
                return;
              }
            }
            resolve(false);
          }
        });
      });
    }

    try {
      if (localStorage.getItem(STORAGE_KEY) !== null) return true;
      for (const legKey of LEGACY_STORAGE_KEYS) {
        if (localStorage.getItem(legKey) !== null) return true;
      }
      return false;
    } catch (_) {
      throw new Error('Storage read error.');
    }
  },

  /**
   * Stage 6 Strict Vault Record Validation:
   * Verifies all required structure, types, algorithms, AADs, and exact binary lengths.
   * Returns true if structurally complete and cryptographically valid, false if malformed or tampered.
   */
  validateVaultRecord(record) {
    if (!record || typeof record !== 'object') return false;

    // 1. Schema version
    if (record.schemaVersion !== 2) return false;

    // 2. Vault section
    if (!record.vault || typeof record.vault !== 'object') return false;
    if (record.vault.algorithm !== 'AES-256-GCM') return false;
    if (record.vault.aad !== AAD_VAULT) return false;
    if (typeof record.vault.iv !== 'string' || typeof record.vault.ciphertext !== 'string') return false;

    // 3. Master protection section
    if (!record.masterProtection || typeof record.masterProtection !== 'object') return false;
    if (record.masterProtection.kdf !== 'PBKDF2') return false;
    if (record.masterProtection.hash !== 'SHA-256') return false;
    if (record.masterProtection.iterations !== 600000) return false;
    if (record.masterProtection.algorithm !== 'AES-256-GCM') return false;
    if (record.masterProtection.aad !== AAD_MASTER_KEY) return false;
    if (
      typeof record.masterProtection.salt !== 'string' ||
      typeof record.masterProtection.iv !== 'string' ||
      typeof record.masterProtection.wrappedVaultKey !== 'string'
    ) {
      return false;
    }

    // 4. Recovery protection section
    if (!record.recoveryProtection || typeof record.recoveryProtection !== 'object') return false;
    if (record.recoveryProtection.algorithm !== 'AES-256-GCM') return false;
    if (record.recoveryProtection.aad !== AAD_RECOVERY_KEY) return false;
    if (
      typeof record.recoveryProtection.iv !== 'string' ||
      typeof record.recoveryProtection.wrappedVaultKey !== 'string'
    ) {
      return false;
    }

    // 5. Binary field length validation (Base64-decoded bytes)
    // Salt must be exactly 16 bytes (128 bits)
    const saltBytes = safeBase64ToBytes(record.masterProtection.salt);
    if (!saltBytes || saltBytes.length !== 16) return false;

    // IVs must be exactly 12 bytes (96 bits) for AES-256-GCM
    const vaultIvBytes = safeBase64ToBytes(record.vault.iv);
    if (!vaultIvBytes || vaultIvBytes.length !== 12) return false;

    const masterIvBytes = safeBase64ToBytes(record.masterProtection.iv);
    if (!masterIvBytes || masterIvBytes.length !== 12) return false;

    const recoveryIvBytes = safeBase64ToBytes(record.recoveryProtection.iv);
    if (!recoveryIvBytes || recoveryIvBytes.length !== 12) return false;

    // Wrapped VEKs: 32-byte VEK + 16-byte GCM tag = 48 bytes exactly
    const masterWrapped = safeBase64ToBytes(record.masterProtection.wrappedVaultKey);
    if (!masterWrapped || masterWrapped.length !== 48) return false;

    const recoveryWrapped = safeBase64ToBytes(record.recoveryProtection.wrappedVaultKey);
    if (!recoveryWrapped || recoveryWrapped.length !== 48) return false;

    // Vault ciphertext must be at least 16 bytes for GCM auth tag
    const ciphertextBytes = safeBase64ToBytes(record.vault.ciphertext);
    if (!ciphertextBytes || ciphertextBytes.length < 16) return false;

    return true;
  },

  /**
   * Stage 6 Strict Decrypted Vault Validation:
   * Validates schemaVersion and account collection structure and types.
   */
  validateDecryptedVault(vaultData) {
    if (!vaultData || typeof vaultData !== 'object') return false;
    if (vaultData.schemaVersion !== 2) return false;
    if (!Array.isArray(vaultData.accounts)) return false;

    const MAX_ACCOUNTS = 50000;
    if (vaultData.accounts.length > MAX_ACCOUNTS) return false;

    const MAX_STR_LEN = 100000; // 100 KB max per field to prevent memory abuse
    for (const acc of vaultData.accounts) {
      if (!acc || typeof acc !== 'object') return false;
      if (typeof acc.id !== 'string' || !acc.id || acc.id.length > 200) return false;
      if (typeof acc.name !== 'string' || acc.name.length > MAX_STR_LEN) return false;
      if (typeof acc.username !== 'string' || acc.username.length > MAX_STR_LEN) return false;
      if (typeof acc.password !== 'string' || acc.password.length > MAX_STR_LEN) return false;
      if (typeof acc.category !== 'string' || acc.category.length > 200) return false;
      if (typeof acc.website !== 'string' || acc.website.length > MAX_STR_LEN) return false;
      if (typeof acc.notes !== 'string' || acc.notes.length > MAX_STR_LEN) return false;
      if (typeof acc.createdAt !== 'string' || acc.createdAt.length > 100) return false;
      if (typeof acc.updatedAt !== 'string' || acc.updatedAt.length > 100) return false;
    }

    return true;
  },

  /**
   * Returns true only if a structurally valid encrypted vault record exists
   */
  async hasVault() {
    const record = await this.loadVaultRecord();
    return this.validateVaultRecord(record);
  },

  /**
   * Load non-sensitive UI settings (Auto-lock preference, etc.)
   */
  async getSettings() {
    const DEFAULT_SETTINGS = { autoLockMinutes: 5 };
    if (isChromeStorageAvailable()) {
      return new Promise((resolve) => {
        chrome.storage.local.get([SETTINGS_KEY], (result) => {
          if (result && result[SETTINGS_KEY] && typeof result[SETTINGS_KEY] === 'object') {
            const minutes = result[SETTINGS_KEY].autoLockMinutes;
            const valid = [1, 5, 10, 15, 30, 60, 0].includes(minutes) ? minutes : 5;
            resolve({ autoLockMinutes: valid });
          } else {
            resolve(DEFAULT_SETTINGS);
          }
        });
      });
    }

    try {
      const stored = localStorage.getItem(SETTINGS_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        const minutes = parsed.autoLockMinutes;
        const valid = [1, 5, 10, 15, 30, 60, 0].includes(minutes) ? minutes : 5;
        return { autoLockMinutes: valid };
      }
    } catch (_) {}
    return DEFAULT_SETTINGS;
  },

  /**
   * Save non-sensitive UI settings (Auto-lock preference, etc.)
   */
  async saveSettings(settings) {
    if (!settings || typeof settings !== 'object') return;
    const sanitized = {
      autoLockMinutes: Number(settings.autoLockMinutes) ?? 5
    };
    if (isChromeStorageAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.storage.local.set({ [SETTINGS_KEY]: sanitized }, () => {
          if (chrome.runtime && chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve();
          }
        });
      });
    }

    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(sanitized));
    } catch (_) {}
  },

  /**
   * Load the encrypted vault record from storage
   * Returns parsed record object, null if not found, or throws on read failure
   */
  async loadVaultRecord() {
    if (isChromeStorageAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.storage.local.get([STORAGE_KEY, ...LEGACY_STORAGE_KEYS], (result) => {
          if (chrome.runtime && chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else if (result && Object.prototype.hasOwnProperty.call(result, STORAGE_KEY) && result[STORAGE_KEY] !== undefined) {
            resolve(result[STORAGE_KEY] ?? null);
          } else {
            // Check if any legacy record exists
            for (const legKey of LEGACY_STORAGE_KEYS) {
              if (result && Object.prototype.hasOwnProperty.call(result, legKey) && result[legKey] !== undefined) {
                resolve({ isLegacyIncompatible: true, legacyKey: legKey });
                return;
              }
            }
            resolve(null);
          }
        });
      });
    }

    // Fallback for non-extension browser testing environments
    let serialized;
    try {
      serialized = localStorage.getItem(STORAGE_KEY);
      if (serialized === null) {
        for (const legKey of LEGACY_STORAGE_KEYS) {
          if (localStorage.getItem(legKey) !== null) {
            return { isLegacyIncompatible: true, legacyKey: legKey };
          }
        }
        return null;
      }
    } catch (_) {
      throw new Error('Storage read error.');
    }

    try {
      return JSON.parse(serialized);
    } catch (_) {
      // Malformed JSON stored under the key -> return malformed indicator object so it's not treated as null
      return { isMalformed: true };
    }
  },

  /**
   * Save the encrypted vault record
   */
  async saveVaultRecord(record) {
    if (!this.validateVaultRecord(record)) {
      throw new Error('Refusing to persist malformed or incomplete encrypted vault record.');
    }

    if (isChromeStorageAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.storage.local.set({ [STORAGE_KEY]: record }, () => {
          if (chrome.runtime && chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve();
          }
        });
      });
    }

    // Fallback for non-extension browser preview
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    } catch (e) {
      throw new Error('Storage write failed.');
    }
  },

  /**
   * Destructively delete the encrypted vault record from storage
   */
  async deleteVault() {
    if (isChromeStorageAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.storage.local.remove([STORAGE_KEY], () => {
          if (chrome.runtime && chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve();
          }
        });
      });
    }

    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (_) {
      throw new Error('Storage delete error.');
    }
  }
};
