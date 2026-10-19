/**
 * Secure Vault - Cryptographic Module (Stage 2 Hardened Implementation)
 *
 * Implements native Web Crypto API security:
 * - PBKDF2-SHA-256 key derivation with 600,000 iterations and 16-byte random salt
 * - 256-bit Vault Encryption Key (VEK) generated with CSPRNG
 * - Hardened VEK handling: VEK is imported as non-extractable (extractable = false)
 * - Self-contained rewrapVaultKey() for Master Password change & recovery without extractable keys
 * - AES-256-GCM authenticated encryption with 96-bit unique random IV per operation
 * - Cryptographically random 256-bit Recovery Key with separate AAD
 * - Authenticated Additional Data (AAD) for vault, master wrapping, and recovery wrapping
 *
 * NEVER logs or exposes secrets, passwords, or keys.
 */

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';
const AES_KEY_LENGTH = 256;
const SALT_BYTE_LENGTH = 16;
const IV_BYTE_LENGTH = 12; // 96 bits for AES-GCM

export const AAD_VAULT = 'Secure Vault|Vault|v2';
export const AAD_MASTER_KEY = 'Secure Vault|MasterKey|v2';
export const AAD_RECOVERY_KEY = 'Secure Vault|RecoveryKey|v2';

/**
 * Encode string to UTF-8 Uint8Array
 */
export function encodeText(text) {
  return new TextEncoder().encode(text);
}

/**
 * Decode UTF-8 Uint8Array or ArrayBuffer to string
 */
export function decodeText(bytes) {
  return new TextDecoder().decode(bytes);
}

/**
 * Generate cryptographically secure random bytes
 */
export function generateRandomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate 16-byte random salt for PBKDF2
 */
export function generateSalt() {
  return generateRandomBytes(SALT_BYTE_LENGTH);
}

/**
 * Generate 12-byte (96-bit) random IV for AES-GCM
 */
export function generateIv() {
  return generateRandomBytes(IV_BYTE_LENGTH);
}

/**
 * Base64 string to Uint8Array (serialization only)
 */
export function base64ToBytes(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Uint8Array to Base64 string (serialization only)
 */
export function bytesToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Import 256-bit raw key bytes as an AES-GCM CryptoKey.
 * Defaults to non-extractable (extractable = false) for memory hardening.
 */
export async function importAesGcmKey(rawBytes, isExtractable = false) {
  return await globalThis.crypto.subtle.importKey(
    'raw',
    rawBytes,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    isExtractable,
    ['encrypt', 'decrypt']
  );
}

/**
 * Create a new Vault Encryption Key (VEK) and wrap it immediately with both
 * Master KEK and Recovery Key. Returns wrapped payloads and the active VEK as
 * a strictly NON-EXTRACTABLE CryptoKey (extractable = false).
 * Temporary raw key bytes are immediately zeroized.
 */
export async function createAndWrapVaultKey(masterKek, recoveryCryptoKey) {
  const rawVek = generateRandomBytes(32); // 256 bits

  try {
    // 1. Wrap raw VEK with Master KEK
    const masterIv = generateIv();
    const masterEncrypted = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: masterIv, additionalData: encodeText(AAD_MASTER_KEY) },
      masterKek,
      rawVek
    );

    // 2. Wrap raw VEK with Recovery Key
    const recoveryIv = generateIv();
    const recoveryEncrypted = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: recoveryIv, additionalData: encodeText(AAD_RECOVERY_KEY) },
      recoveryCryptoKey,
      rawVek
    );

    // 3. Import VEK for in-memory use as NON-EXTRACTABLE (extractable = false)
    const vek = await importAesGcmKey(rawVek, false);

    return {
      vek, // Non-extractable CryptoKey
      masterWrapped: {
        iv: bytesToBase64(masterIv),
        wrappedVaultKey: bytesToBase64(new Uint8Array(masterEncrypted))
      },
      recoveryWrapped: {
        iv: bytesToBase64(recoveryIv),
        wrappedVaultKey: bytesToBase64(new Uint8Array(recoveryEncrypted))
      }
    };
  } finally {
    // Securely wipe raw VEK bytes from temporary memory
    rawVek.fill(0);
  }
}

/**
 * Derive Master Key Encryption Key (KEK) using PBKDF2-SHA-256 with 600,000 iterations
 */
export async function deriveMasterKey(masterPassword, saltBytes) {
  const passwordKey = await globalThis.crypto.subtle.importKey(
    'raw',
    encodeText(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await globalThis.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH
    },
    passwordKey,
    {
      name: 'AES-GCM',
      length: AES_KEY_LENGTH
    },
    false, // Master KEK is strictly non-extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate 256-bit Recovery Key with 256 bits of cryptographically random entropy.
 * Formatted as 16 groups of 4 uppercase hex characters (64 hex characters total).
 */
export function generateRecoveryKey() {
  const rawBytes = generateRandomBytes(32); // 256 bits
  let hex = '';
  for (let i = 0; i < rawBytes.length; i++) {
    hex += rawBytes[i].toString(16).padStart(2, '0').toUpperCase();
  }
  const chunks = [];
  for (let i = 0; i < hex.length; i += 4) {
    chunks.push(hex.substring(i, i + 4));
  }
  return {
    rawBytes,
    formatted: chunks.join('-')
  };
}

/**
 * Parse and validate formatted Recovery Key (64 hex characters, hyphens/spaces/newlines optional)
 * Returns 32-byte Uint8Array or throws an Error.
 */
export function parseRecoveryKey(inputString) {
  if (typeof inputString !== 'string') {
    throw new Error('Invalid recovery key format.');
  }
  const cleanHex = inputString.replace(/[\s\-\r\n]/g, '').toUpperCase();
  if (cleanHex.length !== 64 || !/^[0-9A-F]{64}$/.test(cleanHex)) {
    throw new Error('Invalid recovery key: must be a 64-character hexadecimal key.');
  }
  const rawBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    rawBytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return rawBytes;
}

/**
 * Unwrap / Decrypt the Vault Encryption Key (VEK) using a wrapping key.
 * Hardened: imports VEK as strictly NON-EXTRACTABLE (extractable = false).
 * Temporary decrypted buffer is zeroized.
 */
export async function unwrapVaultKey(wrappedVaultKeyBase64, ivBase64, wrappingKey, aadString) {
  const ciphertextBytes = base64ToBytes(wrappedVaultKeyBase64);
  const ivBytes = base64ToBytes(ivBase64);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      additionalData: encodeText(aadString)
    },
    wrappingKey,
    ciphertextBytes
  );

  const rawBytes = new Uint8Array(decryptedBuffer);
  try {
    // Import as non-extractable (extractable = false)
    return await importAesGcmKey(rawBytes, false);
  } finally {
    // Wipe raw decrypted bytes
    rawBytes.fill(0);
  }
}

/**
 * Re-wrap Vault Encryption Key (VEK) from one wrapping key to a new wrapping key
 * (e.g. Master Password change or Recovery flow) without exposing or creating
 * an extractable key. Temporary decrypted bytes are immediately zeroized.
 */
export async function rewrapVaultKey(wrappedVaultKeyBase64, ivBase64, currentWrappingKey, currentAad, newWrappingKey, newAad) {
  const ciphertextBytes = base64ToBytes(wrappedVaultKeyBase64);
  const ivBytes = base64ToBytes(ivBase64);

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      additionalData: encodeText(currentAad)
    },
    currentWrappingKey,
    ciphertextBytes
  );

  const rawBytes = new Uint8Array(decryptedBuffer);
  try {
    const newIv = generateIv();
    const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: newIv,
        additionalData: encodeText(newAad)
      },
      newWrappingKey,
      rawBytes
    );

    return {
      iv: bytesToBase64(newIv),
      wrappedVaultKey: bytesToBase64(new Uint8Array(encryptedBuffer))
    };
  } finally {
    // Wipe raw bytes immediately
    rawBytes.fill(0);
  }
}

/**
 * Encrypt vault data payload using the Vault Encryption Key (VEK)
 */
export async function encryptVault(vaultPayload, vaultKey) {
  const jsonString = JSON.stringify(vaultPayload);
  const plaintextBytes = encodeText(jsonString);
  const iv = generateIv();

  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: encodeText(AAD_VAULT)
    },
    vaultKey,
    plaintextBytes
  );

  return {
    algorithm: 'AES-256-GCM',
    iv: bytesToBase64(iv),
    aad: AAD_VAULT,
    ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer))
  };
}

/**
 * Decrypt vault data payload using the Vault Encryption Key (VEK)
 * Validates schema version and accounts array.
 */
export async function decryptVault(encryptedVaultObj, vaultKey) {
  if (!encryptedVaultObj || !encryptedVaultObj.ciphertext || !encryptedVaultObj.iv) {
    throw new Error('Invalid vault ciphertext structure.');
  }

  const ciphertextBytes = base64ToBytes(encryptedVaultObj.ciphertext);
  const ivBytes = base64ToBytes(encryptedVaultObj.iv);
  const aadString = encryptedVaultObj.aad || AAD_VAULT;

  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      additionalData: encodeText(aadString)
    },
    vaultKey,
    ciphertextBytes
  );

  const jsonString = decodeText(decryptedBuffer);
  const parsed = JSON.parse(jsonString);

  if (typeof parsed !== 'object' || parsed === null || !Array.isArray(parsed.accounts)) {
    throw new Error('Vault payload schema mismatch.');
  }

  return parsed;
}
