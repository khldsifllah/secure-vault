/**
 * Secure Vault - Cryptographically Secure Password Generator Module (Stage 5)
 *
 * Implements random password generation using the browser's native Web Crypto API:
 * globalThis.crypto.getRandomValues() (CSPRNG).
 *
 * ZERO Math.random() usage.
 * ZERO deterministic seeds or timestamps.
 * Unbiased character selection via rejection sampling.
 * Cryptographic Fisher-Yates shuffling.
 */

export const LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz';
export const UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const NUMBER_CHARS = '0123456789';
export const SYMBOL_CHARS = '!@#$%^&*()-_=+[]{};:,.?';

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;
export const DEFAULT_PASSWORD_LENGTH = 20;

/**
 * Validate generator options and return normalized options object.
 * Throws clean error message if validation fails.
 *
 * @param {Object} options
 * @returns {{ length: number, useUppercase: boolean, useLowercase: boolean, useNumbers: boolean, useSymbols: boolean }}
 */
export function validateGeneratorOptions(options = {}) {
  const rawLength = options.length ?? DEFAULT_PASSWORD_LENGTH;
  const length = Number(rawLength);

  if (!Number.isInteger(length) || length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new Error('Password length must be between 8 and 128 characters.');
  }

  const useUppercase = options.useUppercase ?? options.uppercase ?? true;
  const useLowercase = options.useLowercase ?? options.lowercase ?? true;
  const useNumbers = options.useNumbers ?? options.numbers ?? true;
  const useSymbols = options.useSymbols ?? options.symbols ?? true;

  if (!useUppercase && !useLowercase && !useNumbers && !useSymbols) {
    throw new Error('Select at least one character type.');
  }

  return {
    length,
    useUppercase: Boolean(useUppercase),
    useLowercase: Boolean(useLowercase),
    useNumbers: Boolean(useNumbers),
    useSymbols: Boolean(useSymbols)
  };
}

/**
 * Get the list of active character set objects based on validated options.
 *
 * @param {Object} validatedOptions
 * @returns {Array<{ name: string, chars: string }>}
 */
export function getSelectedCharacterSets(validatedOptions) {
  const sets = [];
  if (validatedOptions.useLowercase) {
    sets.push({ name: 'lowercase', chars: LOWERCASE_CHARS });
  }
  if (validatedOptions.useUppercase) {
    sets.push({ name: 'uppercase', chars: UPPERCASE_CHARS });
  }
  if (validatedOptions.useNumbers) {
    sets.push({ name: 'numbers', chars: NUMBER_CHARS });
  }
  if (validatedOptions.useSymbols) {
    sets.push({ name: 'symbols', chars: SYMBOL_CHARS });
  }
  return sets;
}

/**
 * Generate an unbiased random unsigned integer in the range [0, max - 1]
 * using globalThis.crypto.getRandomValues() and rejection sampling.
 *
 * Avoids modulo reduction bias by rejecting values in the incomplete upper range:
 * limit = 2^32 - (2^32 % max)
 *
 * @param {number} max - Upper bound (exclusive). Must be a positive integer.
 * @returns {number} Random integer in range [0, max - 1]
 */
export function secureRandomIndex(max) {
  if (!Number.isInteger(max) || max <= 0) {
    throw new Error('Max must be a positive integer.');
  }
  if (max === 1) return 0;

  const buffer = new Uint32Array(1);
  const maxUint32 = 0x100000000; // 2^32 = 4294967296
  const limit = maxUint32 - (maxUint32 % max);

  let rand;
  do {
    globalThis.crypto.getRandomValues(buffer);
    rand = buffer[0];
  } while (rand >= limit);

  return rand % max;
}

/**
 * Alias for secureRandomIndex.
 *
 * @param {number} max
 * @returns {number}
 */
export function secureRandomInt(max) {
  return secureRandomIndex(max);
}

/**
 * In-place cryptographically secure Fisher-Yates shuffle.
 * Uses globalThis.crypto.getRandomValues() via secureRandomIndex().
 *
 * @param {Array} array
 * @returns {Array} Shuffled array
 */
export function secureShuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = secureRandomIndex(i + 1);
    const temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
  return array;
}

/**
 * Generate a cryptographically secure random password.
 * Guarantees at least ONE character from every selected category,
 * fills remaining length from the combined pool, and shuffles securely.
 *
 * @param {Object} options
 * @returns {string} Generated password
 */
export function generatePassword(options = {}) {
  const opts = validateGeneratorOptions(options);
  const selectedSets = getSelectedCharacterSets(opts);

  const passwordChars = [];

  // 1. Guarantee at least one character from EVERY selected character set
  for (const set of selectedSets) {
    const idx = secureRandomIndex(set.chars.length);
    passwordChars.push(set.chars[idx]);
  }

  // 2. Build the combined character pool from all selected sets
  let combinedPool = '';
  for (const set of selectedSets) {
    combinedPool += set.chars;
  }

  // 3. Fill the remaining positions up to requested length from combined pool
  const remainingCount = opts.length - passwordChars.length;
  for (let i = 0; i < remainingCount; i++) {
    const idx = secureRandomIndex(combinedPool.length);
    passwordChars.push(combinedPool[idx]);
  }

  // 4. Cryptographically secure Fisher-Yates shuffle
  secureShuffle(passwordChars);

  return passwordChars.join('');
}

/**
 * Compatibility wrapper object.
 */
export const PasswordGenerator = {
  generate: generatePassword,
  validate: validateGeneratorOptions,
  secureRandomInt,
  secureRandomIndex,
  secureShuffle,
  getSelectedCharacterSets,
  defaultOptions: {
    length: DEFAULT_PASSWORD_LENGTH,
    useUppercase: true,
    useLowercase: true,
    useNumbers: true,
    useSymbols: true
  }
};
