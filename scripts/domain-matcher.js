/**
 * Secure Vault - Domain & Website Matching Engine (Manifest V3 - Stage 7 Security Hardened)
 *
 * Architecture Role:
 * - Strict, conservative domain extraction and normalization
 * - eTLD+1 base domain identification without unsafe wildcard fallbacks
 * - Explicit, narrow subdomain/service equivalence (telegram.org <-> web.telegram.org)
 * - SOLE AUTHORITY for website matching: account.website field.
 *
 * SECURITY INVARIANTS:
 * - NO broad cross-service aliases (google.com does NOT match youtube.com; gmail.com does NOT match youtube.com).
 * - NO account name -> domain matching (never cleanName.includes(...) or targetBaseName.includes(...)).
 * - NO category -> domain matching (category "Gmail" never matches arbitrary Google properties).
 * - NO includes() on hostnames (prevents phishing/subdomain injection: evil-example.com, fakefacebook.com, facebook.com.attacker.com).
 * - NO generic base-domain fallback across distinct sibling subdomains (foo.example.com does NOT match bar.example.com).
 * - False-negative matching is strictly preferred over false-positive matching.
 */

// Common compound public suffixes (eTLD+1 support)
const COMPOUND_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp',
  'co.kr', 'ne.kr',
  'com.br', 'org.br',
  'com.mx', 'org.mx',
  'com.tr', 'edu.tr',
  'com.sg', 'edu.sg',
  'co.za', 'org.za',
  'com.tw', 'org.tw'
]);

// Explicit, conservative equivalent subdomain pairs ONLY (Requirement 1 & 18)
const EXPLICIT_EQUIVALENTS = [
  ['telegram.org', 'web.telegram.org'],
  ['github.com', 'gist.github.com']
];

/**
 * Normalizes an input string or URL into a clean lowercase hostname.
 * Strips protocol, port, path, query parameters, hash, and trailing dots.
 *
 * @param {string} input
 * @returns {string} Lowercase hostname or empty string if invalid
 */
export function extractHostname(input) {
  if (!input || typeof input !== 'string') return '';
  const trimmed = input.trim();
  if (!trimmed) return '';

  let hostname = '';
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed);
    const url = new URL(hasScheme ? trimmed : `https://${trimmed}`);
    hostname = url.hostname.toLowerCase();
  } catch (_) {
    hostname = trimmed.split('/')[0].split(':')[0].toLowerCase();
  }

  // Remove trailing dots
  hostname = hostname.replace(/\.+$/, '');

  // Reject malformed hostnames containing spaces or invalid chars
  if (/[^a-z0-9.-]/.test(hostname) || hostname.length === 0) {
    return '';
  }

  return hostname;
}

/**
 * Strips standard 'www.' or 'm.' prefix for mobile/web prefix normalization.
 *
 * @param {string} hostname
 * @returns {string}
 */
export function stripHostPrefix(hostname) {
  if (!hostname || typeof hostname !== 'string') return '';
  if (hostname.startsWith('www.')) return hostname.slice(4);
  if (hostname.startsWith('m.')) return hostname.slice(2);
  return hostname;
}

/**
 * Checks whether a hostname represents a registered base domain (eTLD+1).
 *
 * @param {string} hostname
 * @returns {boolean}
 */
export function isBaseDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const parts = hostname.split('.');
  if (parts.length <= 1) return false;
  if (parts.length === 2) return true;

  // Check if compound TLD (e.g. example.co.uk has 3 parts)
  const lastTwo = parts.slice(-2).join('.');
  if (COMPOUND_TLDS.has(lastTwo)) {
    return parts.length === 3;
  }

  return false;
}

/**
 * Extracts the base domain (eTLD+1) from a hostname.
 *
 * @param {string} hostname
 * @returns {string} Base domain or original clean hostname
 */
export function getBaseDomain(hostname) {
  const clean = extractHostname(hostname);
  if (!clean) return '';

  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (COMPOUND_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}

/**
 * Checks whether two hostnames match under strict, conservative security rules.
 *
 * RULES:
 * 1. Normalized exact equality (www.facebook.com === facebook.com; m.facebook.com === facebook.com).
 * 2. Explicitly documented equivalent pairs ONLY (e.g. telegram.org <-> web.telegram.org).
 * 3. If stored site is a base domain (e.g. example.com), legitimate subdomains (sub.example.com) match
 *    using strict dot-boundary check (normCurrent.endsWith('.' + normStored)).
 * 4. Sibling subdomains (foo.example.com vs bar.example.com) MUST NOT MATCH.
 * 5. Prefix/suffix spoofing (facebook.com.attacker.com, fakefacebook.com, evil-example.com) MUST NOT MATCH.
 * 6. Cross-service domains (google.com vs youtube.com, microsoft.com vs outlook.com) MUST NOT MATCH.
 *
 * @param {string} storedSite - Account's stored website field
 * @param {string} currentSite - Active webpage URL or hostname
 * @returns {boolean}
 */
export function isDomainMatch(storedSite, currentSite) {
  const hostStored = extractHostname(storedSite);
  const hostCurrent = extractHostname(currentSite);

  if (!hostStored || !hostCurrent) {
    return false;
  }

  const normStored = stripHostPrefix(hostStored);
  const normCurrent = stripHostPrefix(hostCurrent);

  // 1. Exact normalized host equality (covers facebook.com <-> www.facebook.com, m.facebook.com)
  if (normStored === normCurrent) {
    return true;
  }

  // 2. Explicit supported equivalents (telegram.org <-> web.telegram.org)
  for (const [a, b] of EXPLICIT_EQUIVALENTS) {
    if ((normStored === a && normCurrent === b) || (normStored === b && normCurrent === a)) {
      return true;
    }
  }

  // 3. Subdomain of stored base domain (Requirement 4):
  // ONLY if stored host is verified to be a base domain (e.g. "example.com", NOT "foo.example.com")
  // and current host strictly ends with "." + stored host.
  if (isBaseDomain(normStored)) {
    if (normCurrent.endsWith(`.${normStored}`)) {
      return true;
    }
  }

  // All other cases (sibling subdomains, cross-services, prefix spoofs) FAIL safely
  return false;
}

/**
 * Scores how well an account matches a target webpage URL or hostname.
 *
 * CRITICAL SECURITY INVARIANT (Requirement 2):
 * - Stored website is the SOLE authority.
 * - Account name is NEVER used for domain matching.
 * - Category is NEVER used for domain matching.
 *
 * @param {Object} account - Stored decrypted account object
 * @param {string} targetUrl - Current tab URL or hostname
 * @returns {{ isMatch: boolean, score: number, reason: string }}
 */
export function scoreAccountMatch(account, targetUrl) {
  if (!account || typeof account !== 'object' || !targetUrl) {
    return { isMatch: false, score: 0, reason: '' };
  }

  // Account website is the SOLE authority
  if (!account.website || typeof account.website !== 'string' || !account.website.trim()) {
    return { isMatch: false, score: 0, reason: '' };
  }

  const match = isDomainMatch(account.website, targetUrl);
  if (match) {
    return {
      isMatch: true,
      score: 100,
      reason: 'Website match'
    };
  }

  return { isMatch: false, score: 0, reason: '' };
}

/**
 * Finds all accounts matching the given target URL.
 *
 * @param {Array<Object>} accounts - List of decrypted accounts
 * @param {string} targetUrl - URL of active tab
 * @returns {Array<Object>} Matched accounts sorted by recently updated
 */
export function findMatchingAccounts(accounts, targetUrl) {
  if (!Array.isArray(accounts) || !targetUrl) return [];

  const results = [];

  for (const account of accounts) {
    const match = scoreAccountMatch(account, targetUrl);
    if (match.isMatch) {
      results.push({
        ...account,
        _matchScore: match.score,
        _matchReason: match.reason
      });
    }
  }

  // Stable sort by recently updated, then name
  results.sort((a, b) => {
    const timeA = new Date(a.updatedAt || a.createdAt || 0).getTime();
    const timeB = new Date(b.updatedAt || b.createdAt || 0).getTime();
    if (timeB !== timeA) return timeB - timeA;
    return (a.name || '').localeCompare(b.name || '');
  });

  return results;
}
