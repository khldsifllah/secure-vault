/**
 * Secure Vault - User-Triggered Autofill Engine (Manifest V3 - Stage 7 Security Hardened)
 *
 * Architecture Role:
 * - Single source of truth for in-page login form field discovery and value assignment
 * - Bypasses framework synthetic value caching via native HTMLInputElement.prototype descriptors
 * - Emits standard input, change, and blur DOM events
 * - Conservative field discovery (no generic text-field fallback)
 * - Strict password field constraints (strictly input[type="password"])
 *
 * SECURITY INVARIANTS:
 * - STRICTLY USER-TRIGGERED. Never executes automatically on tab load or navigation.
 * - NO auto-submit (no form.submit, no button clicks, no Enter key simulation).
 * - NEVER fills textarea, contenteditable, search fields, comments, or chat boxes.
 * - NEVER stores or persists credentials in webpage storage (no localStorage, sessionStorage, cookies, window.name).
 */

/**
 * Single source of truth for in-page field discovery and credential assignment.
 * Executed in the context of the target webpage via chrome.scripting.executeScript.
 *
 * @param {{ username?: string, password?: string }} credentials
 * @returns {{ success: boolean, filled: 'both'|'username'|'password'|'none', usernameFilled: boolean, passwordFilled: boolean, message: string }}
 */
export function executeAutofillInPage(credentials) {
  const { username = '', password = '' } = credentials || {};

  /**
   * Checks whether an element is truly visible and rendered on screen.
   */
  function isVisible(el) {
    if (!el || el.type === 'hidden') return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  }

  /**
   * Rejects non-login fields (textarea, contenteditable, search, comments, chats).
   */
  function isExcludedField(el) {
    if (!el || el.tagName === 'TEXTAREA' || el.isContentEditable) return true;

    const type = (el.getAttribute('type') || 'text').toLowerCase();
    // Forbid non-text inputs
    if (['search', 'tel', 'checkbox', 'radio', 'file', 'hidden', 'submit', 'button', 'reset', 'color', 'date', 'range', 'number'].includes(type)) {
      return true;
    }

    const name = (el.getAttribute('name') || '').toLowerCase();
    const id = (el.getAttribute('id') || '').toLowerCase();
    const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();
    const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
    const role = (el.getAttribute('role') || '').toLowerCase();

    if (role === 'search' || role === 'searchbox') return true;

    // Strict blocklist for non-credential inputs
    const excludedKeywords = [
      'search', 'find', 'query', 'filter', 'comment',
      'chat', 'message', 'reply', 'post', 'feed', 'tweet', 'status', 'q'
    ];
    for (const kw of excludedKeywords) {
      if (name === kw || id === kw) return true;
      if (name.includes(kw) || id.includes(kw) || placeholder.includes(kw) || ariaLabel.includes(kw)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Safely set an input's value using native descriptors and dispatch events.
   * STRICTLY NO FORM SUBMIT (Requirement 10).
   */
  function setInputValue(input, value) {
    if (!input) return false;

    try {
      input.focus();

      // Bypass framework synthetic state overriding
      const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
      if (nativeSetter) {
        nativeSetter.call(input, value);
      } else {
        input.value = value;
      }

      // Dispatch standard DOM events
      input.dispatchEvent(new Event('input', { bubbles: true, cancelable: true, composed: true }));
      input.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
      input.dispatchEvent(new Event('blur', { bubbles: true, cancelable: true }));

      // Subtle visual outline to confirm autofill without changing layout
      const originalOutline = input.style.outline;
      const originalTransition = input.style.transition;
      input.style.transition = 'outline 0.2s ease';
      input.style.outline = '2px solid #3b82f6';
      setTimeout(() => {
        input.style.outline = originalOutline;
        input.style.transition = originalTransition;
      }, 800);

      return true;
    } catch (_) {
      try {
        input.value = value;
        return true;
      } catch (e) {
        return false;
      }
    }
  }

  // 1. STRICT PASSWORD FIELD DISCOVERY (Requirement 9)
  // ONLY input[type="password"]! Never put passwords into text, email, search, or textareas.
  const passwordInputs = Array.from(
    document.querySelectorAll('input[type="password"]')
  ).filter((el) => isVisible(el) && !isExcludedField(el));

  const targetPasswordInput = passwordInputs[0] || null;

  // 2. CONSERVATIVE USERNAME / EMAIL DISCOVERY (Requirement 8)
  let targetUsernameInput = null;

  // Priority 1: autocomplete="username"
  const acUser = Array.from(
    document.querySelectorAll('input[autocomplete="username" i]')
  ).filter((el) => isVisible(el) && !isExcludedField(el) && el.type !== 'password');
  if (acUser.length > 0) {
    targetUsernameInput = acUser[0];
  }

  // Priority 2: autocomplete="email"
  if (!targetUsernameInput) {
    const acEmail = Array.from(
      document.querySelectorAll('input[autocomplete="email" i]')
    ).filter((el) => isVisible(el) && !isExcludedField(el) && el.type !== 'password');
    if (acEmail.length > 0) {
      targetUsernameInput = acEmail[0];
    }
  }

  // Priority 3: input[type="email"]
  if (!targetUsernameInput) {
    const emailInputs = Array.from(
      document.querySelectorAll('input[type="email"]')
    ).filter((el) => isVisible(el) && !isExcludedField(el));
    if (emailInputs.length > 0) {
      targetUsernameInput = emailInputs[0];
    }
  }

  // Priority 4: Strong semantic name/id (username, user, login, email)
  if (!targetUsernameInput) {
    const semanticRegex = /(^|_|-)(username|user|login|email)(_|-|$)/i;
    const candidates = Array.from(
      document.querySelectorAll('input[type="text"], input:not([type])')
    ).filter((el) => isVisible(el) && !isExcludedField(el));

    const matchedSemantic = candidates.find((el) => {
      const name = el.getAttribute('name') || '';
      const id = el.getAttribute('id') || '';
      return semanticRegex.test(name) || semanticRegex.test(id);
    });

    if (matchedSemantic) {
      targetUsernameInput = matchedSemantic;
    }
  }

  // Priority 5: Single text input inside the same form as the password input
  if (!targetUsernameInput && targetPasswordInput) {
    const form = targetPasswordInput.closest('form');
    if (form) {
      const formTextInputs = Array.from(
        form.querySelectorAll('input[type="text"], input:not([type])')
      ).filter((el) => isVisible(el) && !isExcludedField(el));

      // Only match if there is exactly ONE non-password text input in the login form
      if (formTextInputs.length === 1) {
        targetUsernameInput = formTextInputs[0];
      }
    }
  }

  // CRITICAL REQUIREMENT 8: DO NOT fill arbitrary visible text fields!
  // If no high-confidence field found, targetUsernameInput stays null.

  // 3. EXECUTE SAFE FILL
  let filledUsername = false;
  let filledPassword = false;

  if (targetUsernameInput && username) {
    filledUsername = setInputValue(targetUsernameInput, username);
  }

  if (targetPasswordInput && password) {
    filledPassword = setInputValue(targetPasswordInput, password);
  }

  // 4. PRECISE RESULT REPORTING
  if (filledUsername && filledPassword) {
    return {
      success: true,
      filled: 'both',
      usernameFilled: true,
      passwordFilled: true,
      message: 'Username and password autofilled.'
    };
  }

  if (filledUsername && !filledPassword) {
    return {
      success: true,
      filled: 'username',
      usernameFilled: true,
      passwordFilled: false,
      message: targetPasswordInput ? 'Filled username only.' : 'Username autofilled. (Password field not found).'
    };
  }

  if (filledPassword && !filledUsername) {
    return {
      success: true,
      filled: 'password',
      usernameFilled: false,
      passwordFilled: true,
      message: username ? "Couldn’t identify the username field. Password autofilled." : 'Password autofilled.'
    };
  }

  // Neither filled
  if (username && !targetUsernameInput && password && !targetPasswordInput) {
    return {
      success: false,
      filled: 'none',
      usernameFilled: false,
      passwordFilled: false,
      message: 'No compatible login fields found on this page.'
    };
  }

  if (username && !targetUsernameInput) {
    return {
      success: false,
      filled: 'none',
      usernameFilled: false,
      passwordFilled: false,
      message: "Couldn’t identify the username field."
    };
  }

  return {
    success: false,
    filled: 'none',
    usernameFilled: false,
    passwordFilled: false,
    message: 'Could not fill credentials.'
  };
}

/**
 * Triggers user-initiated autofill into a target tab via chrome.scripting.
 *
 * @param {number} tabId - Target tab ID
 * @param {string} tabUrl - Target tab URL
 * @param {{ username: string, password: string }} credentials
 * @returns {Promise<{ success: boolean, message: string, filled?: string }>}
 */
export async function triggerTabAutofill(tabId, tabUrl, credentials) {
  if (!credentials) {
    return { success: false, message: 'No credentials provided for autofill.' };
  }

  // Disallow restricted browser internal schemes
  if (!tabUrl || (!tabUrl.startsWith('http://') && !tabUrl.startsWith('https://'))) {
    return {
      success: false,
      message: 'Cannot autofill browser internal or system pages.'
    };
  }

  if (typeof chrome === 'undefined' || !chrome.scripting || !chrome.scripting.executeScript) {
    return {
      success: true,
      message: 'Autofill simulated in workbench.'
    };
  }

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: executeAutofillInPage,
      args: [{ username: credentials.username || '', password: credentials.password || '' }]
    });

    if (results && results[0] && results[0].result) {
      return results[0].result;
    }

    return { success: true, message: 'Autofill injected successfully.' };
  } catch (err) {
    return {
      success: false,
      message: `Autofill failed: ${err.message || 'Script injection error'}`
    };
  }
}
