/**
 * Secure Vault - Background Service Worker (Manifest V3 - Stage 7 Security Hardened)
 *
 * Architecture Role:
 * - Extension lifecycle events
 * - Global keyboard shortcuts
 * - Background auto-lock alarm scheduler (Stage 6)
 * - System/screen lock detection via chrome.idle (Stage 6)
 * - Safe tab querying for extension views (Stage 7)
 *
 * SECURITY INVARIANTS:
 * - NEVER stores, accepts, or persists Master Password, Recovery Key, VEK, or credentials.
 * - NO raw-credential message paths accepted in background service worker.
 * - Single source of truth for in-page autofill resides strictly in ./scripts/autofill.js (invoked directly from UI).
 * - SENDER VALIDATION: Rejects all messages from external origins or untrusted senders.
 * - MESSAGE VALIDATION: Validates all incoming payloads before performing actions.
 * - Zero credential logging.
 */

const AUTO_LOCK_ALARM_NAME = 'secure-vault-auto-lock';

// Lifecycle: Installation event
chrome.runtime.onInstalled.addListener(() => {
  // Production initialization
});

// Command listener for keyboard shortcuts defined in manifest.json
chrome.commands.onCommand.addListener((command) => {
  if (command === 'open-vault') {
    chrome.tabs.create({
      url: chrome.runtime.getURL('pages/vault.html')
    });
  } else if (command === 'lock-vault') {
    // Broadcast LOCK_VAULT signal to all active extension views
    chrome.runtime.sendMessage({ type: 'LOCK_VAULT' }).catch(() => {});
  }
});

// Stage 6: Background Alarms for Auto-Lock
if (typeof chrome !== 'undefined' && chrome.alarms) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === AUTO_LOCK_ALARM_NAME) {
      // Broadcast AUTO_LOCK signal to all active extension pages
      chrome.runtime.sendMessage({ type: 'AUTO_LOCK' }).catch(() => {
        // Safe to ignore when no extension views are open
      });
    }
  });
}

// Stage 6: System / Screen Lock Detection via chrome.idle
if (typeof chrome !== 'undefined' && chrome.idle && chrome.idle.onStateChanged) {
  chrome.idle.onStateChanged.addListener((newState) => {
    if (newState === 'locked') {
      // Broadcast SYSTEM_LOCK signal to all active extension pages
      chrome.runtime.sendMessage({ type: 'SYSTEM_LOCK' }).catch(() => {
        // Safe to ignore when no extension views are open
      });
    }
  });
}

// Stage 6 & 7: Hardened Message Listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') return false;

  // Requirement 12: Sender Validation (Reject non-extension senders)
  if (!sender || sender.id !== chrome.runtime.id) {
    if (sendResponse) sendResponse({ ok: false, error: 'Unauthorized sender' });
    return false;
  }

  // Reject messages from unexpected origins
  if (sender.url && !sender.url.startsWith(`chrome-extension://${chrome.runtime.id}/`)) {
    if (sendResponse) sendResponse({ ok: false, error: 'Unauthorized sender origin' });
    return false;
  }

  // 1. Schedule Auto-Lock
  if (message.type === 'SCHEDULE_AUTO_LOCK') {
    if (typeof chrome !== 'undefined' && chrome.alarms && typeof message.deadline === 'number') {
      const now = Date.now();
      const delayMs = Math.max(message.deadline - now, 30000); // Minimum 30s for Chrome alarms
      chrome.alarms.create(AUTO_LOCK_ALARM_NAME, {
        when: now + delayMs
      });
    }
    if (sendResponse) sendResponse({ ok: true });
    return true;
  }

  // 2. Clear Auto-Lock
  if (message.type === 'CLEAR_AUTO_LOCK') {
    if (typeof chrome !== 'undefined' && chrome.alarms) {
      chrome.alarms.clear(AUTO_LOCK_ALARM_NAME).catch(() => {});
    }
    if (sendResponse) sendResponse({ ok: true });
    return true;
  }

  // 3. Query Active Tab Info Safely
  if (message.type === 'GET_ACTIVE_TAB') {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
        if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
          sendResponse({ ok: false, error: 'No active tab found' });
          return;
        }
        const activeTab = tabs[0];
        sendResponse({
          ok: true,
          tab: {
            id: activeTab.id,
            url: activeTab.url || '',
            title: activeTab.title || '',
            favIconUrl: activeTab.favIconUrl || ''
          }
        });
      });
      return true; // Keep channel open for async response
    }
    sendResponse({ ok: false, error: 'Tabs API unavailable' });
    return true;
  }
});
