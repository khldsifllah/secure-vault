/**
 * Secure Vault - Popup Controller (Manifest V3 - Stage 7)
 *
 * Architecture Role:
 * - Detects active tab URL and domain
 * - Matches active website against decrypted accounts using domain-matcher.js
 * - Performs user-triggered form autofill via script injection into active tab
 * - Provides ephemeral in-memory unlock for quick autofill without persistent state
 * - Provides 1-click credential copying with 30s clipboard auto-clear
 *
 * SECURITY INVARIANT:
 * - Cryptographic operations use native Web Crypto API (PBKDF2-SHA-256 + AES-256-GCM).
 * - Decrypted data and VEK reside strictly in volatile memory.
 * - Zero telemetry, zero external APIs, zero disk writes for plaintext credentials.
 * - Autofill is strictly user-triggered (never automatic).
 */

import { StorageModule } from './scripts/storage.js';
import {
  deriveMasterKey,
  unwrapVaultKey,
  decryptVault,
  base64ToBytes,
  AAD_MASTER_KEY
} from './scripts/crypto.js';
import {
  extractHostname,
  isDomainMatch,
  findMatchingAccounts
} from './scripts/domain-matcher.js';
import { triggerTabAutofill } from './scripts/autofill.js';

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements - Shell
  const htmlRoot = document.documentElement;
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeIconDark = document.getElementById('themeIconDark');
  const themeIconLight = document.getElementById('themeIconLight');
  const openVaultPageBtn = document.getElementById('openVaultPageBtn');
  const popupLockBtn = document.getElementById('popupLockBtn');
  const siteNameDisplay = document.getElementById('siteNameDisplay');
  const siteMatchCount = document.getElementById('siteMatchCount');
  const popupNotice = document.getElementById('popupNotice');
  const popupNoticeText = document.getElementById('popupNoticeText');

  // DOM Elements - Views
  const popupSetupView = document.getElementById('popupSetupView');
  const popupLockedView = document.getElementById('popupLockedView');
  const popupUnlockedView = document.getElementById('popupUnlockedView');
  const setupVaultBtn = document.getElementById('setupVaultBtn');
  const launchVaultBtn = document.getElementById('launchVaultBtn');
  const popupUnlockForm = document.getElementById('popupUnlockForm');
  const popupMasterPasswordInput = document.getElementById('popupMasterPasswordInput');
  const popupSubmitUnlockBtn = document.getElementById('popupSubmitUnlockBtn');

  // DOM Elements - Unlocked View
  const popupSearchInput = document.getElementById('popupSearchInput');
  const matchedAccountsList = document.getElementById('matchedAccountsList');
  const noMatchesNotice = document.getElementById('noMatchesNotice');
  const noMatchesDesc = document.getElementById('noMatchesDesc');
  const addAccountForSiteBtn = document.getElementById('addAccountForSiteBtn');
  const otherAccountsSectionWrapper = document.getElementById('otherAccountsSectionWrapper');
  const otherAccountsList = document.getElementById('otherAccountsList');
  const popupOpenFullTabLink = document.getElementById('popupOpenFullTabLink');

  // In-Memory Ephemeral State (Cleared on lock or popup close)
  let activeVek = null;
  let decryptedVault = null;
  let activeTabId = null;
  let activeTabUrl = '';
  let activeDomain = '';
  let noticeTimer = null;
  let clipboardClearTimer = null;
  let isUnlocking = false;
  let lockGeneration = 0;
  const viewInstanceId = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `popup-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  function isLockGenerationCurrent(generation) {
    return generation === lockGeneration;
  }

  function broadcastGlobalLock(reason = 'manual') {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'LOCK_VAULT', sourceId: viewInstanceId, reason }).catch(() => {});
      }
    } catch (_) {}
  }

  // --- THEME MANAGEMENT ---
  function initTheme() {
    const savedTheme = localStorage.getItem('secure_vault_theme') || 'dark';
    applyTheme(savedTheme);
  }

  function applyTheme(theme) {
    htmlRoot.setAttribute('data-theme', theme);
    if (theme === 'light') {
      themeIconDark.classList.add('hidden');
      themeIconLight.classList.remove('hidden');
    } else {
      themeIconDark.classList.remove('hidden');
      themeIconLight.classList.add('hidden');
    }
  }

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = htmlRoot.getAttribute('data-theme') || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(newTheme);
      try {
        localStorage.setItem('secure_vault_theme', newTheme);
      } catch (_) {}
    });
  }

  // --- NOTIFICATION BANNER ---
  function showNotice(message, duration = 3000) {
    if (!popupNotice || !popupNoticeText) return;
    popupNoticeText.textContent = message;
    popupNotice.classList.remove('hidden');
    if (noticeTimer) clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => {
      popupNotice.classList.add('hidden');
      noticeTimer = null;
    }, duration);
  }

  // --- ACTIVE TAB DETECTION ---
  async function detectActiveTab() {
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (tabs && tabs[0]) {
          activeTabId = tabs[0].id;
          activeTabUrl = tabs[0].url || '';
        }
      }
    } catch (_) {
      // In dev simulator or iframe
      activeTabUrl = window.location.href;
    }

    if (!activeTabUrl) {
      siteNameDisplay.textContent = 'No active tab';
      return;
    }

    // Check for internal schemes
    if (activeTabUrl.startsWith('chrome://') || activeTabUrl.startsWith('chrome-extension://') ||
        activeTabUrl.startsWith('edge://') || activeTabUrl.startsWith('about:') || activeTabUrl.startsWith('view-source:')) {
      activeDomain = '';
      siteNameDisplay.textContent = 'Browser System Page';
      siteNameDisplay.title = activeTabUrl;
      return;
    }

    activeDomain = extractHostname(activeTabUrl);
    if (activeDomain) {
      siteNameDisplay.textContent = activeDomain;
      siteNameDisplay.title = activeTabUrl;
    } else {
      siteNameDisplay.textContent = 'Local / Unknown Page';
    }
  }

  // --- NAVIGATION: OPEN DEDICATED VAULT ---
  function openVaultTab(params = '') {
    const isExtension = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL;
    const targetUrl = isExtension
      ? chrome.runtime.getURL(`pages/vault.html${params}`)
      : `pages/vault.html${params}`;

    if (isExtension && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  }

  if (openVaultPageBtn) openVaultPageBtn.addEventListener('click', () => openVaultTab());
  if (launchVaultBtn) launchVaultBtn.addEventListener('click', () => openVaultTab());
  if (setupVaultBtn) setupVaultBtn.addEventListener('click', () => openVaultTab());
  if (popupOpenFullTabLink) popupOpenFullTabLink.addEventListener('click', () => openVaultTab());

  if (addAccountForSiteBtn) {
    addAccountForSiteBtn.addEventListener('click', () => {
      const q = activeDomain ? `?addSite=${encodeURIComponent(activeDomain)}` : '';
      openVaultTab(q);
    });
  }

  // --- VIEW SWITCHER ---
  function switchView(viewName) {
    popupSetupView.classList.add('hidden');
    popupLockedView.classList.add('hidden');
    popupUnlockedView.classList.add('hidden');
    popupLockBtn.classList.add('hidden');

    if (viewName === 'setup') {
      popupSetupView.classList.remove('hidden');
    } else if (viewName === 'locked') {
      popupLockedView.classList.remove('hidden');
      if (popupMasterPasswordInput) {
        popupMasterPasswordInput.value = '';
        popupMasterPasswordInput.focus();
      }
    } else if (viewName === 'unlocked') {
      popupUnlockedView.classList.remove('hidden');
      popupLockBtn.classList.remove('hidden');
    }
  }

  // --- GLOBAL LOCK ---
  function lockVault(options = {}) {
    const { broadcast = true, notify = true } = options;
    const wasUnlocked = Boolean(activeVek || decryptedVault);

    // Invalidate any unlock/copy operation that is still awaiting an API response.
    lockGeneration += 1;
    activeVek = null;
    decryptedVault = null;
    if (popupMasterPasswordInput) popupMasterPasswordInput.value = '';
    if (popupSearchInput) popupSearchInput.value = '';
    if (matchedAccountsList) matchedAccountsList.innerHTML = '';
    if (otherAccountsList) otherAccountsList.innerHTML = '';
    siteMatchCount.classList.add('hidden');

    // Keep a pending clipboard expiry timer alive across lock.
    if (wasUnlocked) switchView('locked');
    if (broadcast) broadcastGlobalLock('manual');
    if (notify && wasUnlocked) showNotice('Vault locked.');
  }

  if (popupLockBtn) popupLockBtn.addEventListener('click', lockVault);

  // --- UNLOCK VAULT (HARDENED 6-STAGE PIPELINE) ---
  async function performUnlock(password) {
    if (isUnlocking) return;
    const operationGeneration = lockGeneration;
    if (!password) {
      showNotice('Please enter your Master Password.');
      return;
    }

    let failureStage = null;

    try {
      isUnlocking = true;
      popupSubmitUnlockBtn.disabled = true;
      popupSubmitUnlockBtn.textContent = '...';

      // 1. Storage load
      let record;
      try {
        record = await StorageModule.loadVaultRecord();
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'STORAGE_LOAD_FAILED';
        showNotice('Unable to access your vault storage. Please try again.');
        return;
      }

      // 2. Vault record validation
      if (!record || !StorageModule.validateVaultRecord(record)) {
        failureStage = 'INVALID_VAULT_RECORD';
        showNotice('Your vault data appears corrupted or incomplete.');
        return;
      }

      // 3. Master key derivation
      let masterKey;
      try {
        const saltBytes = base64ToBytes(record.masterProtection.salt);
        masterKey = await deriveMasterKey(password, saltBytes);
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'MASTER_KEY_DERIVATION_FAILED';
        showNotice('Unable to access your vault storage. Please try again.');
        return;
      }

      // 4. VEK unwrap (Cryptographic authentication of Master Password)
      let vek;
      try {
        vek = await unwrapVaultKey(
          record.masterProtection.wrappedVaultKey,
          record.masterProtection.iv,
          masterKey,
          record.masterProtection.aad || AAD_MASTER_KEY
        );
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'VEK_UNWRAP_FAILED';
        if (popupMasterPasswordInput) popupMasterPasswordInput.value = '';
        showNotice('Incorrect Master Password.');
        return;
      }

      // 5. Decrypt Vault payload
      let rawVaultData;
      try {
        rawVaultData = await decryptVault(record.vault, vek);
        if (!isLockGenerationCurrent(operationGeneration)) return;
      } catch (err) {
        if (!isLockGenerationCurrent(operationGeneration)) return;
        failureStage = 'VAULT_DECRYPT_FAILED';
        showNotice('Your vault data appears corrupted or incomplete.');
        return;
      }

      // 6. Payload validation
      if (!rawVaultData || typeof rawVaultData !== 'object' || !Array.isArray(rawVaultData.accounts)) {
        failureStage = 'VAULT_PAYLOAD_INVALID';
        showNotice('Your vault data appears corrupted or incomplete.');
        return;
      }

      // Commit only if no global lock arrived during the unlock pipeline.
      if (!isLockGenerationCurrent(operationGeneration)) return;
      activeVek = vek;
      decryptedVault = rawVaultData;
      if (popupMasterPasswordInput) popupMasterPasswordInput.value = '';

      switchView('unlocked');
      renderAccountsView();
      showNotice('Vault unlocked.');
    } catch (_) {
      if (popupMasterPasswordInput) popupMasterPasswordInput.value = '';
      if (isLockGenerationCurrent(operationGeneration)) showNotice('Incorrect Master Password.');
    } finally {
      isUnlocking = false;
      popupSubmitUnlockBtn.disabled = false;
      popupSubmitUnlockBtn.textContent = 'Unlock';
    }
  }

  if (popupUnlockForm) {
    popupUnlockForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const pass = popupMasterPasswordInput.value;
      if (pass) performUnlock(pass);
    });
  }

  // --- RENDER MATCHED & SEARCH ACCOUNTS ---
  function renderAccountsView() {
    if (!decryptedVault || !Array.isArray(decryptedVault.accounts)) return;

    const allAccounts = decryptedVault.accounts;
    const searchQuery = (popupSearchInput?.value || '').trim().toLowerCase();

    // 1. Domain matching for active webpage
    const matchedAccounts = activeDomain ? findMatchingAccounts(allAccounts, activeDomain) : [];

    // Update match count badge
    if (matchedAccounts.length > 0) {
      siteMatchCount.textContent = `${matchedAccounts.length} match${matchedAccounts.length > 1 ? 'es' : ''}`;
      siteMatchCount.classList.remove('hidden');
    } else {
      siteMatchCount.classList.add('hidden');
    }

    // 2. Render matched accounts section
    matchedAccountsList.innerHTML = '';
    if (matchedAccounts.length > 0) {
      noMatchesNotice.classList.add('hidden');
      matchedAccounts.forEach((acc) => {
        matchedAccountsList.appendChild(createAccountCard(acc, true));
      });
    } else {
      if (activeDomain) {
        noMatchesNotice.classList.remove('hidden');
        noMatchesDesc.textContent = `No stored credentials match "${activeDomain}".`;
      } else {
        noMatchesNotice.classList.add('hidden');
      }
    }

    // 3. Render other / search accounts
    otherAccountsList.innerHTML = '';
    let filteredOthers = [];

    if (searchQuery) {
      // Search all accounts
      filteredOthers = allAccounts.filter((acc) => {
        const name = (acc.name || '').toLowerCase();
        const user = (acc.username || '').toLowerCase();
        const site = (acc.website || '').toLowerCase();
        const cat = (acc.category || '').toLowerCase();
        return name.includes(searchQuery) || user.includes(searchQuery) || site.includes(searchQuery) || cat.includes(searchQuery);
      });
      otherAccountsSectionWrapper.classList.remove('hidden');
      const titleEl = document.getElementById('otherAccountsTitle');
      if (titleEl) titleEl.textContent = `Search Results (${filteredOthers.length})`;
    } else if (matchedAccounts.length === 0) {
      // If no matches for domain, show all accounts
      filteredOthers = allAccounts;
      otherAccountsSectionWrapper.classList.remove('hidden');
      const titleEl = document.getElementById('otherAccountsTitle');
      if (titleEl) titleEl.textContent = `All Accounts (${allAccounts.length})`;
    } else {
      // If matches exist and not searching, hide other accounts to keep popup clean
      otherAccountsSectionWrapper.classList.add('hidden');
    }

    filteredOthers.forEach((acc) => {
      otherAccountsList.appendChild(createAccountCard(acc, false));
    });
  }

  // --- ACCOUNT CARD DOM BUILDER ---
  function createAccountCard(account, isMatched = false) {
    const card = document.createElement('div');
    card.className = `account-card ${isMatched ? 'matched-card' : ''}`;

    // Header
    const cardHeader = document.createElement('div');
    cardHeader.className = 'card-header';

    const avatar = document.createElement('div');
    avatar.className = 'card-avatar avatar-blue';
    avatar.textContent = (account.name || 'A').charAt(0).toUpperCase();

    const meta = document.createElement('div');
    meta.className = 'card-meta';

    const titleRow = document.createElement('div');
    titleRow.style.display = 'flex';
    titleRow.style.alignItems = 'center';
    titleRow.style.gap = '6px';

    const title = document.createElement('div');
    title.className = 'card-title';
    title.textContent = account.name || 'Account';
    titleRow.appendChild(title);

    if (account._matchReason) {
      const matchPill = document.createElement('span');
      matchPill.className = 'match-reason-pill';
      matchPill.textContent = account._matchReason;
      titleRow.appendChild(matchPill);
    }

    const category = document.createElement('div');
    category.className = 'card-category';
    category.textContent = account.category || 'Other';

    meta.appendChild(titleRow);
    meta.appendChild(category);

    cardHeader.appendChild(avatar);
    cardHeader.appendChild(meta);

    // Identity (Username)
    const identityBox = document.createElement('div');
    identityBox.className = 'card-identity';

    const label = document.createElement('span');
    label.className = 'identity-label';
    label.textContent = 'Username';

    const val = document.createElement('span');
    val.className = 'identity-value';
    val.textContent = account.username || '(none)';

    identityBox.appendChild(label);
    identityBox.appendChild(val);

    // Actions Row
    const actionsRow = document.createElement('div');
    actionsRow.className = 'card-actions';

    // 1. Primary "Fill" Button (Stage 7 User-Triggered Autofill)
    const fillBtn = document.createElement('button');
    fillBtn.type = 'button';
    fillBtn.className = 'btn-fill-primary';
    fillBtn.style.flex = '1';
    fillBtn.innerHTML = `
      <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 2l-2 2m-1-1l-3 3m2-2l-3 3m-2-2l-3 3M3 21l9-9"/>
        <circle cx="7.5" cy="7.5" r="4.5"/>
      </svg>
      Fill
    `;
    fillBtn.addEventListener('click', async () => {
      await handleAutofill(account.id);
    });

    // 2. Copy Username Button
    const copyUserBtn = document.createElement('button');
    copyUserBtn.type = 'button';
    copyUserBtn.className = 'btn btn-secondary btn-action';
    copyUserBtn.title = 'Copy Username';
    copyUserBtn.innerHTML = `
      <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
      </svg>
    `;
    copyUserBtn.addEventListener('click', async () => {
      const operationGeneration = lockGeneration;
      try {
        await navigator.clipboard.writeText(account.username || '');
        if (isLockGenerationCurrent(operationGeneration)) showNotice('Username copied.');
      } catch (_) {
        if (isLockGenerationCurrent(operationGeneration)) showNotice('Could not copy username.');
      }
    });

    // 3. Copy Password Button
    const copyPassBtn = document.createElement('button');
    copyPassBtn.type = 'button';
    copyPassBtn.className = 'btn btn-secondary btn-action';
    copyPassBtn.title = 'Copy Password';
    copyPassBtn.innerHTML = `
      <svg class="icon-svg-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    `;
    copyPassBtn.addEventListener('click', async () => {
      const operationGeneration = lockGeneration;
      try {
        await navigator.clipboard.writeText(account.password || '');
        if (!isLockGenerationCurrent(operationGeneration)) {
          try { await navigator.clipboard.writeText(''); } catch (_) {}
          return;
        }
        showNotice('Password copied. Clipboard clears in 30s.');
        scheduleClipboardClear();
      } catch (_) {
        if (isLockGenerationCurrent(operationGeneration)) showNotice('Could not copy password.');
      }
    });

    actionsRow.appendChild(fillBtn);
    actionsRow.appendChild(copyUserBtn);
    actionsRow.appendChild(copyPassBtn);

    card.appendChild(cardHeader);
    card.appendChild(identityBox);
    card.appendChild(actionsRow);

    return card;
  }

  // --- STAGE 7 AUTOFILL HANDLER (Requirements 5, 6, 20, 21) ---
  async function handleAutofill(accountId) {
    // 1. Vault unlocked verification (Requirement 20)
    if (!activeVek || !decryptedVault || !Array.isArray(decryptedVault.accounts)) {
      showNotice('Vault is locked.');
      return;
    }
    const operationGeneration = lockGeneration;
    const operationVek = activeVek;

    // 2. Account ID must be the source of truth (Requirement 6)
    const account = decryptedVault.accounts.find((a) => a.id === accountId);
    if (!account) {
      showNotice('Website changed. Please select the account again.');
      return;
    }

    // 3. Mandatory Active Tab Revalidation immediately before autofill (Requirement 5 & 21)
    let currentTab = null;
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (!isLockGenerationCurrent(operationGeneration) || activeVek !== operationVek) return;
        if (tabs && tabs.length > 0) {
          currentTab = tabs[0];
        }
      }
    } catch (_) {}

    // Mandatory Active Tab Revalidation immediately before autofill:
    // Stale cached activeTabUrl or activeTabId must NEVER be used for credential autofill.
    // If chrome.tabs.query() cannot return the current active tab, autofill is aborted.
    if (!isLockGenerationCurrent(operationGeneration) || activeVek !== operationVek) return;
    if (!currentTab || !currentTab.url) {
      showNotice('Website changed. Please select the account again.');
      return;
    }

    // Verification 2: Current URL is http or https
    if (!currentTab.url.startsWith('http://') && !currentTab.url.startsWith('https://')) {
      showNotice('Cannot autofill browser system pages.');
      return;
    }

    // Verification 3: Current hostname is valid
    const currentHost = extractHostname(currentTab.url);
    if (!currentHost) {
      showNotice('Website changed. Please select the account again.');
      return;
    }

    // Verification 4: Selected account still exists in the in-memory decrypted vault
    if (!decryptedVault.accounts.some((a) => a.id === accountId)) {
      showNotice('Website changed. Please select the account again.');
      return;
    }

    // Verification 5: Selected account still matches CURRENT hostname (Requirement 5 & 21)
    if (!account.website || !isDomainMatch(account.website, currentHost)) {
      showNotice('Website changed. Please select the account again.');
      return;
    }

    // Verification 6: The exact unlock session must still be current.
    if (!isLockGenerationCurrent(operationGeneration) || activeVek !== operationVek || !decryptedVault) return;

    // 4. ONLY THEN retrieve username and password for the fill operation
    const credentials = {
      username: account.username || '',
      password: account.password || ''
    };

    try {
      if (!isLockGenerationCurrent(operationGeneration) || activeVek !== operationVek) return;
      const result = await triggerTabAutofill(currentTab.id, currentTab.url, credentials);
      if (!isLockGenerationCurrent(operationGeneration) || activeVek !== operationVek) return;
      if (result.success) {
        showNotice(`Autofilled into ${currentHost}!`);
      } else {
        showNotice(result.message || 'Could not find login fields.');
      }
    } catch (err) {
      if (isLockGenerationCurrent(operationGeneration) && activeVek === operationVek) {
        showNotice(`Autofill error: ${err.message || 'Execution error'}`);
      }
    }
  }

  // --- BEST-EFFORT CLIPBOARD CLEAR (30s) ---
  function scheduleClipboardClear() {
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
    clipboardClearTimer = setTimeout(() => {
      try {
        navigator.clipboard.writeText('');
      } catch (_) {}
      clipboardClearTimer = null;
    }, 30000);
  }

  // Search input event
  if (popupSearchInput) {
    popupSearchInput.addEventListener('input', () => {
      renderAccountsView();
    });
  }

  // Listen for auto-lock, screen-lock, or lock-vault signals from background service worker
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg) => {
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'LOCK_VAULT') {
        if (msg.sourceId !== viewInstanceId) lockVault({ broadcast: false, notify: false });
      } else if (msg.type === 'SYSTEM_LOCK') {
        lockVault({ broadcast: false, notify: false });
      } else if (msg.type === 'AUTO_LOCK') {
        lockVault({ broadcast: false, notify: false });
      }
    });
  }

  // In-page keyboard shortcut: Ctrl+Shift+K / Cmd+Shift+K to lock
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'K' || e.key === 'k')) {
      e.preventDefault();
      if (activeVek) {
        lockVault();
      }
    }
  });

  // --- INITIALIZATION ---
  initTheme();
  await detectActiveTab();

  const hasVault = await StorageModule.hasVault();
  if (!hasVault) {
    switchView('setup');
  } else {
    switchView('locked');
  }
});
