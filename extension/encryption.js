import Logger from './logger.js';
import { ensureSettings, defaultSettings } from './settings.js';
import { sessionGet, sessionSet, sessionRemove } from './session.js';

export const KEY_RECORD_KEY = 'encryptionKeyRecord';
export const KEY_VERSION = 1;

let cryptoKey = null;
let encryptionLocked = false;
let encryptionLockReason = null;

export function getCryptoKey() {
  return cryptoKey;
}

export function isEncryptionLocked() {
  return encryptionLocked;
}

export function getEncryptionLockReason() {
  return encryptionLockReason;
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(base64) {
  const binary = atob(base64 || '');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function generateDataKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKeyBase64(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(raw);
}

export async function importKeyBase64(b64) {
  const bytes = base64ToUint8(b64);
  return crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

const MIN_ITERATIONS = 150000;

async function deriveWrappingKey(passkey, saltBytes, iterations, enforceFloor = true) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passkey),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: enforceFloor
        ? Math.max(iterations || defaultSettings.encryption.iterations, MIN_ITERATIONS)
        : (iterations || defaultSettings.encryption.iterations),
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrapDataKey(passkey) {
  if (!cryptoKey) {
    throw new Error('Data key not available to wrap');
  }
  const settings = await ensureSettings();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const effectiveIterations = Math.max(settings.encryption.iterations || MIN_ITERATIONS, MIN_ITERATIONS);
  const wrappingKey = await deriveWrappingKey(passkey, salt, effectiveIterations);
  const raw = await crypto.subtle.exportKey('raw', cryptoKey);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, raw);
  return {
    encryptedKey: bufferToBase64(encrypted),
    keySalt: bufferToBase64(salt),
    keyIV: bufferToBase64(iv),
    iterations: effectiveIterations,
  };
}

function isValidKeyRecord(record) {
  if (!record || typeof record !== 'object') return false;
  if (typeof record.encryptedKey !== 'string' || !record.encryptedKey) return false;
  if (typeof record.keySalt !== 'string' || !record.keySalt) return false;
  if (typeof record.keyIV !== 'string' || !record.keyIV) return false;
  try {
    const salt = base64ToUint8(record.keySalt);
    const iv = base64ToUint8(record.keyIV);
    if (salt.length !== 16) return false;
    if (iv.length !== 12) return false;
  } catch { return false; }
  return true;
}

export async function unwrapDataKey(passkey, record) {
  if (!isValidKeyRecord(record)) {
    throw new Error('Encrypted key record is incomplete or invalid');
  }
  const salt = base64ToUint8(record.keySalt);
  const iv = base64ToUint8(record.keyIV);
  const encrypted = base64ToUint8(record.encryptedKey);
  const wrappingKey = await deriveWrappingKey(passkey, salt, record.iterations || defaultSettings.encryption.iterations, false);
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, encrypted);
  cryptoKey = await crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  await saveKeyToSession(cryptoKey);
  encryptionLocked = false;
  encryptionLockReason = null;
  return cryptoKey;
}

export async function saveKeyToSession(key) {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', key);
    await sessionSet('cryptoKey', jwk);
  } catch (err) {
    Logger.warn('Failed to save key to session', err);
  }
}

export async function restoreKeyFromSession() {
  try {
    const stored = await sessionGet('cryptoKey');
    const jwk = stored.cryptoKey;
    if (jwk) {
      cryptoKey = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      encryptionLocked = false;
      encryptionLockReason = null;
    }
  } catch (err) {
    Logger.warn('Failed to restore key from session', err);
  }
}

export async function clearSessionKey() {
  cryptoKey = null;
  await sessionRemove('cryptoKey');
}

// ABSOLUTELY-LOCAL: the key record never leaves this device. The local storage area
// is the only backing store; the synced storage area would replicate key material to
// Google servers, which is the single byte of egress this build exists to eliminate.
// Failures deliberately propagate. Swallowing them lets setPasskey() report success
// while the wrapped key was never written — the user believes their history is
// passkey-protected when it is not, and only discovers otherwise after a restart.
// A security boundary must not report success it cannot substantiate.
export async function persistKeyRecord(record) {
  await chrome.storage.local.set({ [KEY_RECORD_KEY]: record });
}

// Allowlist on read, mirroring settings.js. A key record written by the upstream
// build carries escrow flags; callers that rebuild a record via spread (the PBKDF2
// iteration upgrade in unlockWithPasskey) would otherwise re-persist them, leaving
// live-looking remote-backup state sitting next to key material in local storage.
// Normalizing here cleans every consumer, since they all read through this function.
const KEY_RECORD_FIELDS = [
  'usingPasskey', 'dataKey', 'encryptedKey', 'keySalt',
  'keyIV', 'iterations', 'keyVersion', 'updatedAt',
];

function normalizeKeyRecord(record) {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const clean = {};
  for (const field of KEY_RECORD_FIELDS) {
    if (record[field] !== undefined) {
      clean[field] = record[field];
    }
  }
  return clean;
}

export async function loadKeyRecord() {
  try {
    const localStored = await chrome.storage.local.get(KEY_RECORD_KEY);
    return normalizeKeyRecord(localStored[KEY_RECORD_KEY]);
  } catch (err) {
    Logger.warn('Failed to read key record from local storage', err);
    return null;
  }
}

export async function clearKeyRecords() {
  try {
    await chrome.storage.local.remove(KEY_RECORD_KEY);
  } catch (err) {
    Logger.warn('Failed to clear key record from local storage', err);
  }
}

// Generated once, on this device, at install. Never transmitted, never escrowed.
// If the extension is uninstalled the key is gone and suspended tabs are
// unrecoverable — an accepted trade for zero egress.
export async function generateAndPersistDataKey() {
  cryptoKey = await generateDataKey();
  const b64 = await exportKeyBase64(cryptoKey);
  const record = {
    usingPasskey: false,
    dataKey: b64,
    keyVersion: KEY_VERSION,
    updatedAt: Date.now(),
  };
  await persistKeyRecord(record);
  await saveKeyToSession(cryptoKey);
  encryptionLocked = false;
  encryptionLockReason = null;
  Logger.info('Generated new device-local data key');
  return record;
}

export function markEncryptionLocked(reason = null) {
  encryptionLocked = true;
  encryptionLockReason = reason || null;
}

export async function retryImportPlaintextKey() {
  const record = await loadKeyRecord();
  if (!record || record.usingPasskey || !record.dataKey) {
    return { ok: false, error: 'no-plaintext-record' };
  }
  try {
    cryptoKey = await importKeyBase64(record.dataKey);
    encryptionLocked = false;
    encryptionLockReason = null;
    await saveKeyToSession(cryptoKey);
    return { ok: true };
  } catch (err) {
    Logger.warn('Retry import of plaintext key failed', err);
    markEncryptionLocked('corrupt-key');
    return { ok: false, error: 'corrupt-key' };
  }
}

export async function initializeEncryption() {
  if (!cryptoKey) {
    await restoreKeyFromSession();
  }
  if (cryptoKey) {
    encryptionLocked = false;
    encryptionLockReason = null;
    return;
  }

  const record = await loadKeyRecord();
  if (!record) {
    await generateAndPersistDataKey();
    return;
  }

  if (record.usingPasskey) {
    if (record.encryptedKey && record.keySalt && record.keyIV) {
      markEncryptionLocked('passkey-required');
    } else {
      markEncryptionLocked('corrupt-key');
    }
    return;
  }

  if (record.dataKey) {
    try {
      cryptoKey = await importKeyBase64(record.dataKey);
      encryptionLocked = false;
      encryptionLockReason = null;
      await saveKeyToSession(cryptoKey);
      return;
    } catch (err) {
      Logger.warn('Failed to import plaintext data key', err);
      markEncryptionLocked('corrupt-key');
      return;
    }
  }

  markEncryptionLocked('corrupt-key');
}

export async function unlockWithPasskey(passkey) {
  const settings = await ensureSettings();
  const record = await loadKeyRecord();
  if (!record || !record.usingPasskey) {
    return { ok: false, error: 'not-locked' };
  }
  try {
    await unwrapDataKey(passkey, record);
  } catch (err) {
    Logger.warn('Passkey unlock failed', err);
    markEncryptionLocked('bad-passkey');
    return { ok: false, error: 'bad-passkey' };
  }

  // Upgrade weak PBKDF2 iteration count after successful unwrap
  const recordIterations = record.iterations || settings.encryption.iterations;
  if (recordIterations < MIN_ITERATIONS) {
    try {
      Logger.info('Upgrading PBKDF2 iterations', {
        from: recordIterations,
        to: Math.max(settings.encryption.iterations, MIN_ITERATIONS),
      });
      const wrapped = await wrapDataKey(passkey);
      const upgraded = {
        ...record,
        encryptedKey: wrapped.encryptedKey,
        keySalt: wrapped.keySalt,
        keyIV: wrapped.keyIV,
        iterations: wrapped.iterations,
        updatedAt: Date.now(),
      };
      await persistKeyRecord(upgraded);
    } catch (upgradeErr) {
      // Non-fatal: key is already unwrapped and usable
      Logger.warn('Failed to upgrade PBKDF2 iteration count', upgradeErr);
    }
  }

  return { ok: true };
}

export async function setPasskey(passkey) {
  if (!passkey) {
    return { ok: false, error: 'missing-passkey' };
  }
  if (encryptionLocked || !cryptoKey) {
    return { ok: false, error: 'locked' };
  }
  const wrapped = await wrapDataKey(passkey);
  const record = {
    usingPasskey: true,
    encryptedKey: wrapped.encryptedKey,
    keySalt: wrapped.keySalt,
    keyIV: wrapped.keyIV,
    iterations: wrapped.iterations,
    keyVersion: KEY_VERSION,
    updatedAt: Date.now(),
  };
  try {
    await persistKeyRecord(record);
  } catch (err) {
    Logger.error('Failed to persist passkey-wrapped key record', err);
    return { ok: false, error: 'persist-failed' };
  }
  return { ok: true };
}

export async function removePasskey() {
  if (encryptionLocked || !cryptoKey) {
    return { ok: false, error: 'locked' };
  }
  const b64 = await exportKeyBase64(cryptoKey);
  const record = {
    usingPasskey: false,
    dataKey: b64,
    keyVersion: KEY_VERSION,
    updatedAt: Date.now(),
  };
  try {
    await persistKeyRecord(record);
  } catch (err) {
    Logger.error('Failed to persist key record after passkey removal', err);
    return { ok: false, error: 'persist-failed' };
  }
  return { ok: true };
}

export function getEncryptionStatusPayload(record) {
  const locked = encryptionLocked || (!cryptoKey && record?.usingPasskey);
  return {
    locked,
    reason: locked ? (encryptionLockReason || (record?.usingPasskey ? 'passkey-required' : null)) : null,
    usingPasskey: !!record?.usingPasskey,
    hasKeyRecord: !!record,
  };
}
