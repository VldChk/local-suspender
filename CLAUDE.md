# Local Suspender — Developer Guide

## Project Identity

- **Name:** Local Suspender
- **Author:** VldChk
- **License:** MIT
- **Platform:** Chrome MV3 extension, vanilla JavaScript (ES modules)
- **No external dependencies** at runtime (dev-only: ESLint, archiver)

## Architecture Overview

```
extension/           <- packaged into the .zip / loaded by Chrome
  background.js      Service worker: core logic, state, alarms, message handler
  encryption.js      AES-256-GCM key management (generate, wrap, unwrap, session)
  settings.js        Settings schema, defaults, persistence
  session.js         chrome.storage.session wrapper with in-memory fallback
  logger.js          Structured logger → chrome.storage.local.logs[]
  popup.html/js/css  Toolbar popup: suspend/unsuspend actions, tab list
  options.html/js/css Options page: settings form, encryption panel, snapshots
  suspended.html/js/css Parked-tab page: token-based unsuspend flow
  manifest.json      MV3 manifest
scripts/
  package-extension.mjs  Archives extension/ into dist/*.zip
```

## Key Design Principles

1. **Offline-only** — zero network calls, no analytics, no telemetry
2. **Encryption-first** — state is always AES-256-GCM encrypted in storage
3. **MV3 compliant** — event listeners registered synchronously at module top level
4. **XSS-safe UI** — all DOM writes use `.textContent`, never `.innerHTML` with user data
5. **No content scripts** — operates entirely via chrome.tabs API and extension pages

## Storage Schema

### chrome.storage.local
| Key | Shape | Purpose |
|-----|-------|---------|
| `settings` | `{ autoSuspendMinutes, excludePinned, ... }` | User settings |
| `suspenderState` | `{ iv, ct }` or `{ plain: { suspendedTabs } }` | Encrypted tab state |
| `backups` | `[{ id, timestamp, tabCount, data }]` | Snapshot history |
| `encryptionKeyRecord` | `{ usingPasskey, dataKey?, encryptedKey?, ... }` | Key material |
| `logs` | `[{ timestamp, level, message, data }]` | Debug logs (max 1000) |

### chrome.storage.sync
| Key | Shape | Purpose |
|-----|-------|---------|
| `encryptionKeyRecord` | Same as local | Cloud backup of key record |

### chrome.storage.session
| Key | Shape | Purpose |
|-----|-------|---------|
| `cryptoKey` | JWK object | Decrypted data key for runtime |
| `lastActive` | `{ [tabId]: timestamp }` | Per-tab last-active timestamps |
| `pendingSuspenderState` | `{ suspendedTabs }` | Buffer while encryption is locked |

## Encryption Flow

```
First install → generateDataKey() → store plaintext Base64 in key record
With passkey  → wrapDataKey(passkey) → PBKDF2 → AES-GCM wrap → store encrypted blob
On startup    → restore JWK from session OR import from key record OR prompt for passkey
Locked state  → state writes go to pendingSuspenderState; reads return { locked: true }
On unlock     → reconcile pending + persisted state → re-encrypt → clear pending
```

**Key constants:**
- AES-256-GCM (256-bit keys, 12-byte IV)
- PBKDF2-SHA256, 150k iterations (see Known Issues)
- 16-byte salt for key derivation

## Message API (background.js ↔ UI)

| Message Type | Payload | Response |
|---|---|---|
| `GET_SETTINGS` | — | Settings object |
| `SAVE_SETTINGS` | `{ payload }` | `{ ok }` |
| `GET_STATE` | — | `{ locked, state? }` |
| `SUSPEND_CURRENT` | — | `{ ok }` |
| `SUSPEND_INACTIVE` | — | `{ ok }` |
| `RESUME_TAB` | `{ tabId }` | `{ ok }` |
| `RESUME_ALL` | — | `{ ok }` |
| `SUSPENDED_VIEW_INFO` | `{ token, tabId? }` | `{ found, info? }` |
| `UNSUSPEND_TOKEN` | `{ token, tabId }` | `{ ok, error? }` |
| `GET_ENCRYPTION_STATUS` | — | `{ locked, reason, usingPasskey, ... }` |
| `UNLOCK_WITH_PASSKEY` | `{ passkey }` | `{ ok, error? }` |
| `SET_PASSKEY` | `{ passkey }` | `{ ok, error? }` |
| `REMOVE_PASSKEY` | — | `{ ok, error? }` |
| `SET_CLOUD_BACKUP` | `{ enabled }` | `{ ok }` |
| `RESET_ENCRYPTION` | — | `{ ok }` |
| `GET_SNAPSHOTS` | — | `{ snapshots }` or `{ locked }` |
| `GET_SNAPSHOT_DETAILS` | `{ snapshotId }` | `{ ok, tabs? }` |
| `RESTORE_SNAPSHOT` | `{ snapshotId }` | `{ ok }` |
| `OPEN_SNAPSHOT` | `{ snapshotId, unsuspend? }` | `{ ok, opened }` |
| `RETRY_IMPORT_KEY` | — | `{ ok, error? }` |

## Alarms

| Name | Period | Purpose |
|------|--------|---------|
| `autoSuspend` | `autoSuspendMinutes / 3` (1-60 min) | Run auto-suspension tick |
| `snapshotTimer` | 180 min | Create encrypted state snapshot |
| `stateValidator` | 15 min | Prune orphaned tab entries |

## Tab Suspension Methods

1. **Discard** (`chrome.tabs.discard`) — native memory release, Chrome auto-reloads on focus
2. **Page** (`suspended.html`) — navigates tab to a parked page with token-based unsuspend

Selection: `unsuspendMethod === 'manual'` → page, otherwise → discard (with page fallback if discard fails).

## Token System

Each page-suspended tab gets a `crypto.randomUUID()` token with:
- 24-hour TTL (`TOKEN_TTL_MS`)
- Single-use flag (`tokenUsed`)
- Embedded in suspended page URL params (if `embedOriginalUrl` enabled)

## Coding Conventions

- ES modules throughout (`import`/`export`, `type: "module"` in manifest)
- `async`/`await` for all async operations
- UI uses `.textContent` exclusively (never `innerHTML` with dynamic data)
- Settings spread-merged with `defaultSettings` to ensure all fields present
- Encryption always enabled (`encryption.enabled: true` is forced)
- Logger writes to both `console` and `chrome.storage.local.logs`

## Known Issues (by severity)

### CRITICAL
- **Race conditions on cachedState** — concurrent async read-modify-write without mutex. Multiple handlers (handleTabUpdated, autoSuspendTick, suspendTab) can modify state simultaneously, causing lost updates.
- **Token reuse** — `tokenUsed` flag is checked but never set to `true` after successful unsuspend in `UNSUSPEND_TOKEN` handler. Tokens can theoretically be replayed.
- **Plaintext key in Chrome Sync** — when no passkey is set and cloud backup is enabled, the AES data key is stored in plaintext Base64 in `chrome.storage.sync`.
- **JWK in session storage** — the decrypted key is exported as JWK and stored in `chrome.storage.session`, readable by any code in the extension context.

### HIGH
- **PBKDF2 iterations** — 150k is below OWASP 2023 recommendation of 600k+ for SHA-256.
- **All CryptoKeys are extractable** — keys created with `extractable: true`, allowing memory extraction.
- **No key rotation** — `keyVersion` field exists but no rotation mechanism is implemented.
- **lastActiveCache memory leak** — orphaned entries for closed tabs accumulate; no pruning in `autoSuspendTick`.
- **Missing outer error boundary in handleMessage** — uncaught errors in the async IIFE go unhandled.
- **Snapshot concurrency** — `getSnapshots()` doesn't use `snapshotLock`, can race with `createSnapshot()`.

### MEDIUM
- **wildcardToRegExp greedy quantifier** — uses `.*` instead of `.*?`, minor ReDoS risk.
- **No iteration count validation** — stored record could have `iterations: 1`.
- **No URL validation in snapshot restore** — `javascript:` or `chrome://` URLs not filtered.
- **Duplicate code: SnapshotService.openSnapshot vs openSnapshotTabs** — two similar implementations for opening snapshot tabs.
- **Redundant validateState calls** in handleTabRemoved/handleTabUpdated.
- **handleTabUpdated loads state 3 times** — should load once and reuse.

### LOW
- **Dead code** — `UNSUSPEND_TOKEN` has redundant token check at line 1289 (already validated at 1276).
- **No rate limiting** on passkey unlock attempts.
- **Missing icons** in manifest.
- **implementation.plan.md** inside `extension/` gets packaged; should be moved out.
- **Inconsistent error response shapes** across message handlers.
- **Favicon caching blocks suspension** — network fetch (up to 1.5s) during `suspendViaDiscard`/`suspendViaPage`.

## Development

```bash
npm install          # Install dev dependencies (ESLint, archiver)
npm run lint         # ESLint check on extension/
npm run package      # Create dist/*.zip
```

Load the `extension/` directory as an unpacked extension in Chrome for development.

## File-by-File Guide

### background.js (1360 lines)
The service worker. Contains:
- `init()` — loads settings, encryption, schedules alarms
- Event listeners (tabs, alarms, idle, storage, runtime)
- `SnapshotService` — snapshot CRUD with serialized locking
- `autoSuspendTick()` — periodic suspension of idle tabs
- `suspendTab()` / `suspendViaDiscard()` / `suspendViaPage()` — suspension logic
- `handleMessage()` — central message router (20+ message types)
- `encryptPayload()` / `decryptPayload()` — state encryption wrappers
- `reconcilePendingStateAfterUnlock()` — merges pending state after key unlock

### encryption.js (406 lines)
Key management module. Exports:
- `initializeEncryption()` — startup key restoration/generation
- `getCryptoKey()` / `isEncryptionLocked()` — state queries
- `generateDataKey()` / `wrapDataKey()` / `unwrapDataKey()` — key lifecycle
- `setPasskey()` / `removePasskey()` / `unlockWithPasskey()` — passkey flow
- `setCloudBackupEnabled()` — cloud sync toggle
- `persistKeyRecord()` / `loadKeyRecord()` — storage layer

### settings.js (56 lines)
Simple settings manager with `defaultSettings`, `ensureSettings()`, and `saveSettings()`. Forces `encryption.enabled: true` always.

### session.js (24 lines)
Wraps `chrome.storage.session` with in-memory fallback for environments where session storage is unavailable.

### logger.js (28 lines)
Writes to both `console` and `chrome.storage.local.logs[]` (ring buffer, max 1000 entries).

### popup.js (202 lines)
Toolbar popup. Detects if current tab is suspended (shows context-aware UI), lists suspended tabs, handles suspend/unsuspend actions.

### options.js (545 lines)
Options page. Settings form, encryption status panel, passkey management, snapshot browser with expand/collapse details, log download/clear.

### suspended.js (176 lines)
Parked tab page. Reads token from URL params, fetches tab info from background, handles unsuspend flow with fallback to direct navigation.
