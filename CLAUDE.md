# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Companion docs: **`SECURITY.md`** is the authoritative threat model and the document a reviewer reads first. **`AGENTS.md`** holds release checklists, branding guardrails, and the pre-merge scan. Don't duplicate either here.

## Branch: `absolutely-local`

This branch removes all network egress. It is a distinct product from `main`, not a feature toggle:

- **No synced storage.** The key record lives only in `chrome.storage.local`. Reintroducing `chrome.storage.sync` anywhere fails the build.
- **No cloud backup.** `SET_CLOUD_BACKUP`, `setCloudBackupEnabled`, `cloudBackupEnabled`, `syncEligible`, `syncBlockedReason` are all gone.
- **Manifest CSP** makes remote requests structurally impossible.
- **`scripts/verify-no-egress.mjs`** is a release blocker wired into `npm run package`.

Before changing anything network-adjacent, read `SECURITY.md`. The guarantee is the product.

## What this is

Chrome MV3 extension that suspends idle tabs. Vanilla ES modules, zero runtime dependencies, zero network egress. Tab state is always AES-256-GCM encrypted at rest.

## Commands

```bash
npm ci
npm run verify:egress # release-blocking egress gate — run this first
npm run lint          # eslint extension/ + scripts/ — must be clean
npm test              # node --test (3 tests)
npm run package       # gate, then → dist/local-suspender-<manifest.version>.zip (via yazl)

node --test tests/unsuspend-token-flow.test.js   # single file
```

`node --test tests/` (trailing dir) **fails** — Node resolves it as a module path, not a test dir. `npm test` uses bare `node --test` from the repo root.

`eslint.config.mjs` only globs `extension/**/*.js` and `scripts/**/*.mjs`. **`tests/` is unlinted** — running `npx eslint tests` yields a bogus `structuredClone is not defined` because tests fall through to `js.configs.recommended` with no globals configured. Add a `files: ['tests/**/*.js']` block with `globals.node` if you ever want them linted.

Load `extension/` unpacked at `chrome://extensions` for development.

## Architecture

```
extension/
  background.js           service worker — the whole engine
  encryption.js           key lifecycle: generate / wrap / unwrap / session cache
  state-codec.js          v2 compact tuple encoding + tolerant legacy decode
  unsuspend-token-flow.js token state machine (pure, injected deps, unit-tested)
  settings.js  session.js  logger.js
  popup.* options.* suspended.*    three independent UI surfaces
scripts/package-extension.mjs
tests/unsuspend-token-flow.test.js
docs/implementation.plan.md        historical design doc, not current spec
```

Deliberate split: `state-codec.js` and `unsuspend-token-flow.js` were extracted from `background.js` so they're testable without a `chrome` global. `unsuspend-token-flow.js` takes every dependency as a parameter — that's why it has tests and the rest doesn't. **Extract the same way when adding testable logic.**

### The state write pipeline

```
{ suspendedTabs: {...} }  →  encodeStateV2  →  { v:2, tabs:[[...]] }
                          →  encryptPayload →  { iv, ct }  (base64url)
                          →  chrome.storage.local.suspenderState
```

Reads go through `decodeStateAny`, which sniffs `raw.v === 2` and otherwise falls back to the legacy `{ suspendedTabs }` decoder. **Both decode paths normalize** — unknown methods coerce, non-`data:`/`chrome-extension:` favicons become `''`, malformed entries drop. Never bypass the codec; hand-written state objects will silently lose fields on the next round-trip.

Tuple order (`state-codec.js`) is positional and load-bearing:
`[tabId, url, title, windowId, suspendedAt, method, reason, token, tokenIssuedAt, tokenUsed, favIconUrl]`
`method` encodes as `0`=discard, `1`=page. Appending a field is safe (decode requires `length >= 11`); reordering is not.

### Concurrency model — read before touching state

`background.js` documents its lock hierarchy at the top. Acquire in this order or deadlock:

```
snapshotLock  →  stateLock
reconciliationLock is independent; saveState awaits it but never holds stateLock while waiting
```

- `withStateLock(fn)` — serializes every read-modify-write of `cachedState`. Any handler mutating `suspendedTabs` must be inside it.
- **Re-check `stateIsWritable()` inside the lock**, not just before acquiring it. Every existing handler does this; the lock can be held across an unlock/corruption transition.
- `deferStateWrite: true` — `suspendTab` returns `{ ok, patch }` instead of writing. Bulk callers (`autoSuspendTick`, `SUSPEND_INACTIVE`) collect patches, then apply them all under **one** lock, re-verifying each tab still matches its claimed method before committing. This is why bulk suspension doesn't thrash the encrypt path.
- `chrome.storage.onChanged` on `suspenderState` invalidates `cachedState` — external writes won't be silently overwritten.

### Encryption state machine

```
first install    → generateAndPersistDataKey() → raw key, base64, local only
set passkey      → PBKDF2-SHA256 → AES-GCM wrap → { encryptedKey, keySalt, keyIV, iterations }
worker restart   → restoreKeyFromSession() (JWK, imported NON-extractable)
                 → else import from key record
                 → else markEncryptionLocked('passkey-required' | 'corrupt-key')
unlock           → unwrapDataKey → reconcilePendingStateAfterUnlock() → re-encrypt
```

Two independent gates, and code must distinguish them:

| Gate | Set by | Meaning |
|------|--------|---------|
| **locked** | no key available | `passkey-required`, `bad-passkey`, `corrupt-key` |
| **corrupt** | key works, ciphertext doesn't | `corrupt-state` |

`stateWriteBlockedReason()` folds both; `stateIsWritable()` is its negation. A corrupt state must **never** be silently overwritten with an empty one — the only recovery is explicit `RESET_ENCRYPTION`.

**The key never leaves the device.** `persistKeyRecord`/`loadKeyRecord`/`clearKeyRecords` touch `chrome.storage.local` only. There is no escrow, no backup, no recovery path — uninstalling destroys the key and the suspended tabs with it, deliberately. `settings.js` uses an explicit allowlist rather than a spread so a settings blob migrated from `main` drops its key-escrow flags on first read instead of silently carrying them.

PBKDF2: default **600,000** iterations, floor `MIN_ITERATIONS = 150,000` enforced on wrap. Unwrap deliberately uses the record's stored count *without* the floor (old records must stay openable), then `unlockWithPasskey` transparently re-wraps at the higher count.

## Feature spec

### Suspension

Two methods, chosen by `settings.unsuspendMethod`:

| Setting | Method | Behavior |
|---------|--------|----------|
| `'manual'` | **page** | Tab navigates to `suspended.html?token=…`; user clicks to wake |
| `'activate'` | **discard** | `chrome.tabs.discard()`; Chrome auto-reloads on focus |

`suspendViaDiscard` verifies the discard **twice** — immediately, then again after 1s — because Chrome silently reloads some tabs. Either check failing falls back to page suspension. Any throw also falls back.

**Safety skips** (`getSuspendSafetySkipReason`, always enforced): missing tab, `incognito`, `chrome://`, `chrome-extension://`, or any protocol outside `http/https/file/ftp`.

**Auto-policy skips** (`shouldSuspendByAutoPolicy`, *auto flows only*): `excludeActive`, `excludePinned`, `excludeAudible`, whitelist match, idle threshold not met.

The split matters: `SUSPEND_CURRENT` (manual, one tab) applies **only** safety checks — a pinned, audible, just-touched tab still suspends when the user explicitly asks. `SUSPEND_INACTIVE` and `autoSuspendTick` apply both.

Idle time comes from `lastActiveCache[tabId] ?? tab.lastAccessed ?? now`. The cache is coalesced to `chrome.storage.session` on a 3s debounce and pruned in `autoSuspendTick` against `chrome.tabs.query({})` — **all** window types, not just `normal`, or entries for devtools/popup tabs leak forever.

`autoSuspendTick` runs 5 concurrent workers (`AUTO_SUSPEND_BATCH_LIMIT`).

### Unsuspension

Page-suspended tabs carry a `crypto.randomUUID()` token with a 24h TTL and a single-use flag. `processUnsuspendTokenMessage` is a three-phase state machine:

1. **Reserve** — validate token/TTL/unused, set `tokenUsed = true`, save. Blocks concurrent attempts.
2. **Resume** — navigate the tab. **On failure, roll `tokenUsed` back to `false`** so the user can retry.
3. **Finalize** — delete the entry, save.

All three tests in `tests/` pin this. A second use after success returns `invalid-token` (entry is gone), not `used`.

`suspended.js` degrades gracefully: if the background is locked or unreachable and `embedOriginalUrl` was on, it navigates straight to the `?url=` param — but only through `isSafeNavigationUrl`.

### Snapshots

Every 180 min, `SnapshotService.createSnapshot()` validates state against live tabs, encodes v2, encrypts, appends. Retention: 7 days **and** max 20, whichever bites first (`pruneSnapshots`). Skipped entirely if encryption is locked — never writes a plaintext fallback.

`OPEN_SNAPSHOT` opens a new window; `unsuspend: false` re-parks each tab behind a **fresh** token and dedupes against both current state and within the batch. `RESTORE_SNAPSHOT` replaces live state wholesale. Both filter through `isSafeUrl`.

`GET_SNAPSHOT_DETAILS` is backed by a 10-entry LRU (`snapshotDetailsCache`), invalidated on any snapshot mutation — it hands out **clones**, so callers can't mutate the cache.

### Favicons

The `favicon` permission exists for one thing: `captureFaviconAsDataUri` fetches `chrome.runtime.getURL('/_favicon/?pageUrl=…&size=32')` and inlines the result as a `data:` URI. Guards: 500ms `AbortController` timeout, 8KB cap, MIME allowlist, `http(s)` pages only. Failure is non-fatal — the tab suspends without an icon.

**Hard rule, enforced in five places** (`isLocalFaviconParamSafe`, `shouldEmbedFaviconParam`, `sanitizeStateFaviconUrls`, `normalizeFaviconUrl`, `isLocalFaviconUrl`): only `data:` and `chrome-extension:` favicon URLs are ever persisted, embedded in a URL, or rendered. A remote `https://` favicon URL would leak browsing history to that origin on every render of the parked page. Never relax this.

When no favicon survives, `suspended.js` generates a deterministic identicon from the token: FNV-1a hash → xorshift PRNG → mirrored 5×5 grid, with an HSL palette that enforces a 45-point lightness delta for contrast. Density is re-rolled up to 4× to land in 6–19 cells, then falls back to a fixed pattern. Same token always yields the same icon.

### Whitelist

`wildcardToRegExp` strips protocol/`www.`/trailing slash, escapes regex chars except `*`, converts `*`→`.*?` (lazy, deliberately). No `/` in the pattern ⇒ domain match `(^|\.)host(\/|$)`, so `leetcode.com` matches `sub.leetcode.com` and `leetcode.com/problems` but **not** `myleetcode.com`. With a `/` ⇒ anchored prefix match. Compiled regexes are cached keyed on the joined pattern list.

Saving settings with a non-empty whitelist fires `unsuspendWhitelistedTabs` in the background (fire-and-forget) — already-suspended matches wake automatically.

### State validation

`validateState` batch-queries all tabs once and prunes entries whose tab is gone, went incognito, has an unsafe URL, or whose real state contradicts its recorded `method` (`discard` entry on a non-discarded tab, `page` entry not on `suspended.html`).

Two schedulers, by design: the `stateValidator` alarm every 15 min is the **durable** one (survives worker suspension); `maybeScheduleValidation` is an opportunistic 250ms debounce off `GET_STATE`, throttled to 60s. That throttle is in-memory and **intentionally resets on worker restart** so a freshly-woken worker can validate immediately.

## Message API

Every UI surface talks to `background.js` through `chrome.runtime.sendMessage`. `handleMessage` returns `true` and wraps everything in an async IIFE with a `try/catch` that responds `{ ok: false, error: 'internal-error' }`.

| Type | Payload | Response |
|---|---|---|
| `GET_SETTINGS` | — | settings object (**no `ok` wrapper**) |
| `SAVE_SETTINGS` | `{ payload }` | `{ ok: true }` |
| `GET_ENCRYPTION_STATUS` | — | `{ locked, reason, usingPasskey, hasKeyRecord }` |
| `UNLOCK_WITH_PASSKEY` | `{ passkey }` | `{ ok }` \| `{ ok:false, error: 'bad-passkey' \| 'not-locked' \| 'corrupt-state' }` |
| `RETRY_IMPORT_KEY` | — | `{ ok }` \| `{ ok:false, error: 'no-plaintext-record' \| 'corrupt-key' }` |
| `SET_PASSKEY` | `{ passkey }` | `{ ok }` \| `{ ok:false, error: 'missing-passkey' \| 'locked' }` |
| `REMOVE_PASSKEY` | — | `{ ok }` \| `{ ok:false, error: 'locked' }` |
| `RESET_ENCRYPTION` | — | `{ ok: true }` |
| `SUSPEND_CURRENT` | — | `{ ok:true }` \| `{ ok:true, skipped: 'incognito' \| 'unsafe-url' \| 'policy-excluded' \| 'locked' }` |
| `SUSPEND_INACTIVE` | — | `{ ok:true }` \| `{ ok:true, skipped:'locked', reason }` |
| `RESUME_TAB` | `{ tabId }` | `{ ok:true }` \| `{ ok:false, locked:true, reason }` |
| `RESUME_ALL` | — | same as `RESUME_TAB` |
| `GET_STATE` | — | `{ ok:true, locked:false, state }` \| `{ ok:false, locked:true, reason }` |
| `SUSPENDED_VIEW_INFO` | `{ token, tabId? }` | `{ found:true, info }` \| `{ found:false }` \| `{ ok:false, locked:true, reason }` |
| `UNSUSPEND_TOKEN` | `{ token, tabId }` | `{ ok:true }` \| `{ ok:false, error: 'invalid-token' \| 'used' \| 'expired' \| 'resume-failed' }` |
| `GET_SNAPSHOTS` | — | `{ snapshots }` (**no `ok`**) \| `{ ok:false, locked:true, reason }` |
| `GET_SNAPSHOT_DETAILS` | `{ snapshotId }` | `{ ok:true, tabs }` \| `{ ok:false, error }` |
| `RESTORE_SNAPSHOT` | `{ snapshotId }` | `{ ok:true }` \| `{ ok:false, error }` |
| `OPEN_SNAPSHOT` | `{ snapshotId, unsuspend? }` | `{ ok:true, opened }` \| `{ ok:false, error:'not-found' }` \| `{ ok:false, locked:true }` |

Unknown type → `{ ok:false, error:'Unknown message' }`. Init failure → `{ ok:false, error:'initialization-failed' }`.

**Response shapes are inconsistent** — `GET_SETTINGS` and `GET_SNAPSHOTS` omit `ok`. `popup.js` normalizes via `interpretActionResult()`; reuse it rather than re-deriving the truthiness rules.

## Storage schema

**`chrome.storage.local`**

| Key | Shape |
|-----|-------|
| `settings` | see `defaultSettings` in `settings.js` |
| `suspenderState` | `{ iv, ct }` (base64url) or `{ plain: { v:2, tabs:[…] } }` |
| `backups` | `[{ id, timestamp, tabCount, data }]`, `data` encrypted like above |
| `encryptionKeyRecord` | `{ usingPasskey, dataKey? \| encryptedKey+keySalt+keyIV+iterations, keyVersion, updatedAt }` |
| `logs` | ring buffer, max 1000 |

**`chrome.storage.sync`** — **not used.** Adding a call fails `npm run verify:egress`.

**`chrome.storage.session`** (via `session.js`, in-memory fallback) — `cryptoKey` (JWK), `lastActive` (`{[tabId]: ts}`).
`pendingSuspenderState` is **legacy**: deleted on every `init()` and `onStartup`. Don't reintroduce it.

## Alarms

| Name | Period | Purpose |
|------|--------|---------|
| `autoSuspend` | `clamp(round(autoSuspendMinutes / 3), 1, 60)` min | suspension tick |
| `snapshotTimer` | 180 min | encrypted snapshot |
| `stateValidator` | 15 min | prune orphaned entries |

`init()` only creates alarms that don't already exist. `onInstalled` (both `install` and `update`) force-recreates `autoSuspend` and `snapshotTimer` but **not** `stateValidator` — that one is only ever created by `init()`. `saveSettings` always reschedules `autoSuspend`.

## Tunables

`background.js`: `TOKEN_TTL_MS` 24h · `SNAPSHOT_RETENTION_DAYS` 7 · `SNAPSHOT_MAX` 20 · `AUTO_SUSPEND_BATCH_LIMIT` 5 · `FAVICON_CAPTURE_TIMEOUT_MS` 500 · `FAVICON_MAX_BYTES` 8192 · `STATE_VALIDATION_THROTTLE_MS` 60s · `VALIDATION_DEBOUNCE_MS` 250 · `LAST_ACTIVE_FLUSH_DELAY_MS` 3000 · `SNAPSHOT_DETAILS_CACHE_LIMIT` 10
`encryption.js`: `MIN_ITERATIONS` 150000 · `KEY_VERSION` 1
`logger.js`: `MAX_LOGS` 1000 · flush at 2s or 20 entries, immediate on `error`

## Invariants

1. Event listeners registered **synchronously at module top level**; handlers `await ready` before touching state. MV3 drops late registrations.
2. All state mutation inside `withStateLock`, re-checking `stateIsWritable()` **inside** the lock.
3. `entry.method` must match reality — `'discard'` only for genuinely discarded tabs, `'page'` only for tabs on `suspended.html`.
4. Never persist incognito tab metadata.
5. Never write plaintext session state to persistent storage.
6. **Zero egress.** No synced storage, no remote request, no new permission. `npm run verify:egress` must pass; it is a release blocker, not advisory.
7. Only `data:` / `chrome-extension:` favicon URLs get stored, embedded, or rendered.
8. `.textContent` only in UI code — never `.innerHTML` with dynamic data. `target="_blank"` requires `rel="noopener noreferrer"`.
9. Corrupt state fails loudly; it is never silently replaced with an empty state.
10. `settings.encryption.enabled` is forced `true` on every merge path.

## Known gaps

Verified against source on 2026-08-06. Everything not listed here that older notes flagged (cachedState races, token reuse, plaintext key in Sync, PBKDF2 iterations, `lastActiveCache` leak, `handleMessage` error boundary, `getSnapshots` race, greedy wildcard, snapshot URL validation, duplicate open-snapshot paths, missing `.gitignore`, missing `npm test`) **is fixed** — don't re-fix it.

- **Data key is exportable.** `generateDataKey` / `importKeyBase64` / `unwrapDataKey` create it with `extractable: true` — required so `setPasskey` can re-wrap it. `restoreKeyFromSession` and `deriveWrappingKey` correctly import non-extractable.
- **Key JWK sits in `chrome.storage.session`** — readable by any code in the extension context. The price of surviving MV3 worker restarts without re-prompting.
- **No key rotation.** `keyVersion` is written but never acted on.
- **No rate limiting** on `UNLOCK_WITH_PASSKEY` attempts.
- **No `icons` in `manifest.json`** — Chrome renders the default puzzle piece.
- **`tests/` is outside the ESLint config** — `npx eslint tests` yields a bogus `structuredClone is not defined` (see Commands).
- **The `_favicon` read depends on a Chromium implementation detail** — the origin gate in `favicon_source.cc`. Not enforceable from our manifest. Documented in SECURITY.md §3 with the removal path if a deployment won't accept it.
- Inconsistent message response shapes (see Message API).

## Conventions

ES modules (`"type": "module"` in the manifest background entry) · `async`/`await` throughout · settings always spread-merged with `defaultSettings` · `Logger` writes to both `console` and `chrome.storage.local.logs` · no content scripts — everything runs through `chrome.tabs` and extension pages.

**Do not add line counts or per-function file listings to this document.** The previous revision carried both; every number was 30–70% wrong within a few commits.
