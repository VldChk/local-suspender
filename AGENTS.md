# Local Suspender - AGENTS Guide

## 1. Purpose
This file defines how maintainers and coding agents should work in this repository.

Primary goals:
1. Keep suspension and recovery behavior reliable.
2. Preserve privacy and encryption guarantees.
3. Prevent legacy branding regressions.
4. Keep release artifacts reproducible and aligned with source.

## 2. Architecture Snapshot
1. Platform: Chrome Extension (Manifest V3, ES modules).
2. Runtime root: `extension/background.js` service worker.
3. Storage:
`chrome.storage.local` for settings, encrypted state, snapshots, logs.
`chrome.storage.sync` for optional passkey-wrapped key record backup.
`chrome.storage.session` for runtime key/session buffers.

Core modules:
1. `extension/background.js`
2. `extension/encryption.js`
3. `extension/settings.js`
4. `extension/session.js`
5. `extension/logger.js`

## 3. Contracts and Invariants
1. Event listeners in the service worker must remain registered synchronously at module load.
2. All state writes must follow lock-safe paths (`withStateLock` + reconciliation ordering).
3. `suspendedTabs[tabId].method` must match behavior:
`discard` only for real discarded tabs.
`page` only for parked-page tabs.
4. Do not persist incognito tab metadata.
5. No plaintext session history may be written to persistent storage.
6. Cloud backup is allowed only for passkey-wrapped key records.

## 4. Security and Privacy Rules
1. Do not introduce background network calls unless explicitly required and documented.
2. Do not use `innerHTML` with untrusted content.
3. Any `target="_blank"` link must also include `rel="noopener noreferrer"`.
4. Corrupt encrypted-state scenarios must fail safely without implicit destructive overwrite.

## 5. Message API Expectations
Required message semantics:
1. `GET_STATE` must return `reason: 'corrupt-state'` when stored encrypted state is unreadable.
2. `SET_CLOUD_BACKUP` must return deterministic policy failures:
`{ ok: false, error: 'passkey-required' }` when enabling without passkey wrapping.
3. `SUSPEND_CURRENT` may return skip outcomes:
`{ ok: true, skipped: 'incognito' | 'unsafe-url' | 'policy-excluded' }`.
4. `GET_ENCRYPTION_STATUS` must include:
`syncEligible` and `syncBlockedReason`.

## 6. Rebrand Guardrails
Forbidden legacy upstream branding in tracked files and release artifacts:
1. Old concatenated extension-name variant.
2. Old spaced extension-name variant.
3. Old upstream organization/name variant.

Mandatory scan before merge and release:
`rg -n -i "t[h]eg[r]eats[u]spender|t[h]e[- ]?g[r]eat[- ]?s[u]spender|g[r]eats[u]spender" . --hidden -uu --glob '!.git/**'`

## 7. Required Local Validation
Run all of the following before release:
1. `npm ci`
2. `npm run lint`
3. `npm audit`
4. `npm run package`
5. Verify archive content includes runtime modules:
`background.js`, `encryption.js`, `settings.js`, `session.js`, `logger.js`.

## 8. Release Checklist
1. Confirm branding is `Local Suspender` and slug is `local-suspender`.
2. Remove stale dist artifacts and rebuild package.
3. Verify no legacy-name hits in source or packaged output.
4. Confirm cloud-backup policy and lock/corrupt-state flows manually in Chrome.

## 9. No-Regression Checklist
1. Snapshot restore/open writes correct method metadata.
2. Locked parked-page flow still allows safe fallback URL navigation.
3. Retry buttons in snapshot details trigger actual refetch without collapsing.
4. Popup and options handle message failures defensively.
5. No missing static asset references remain in extension pages.
