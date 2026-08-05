# Security Model — Absolutely-Local Build

This branch (`absolutely-local`) exists to make one claim auditable:

> **The extension originates no network communication and transmits no data to any remote
> party. It has no telemetry, no analytics, no cloud sync, and no key escrow.**

That wording is deliberate. A blanket "zero bytes ever cross the network" claim is
falsifiable in one line — see §2.1 — and we would rather state the boundary precisely than
have a reviewer find the exception themselves.

This document states what is enforced, how to verify it independently, and — just as
importantly — what is *not* guaranteed. Nothing below asks you to trust a promise; every
claim has a command you can run yourself.

---

## 0. Scope of the claim

**In scope — the extension never does these:**
- Contact any server operated by us or any third party
- Replicate data through Chrome Sync or any other off-device storage
- Send browsing history, tab URLs, titles, favicons, timings, or key material anywhere
- Load remote scripts, styles, fonts, or images

**Explicitly out of scope — normal browsing:**
Restoring a suspended tab navigates that tab to the URL you were already on. That
navigation is a network request, made by the browser, to a site *you* chose to visit. It
carries no data the extension added. This is the product's entire function; an extension
that could not do it would be useless.

The relevant control is that the destination is always the exact URL previously recorded
for that tab. It is validated against a scheme allowlist (`http`, `https`, `file`, `ftp`)
in `isSafeUrl()` before any navigation, so a corrupted or crafted state entry cannot
redirect a tab to an attacker-chosen scheme.

A reviewer assessing "can this extension exfiltrate?" should treat tab navigation as the
one channel that exists by design, and confirm — as we have — that nothing writes
attacker- or extension-controlled data into the destination URL.

---

## 1. How to verify in five minutes

```bash
npm ci
npm run verify:egress     # release-blocking egress gate
npm run lint
npm test
```

Then, independent of our tooling:

```bash
# No network primitives anywhere in shipped code
grep -rnE 'XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts' extension/

# No synced (cloud-replicated) storage
grep -rn 'storage\.sync' extension/

# Every fetch() in the codebase
grep -rn 'fetch(' extension/
```

Expected: the first two return nothing. The third returns exactly one line — see §3.

`npm run package` runs the egress gate first and **refuses to build** if it fails.

---

## 2. Three independent layers

The guarantee does not rest on any single mechanism.

| Layer | Mechanism | Enforced by |
|---|---|---|
| Source | `scripts/verify-no-egress.mjs`, wired into `npm run package` | Build fails |
| Manifest | `connect-src 'self'; img-src 'self' data:` | Chrome, at runtime |
| Privilege | No `host_permissions`, no content scripts, no `externally_connectable` | Chrome, at install |

`connect-src 'self'` is the load-bearing one: it makes remote `fetch`/XHR/WebSocket
**structurally impossible** for extension pages and the service worker, regardless of what
the JavaScript attempts. `img-src 'self' data:` likewise prevents a stored favicon from
ever causing a remote image load. `default-src 'none'` makes the policy fail closed for
anything not enumerated.

The gate compares each CSP directive against an **exact** source list, not a substring — a
substring check would accept `connect-src 'self' https:` as satisfying `connect-src 'self'`.
Undeclared and duplicated directives also fail.

### 2.1 What the gate does and does not prove

The gate is a **regression barrier, not a sandbox.** It reads source text, so it catches
honest spellings: a newly added `fetch`, an `XMLHttpRequest`, a reintroduced
`chrome.storage.sync`, a widened CSP, an added permission. That is what it is for — stopping
an ordinary change from quietly undoing this work.

It does **not** defeat deliberate obfuscation. `window['fet'+'ch']`, a computed property, or
a base64-decoded identifier will pass it. We consider this acceptable because the gate is not
the security boundary:

- **CSP is**, and it is enforced by Chrome at runtime against the resolved request,
  regardless of how the call was spelled in source.
- The absence of `host_permissions` means Chrome will not grant cross-origin access even if
  a request were constructed.

So an attacker who can already commit obfuscated JavaScript into this repository is inside
the trust boundary — but still cannot open a remote connection. Treat the gate as defence in
depth over CSP, not as the guarantee.

---

## 3. The one permitted network-shaped call

```js
// extension/background.js — captureFaviconAsDataUri()
const response = await fetch(faviconUrl, { signal: controller.signal });
```

`faviconUrl` is always `chrome-extension://<this-extension-id>/_favicon/?pageUrl=…`. It is
**same-origin** and never touches a socket. It reads Chrome's own favicon database — a file
in the local profile, populated when the user visited the site, independent of this
extension. The bytes are converted to a `data:` URI, stored inside the encrypted state, and
served locally from then on.

This exact source line is pinned in `ALLOWED_FETCH_LINES`. Editing it — not merely adding a
new call — fails the gate, so any change surfaces in review.

**Why this cannot reach Google's favicon server.** Chromium gates server-side favicon
fallback on the *calling origin*:

```cpp
// chrome/browser/ui/webui/favicon_source.cc
if (!(parsed.allow_favicon_server_fallback &&
      IsOriginAllowedServerFallback(GetUnsafeRequestOrigin(wc_getter))))
```

`IsOriginAllowedServerFallback()` permits only `chrome://history`, `chrome://newtab`, and
`chrome-untrusted://data-sharing`. **`chrome-extension://` is not on that list**, so an
extension origin cannot trigger the fallback even if the flag were set.

**Residual risk, stated plainly.** This is a Chromium implementation detail. It is not
enforced by our manifest and could in principle change in a future Chrome release. Chrome's
public extension documentation does not state the network behaviour of `_favicon` either
way; the source above is the authoritative reference. A deployment that will not accept
*any* dependency on browser internals should remove the `favicon` permission and the
`captureFaviconAsDataUri` function — the parked-tab page already falls back to a
deterministic locally-generated identicon, so nothing else breaks.

---

## 4. Key management

- A 256-bit AES-GCM key is generated **on this device** at install, via `crypto.subtle`.
- It is stored only in `chrome.storage.local`. It is never transmitted, escrowed, or synced.
- An optional passkey wraps the key with PBKDF2-SHA256 (600,000 iterations, 150,000 floor,
  16-byte salt). The passkey itself is never stored.
- Uninstalling the extension destroys the key. Suspended tabs become unrecoverable. This is
  an accepted, deliberate trade.

**Important — the passkey is the meaningful control.** With no passkey set, the data key
sits in `chrome.storage.local` alongside the ciphertext it decrypts. Encryption then defends
against an attacker who obtains the state blob alone, **not** against one who can read the
whole extension profile directory. Deployments relying on encryption-at-rest to resist local
disk access or endpoint agents **must set a passkey**.

### Migrating from the cloud-backup build — action required

Removing the sync code does **not** remove data already synced. Anyone who previously ran a
build with cloud backup enabled has an `encryptionKeyRecord` sitting in Google's
infrastructure. This build cannot delete it, because it contains no synced-storage code by
design.

Before installing this build, on the previous build:

1. Open its options page and disable cloud backup, **or** use **Reset encrypted data**.
2. Confirm removal at `chrome://sync-internals` under the Extension Settings data type.

For clean deployments — a fresh profile, or a device that never ran the cloud-backup build —
no action is needed and nothing was ever synced.

---

## 5. Permissions, and why each is needed

| Permission | Justification | Grants network access? |
|---|---|---|
| `tabs` | Read tab URL/title to suspend and restore | No |
| `storage` | Local storage of encrypted state and settings | No |
| `alarms` | Periodic suspension, snapshot, validation timers | No |
| `idle` | Suspend when the machine goes idle | No |
| `favicon` | Read the local favicon database (§3) | No — same-origin only |

No `host_permissions`. No content scripts — the extension never injects code into, or reads
the DOM of, any web page. No `externally_connectable` — no other extension or website can
message it.

---

## 6. Known limitations

Disclosed so a reviewer does not have to find them.

- **Data key is exportable.** `extractable: true` is required so a passkey can re-wrap it.
  The session copy is imported non-extractable.
- **Key JWK is held in `chrome.storage.session`** to survive MV3 service-worker restarts
  without re-prompting. Readable by code running in the extension context; cleared when the
  browser closes.
- **No key rotation.** `keyVersion` is recorded but no rotation mechanism exists.
- **No rate limiting** on passkey unlock attempts. PBKDF2 at 600k iterations is the only
  brute-force cost.
- **Favicons and titles are stored** in the encrypted state. They are browsing-history
  derived data. They never leave the device, but they are present in local storage.
- **No signed release artifact.** Builds are reproducible via `npm run package`; verify by
  rebuilding and comparing rather than by trusting a published zip.

---

## 7. Reporting

Open a private security advisory on the repository. Please include the Chrome version and
whether the build was installed fresh or migrated from a cloud-backup build.
