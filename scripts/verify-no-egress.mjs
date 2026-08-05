/**
 * Egress gate for the absolutely-local build.
 *
 * This is a release blocker, not a linter. `npm run package` runs it first, so a
 * change that reintroduces network access cannot be shipped. A reviewer can run
 * `npm run verify:egress` and get a deterministic pass/fail without reading code.
 *
 * The one permitted network-shaped call is the same-origin favicon read, which is
 * pinned by exact source line below. Any other fetch — including an edit to that
 * line — fails the gate and must be justified by updating this file in the diff.
 */
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const extensionDir = path.join(rootDir, 'extension');

// Primitives that can move bytes off this device. None may appear anywhere.
const FORBIDDEN = [
  { pattern: /\bXMLHttpRequest\b/, why: 'XHR can reach any origin' },
  { pattern: /\bWebSocket\b/, why: 'WebSocket is a persistent remote channel' },
  { pattern: /\bEventSource\b/, why: 'EventSource is a remote stream' },
  { pattern: /\bsendBeacon\b/, why: 'sendBeacon is fire-and-forget exfiltration' },
  { pattern: /\bimportScripts\b/, why: 'importScripts can load remote code' },
  { pattern: /chrome\.storage\.sync/, why: 'sync storage replicates to Google servers' },
  { pattern: /\bnavigator\.sendBeacon\b/, why: 'sendBeacon is fire-and-forget exfiltration' },
  { pattern: /\beval\s*\(/, why: 'eval can execute injected code' },
  { pattern: /new\s+Function\s*\(/, why: 'Function constructor can execute injected code' },
];

// Exact source lines allowed to contain `fetch(`. Pinned verbatim so that editing
// the call — not just adding a new one — trips the gate.
const ALLOWED_FETCH_LINES = new Set([
  'const response = await fetch(faviconUrl, { signal: controller.signal });',
]);

// Remote URL literals allowed in JS. XML namespaces are identifiers, never dereferenced.
const ALLOWED_URL_LITERALS = new Set(['http://www.w3.org/2000/svg']);

const EXPECTED_PERMISSIONS = ['tabs', 'storage', 'alarms', 'idle', 'favicon'];

// Exact source lists, not substrings. A substring check accepts
// `connect-src 'self' https:` as satisfying `connect-src 'self'` — which would let a
// policy that permits every HTTPS origin pass a gate whose whole purpose is
// forbidding exactly that.
const EXPECTED_CSP = {
  'default-src': ["'none'"],
  'script-src': ["'self'"],
  'object-src': ["'none'"],
  'connect-src': ["'self'"], // same-origin only: permits the favicon read, blocks all remote
  'img-src': ["'self'", 'data:'],
  'style-src': ["'self'"],
  'font-src': ["'self'"],
  'media-src': ["'none'"],
  'frame-src': ["'none'"],
  'child-src': ["'none'"],
  'worker-src': ["'self'"],
  'base-uri': ["'none'"],
  'form-action': ["'none'"],
};

const failures = [];

async function listFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await listFiles(abs)));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function checkSource(rel, text) {
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    const at = `${rel}:${i + 1}`;
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return; // comments are prose

    for (const { pattern, why } of FORBIDDEN) {
      if (pattern.test(line)) failures.push(`${at}  forbidden: ${pattern.source} — ${why}`);
    }

    if (/\bfetch\s*\(/.test(line) && !ALLOWED_FETCH_LINES.has(trimmed)) {
      failures.push(`${at}  unapproved fetch() — pin it in ALLOWED_FETCH_LINES with justification:\n      ${trimmed}`);
    }

    for (const m of line.matchAll(/https?:\/\/[^\s'"`)]+/g)) {
      if (!ALLOWED_URL_LITERALS.has(m[0])) {
        failures.push(`${at}  remote URL literal: ${m[0]}`);
      }
    }
  });
}

const files = await listFiles(extensionDir);

for (const abs of files) {
  const rel = path.relative(rootDir, abs);
  if (!/\.(js|html|css)$/.test(abs)) continue;
  checkSource(rel, await readFile(abs, 'utf8'));
}

// --- manifest: least privilege + enforced CSP ---
const manifest = JSON.parse(await readFile(path.join(extensionDir, 'manifest.json'), 'utf8'));

const perms = manifest.permissions || [];
const extra = perms.filter(p => !EXPECTED_PERMISSIONS.includes(p));
if (extra.length) failures.push(`manifest.json  unexpected permissions: ${extra.join(', ')}`);
if (manifest.host_permissions?.length) {
  failures.push(`manifest.json  host_permissions must be empty, found: ${manifest.host_permissions.join(', ')}`);
}
if (manifest.content_scripts?.length) {
  failures.push('manifest.json  content_scripts must be absent (no page injection)');
}
if (manifest.externally_connectable) {
  failures.push('manifest.json  externally_connectable must be absent');
}

const csp = manifest.content_security_policy?.extension_pages || '';
if (!csp) {
  failures.push('manifest.json  extension_pages CSP is missing');
} else {
  const seen = new Map();
  for (const chunk of csp.split(';')) {
    const tokens = chunk.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens.shift().toLowerCase();
    // Duplicates matter: browsers honour the first, a reader usually reads the last.
    if (seen.has(name)) failures.push(`manifest.json  CSP declares '${name}' more than once`);
    seen.set(name, tokens);
  }

  for (const [name, expected] of Object.entries(EXPECTED_CSP)) {
    const actual = seen.get(name);
    if (!actual) {
      failures.push(`manifest.json  CSP missing directive: ${name} ${expected.join(' ')}`);
    } else if (actual.join(' ') !== expected.join(' ')) {
      failures.push(`manifest.json  CSP '${name}' must be exactly [${expected.join(' ')}], found [${actual.join(' ')}]`);
    }
  }

  for (const name of seen.keys()) {
    if (!(name in EXPECTED_CSP)) {
      failures.push(`manifest.json  CSP has undeclared directive '${name}' — add it to EXPECTED_CSP with justification`);
    }
  }
}

if (failures.length) {
  console.error(`\n  EGRESS GATE FAILED — ${failures.length} violation(s)\n`);
  for (const f of failures) console.error(`   ${f}`);
  console.error('');
  process.exit(1);
}

console.log(`  Egress gate passed — ${files.length} files scanned.`);
console.log(`  permissions: ${perms.join(', ')}`);
console.log('  network primitives: none (1 pinned same-origin favicon read)');
console.log("  CSP: connect-src 'self' — remote fetch/XHR/WebSocket structurally blocked");
