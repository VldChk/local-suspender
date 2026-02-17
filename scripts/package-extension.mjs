import { createWriteStream } from 'node:fs';
import { mkdir, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yazl from 'yazl';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const extensionDir = path.join(rootDir, 'extension');
const manifestPath = path.join(extensionDir, 'manifest.json');
const distDir = path.join(rootDir, 'dist');

async function ensureExtensionDir() {
  await stat(extensionDir);
}

function sanitizeName(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'extension';
}

async function createArchive(manifest) {
  const version = manifest.version;
  if (!version) {
    throw new Error('manifest.json is missing a version field.');
  }
  const baseName = sanitizeName(manifest.name || 'local-suspender');
  const archiveName = `${baseName}-${version}.zip`;
  await mkdir(distDir, { recursive: true });
  const archivePath = path.join(distDir, archiveName);

  console.log(`Packaging ${manifest.name} v${version}`);

  const files = await listFiles(extensionDir);

  await new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    const output = createWriteStream(archivePath);
    output.on('close', resolve);
    output.on('error', reject);

    zipfile.outputStream.pipe(output).on('error', reject);
    for (const file of files) {
      zipfile.addFile(file.absPath, file.zipPath);
    }
    zipfile.end();
  });

  console.log(`Created ${path.relative(rootDir, archivePath)}`);
}

async function listFiles(directory, root = directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(absPath, root)));
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    const zipPath = path.relative(root, absPath).split(path.sep).join('/');
    files.push({ absPath, zipPath });
  }
  files.sort((a, b) => a.zipPath.localeCompare(b.zipPath));
  return files;
}

async function main() {
  try {
    await ensureExtensionDir();
    const manifestRaw = await readFile(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestRaw);
    await createArchive(manifest);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

main();
