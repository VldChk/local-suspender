# Local Suspender

Privacy-first Chrome extension that suspends inactive tabs to free memory and CPU. All data stays on your device with AES-256-GCM encryption.

## Features

- Automatically suspends tabs after a configurable idle period
- Two suspension methods: native tab discard or a parked page
- AES-256-GCM encryption of session state with optional passkey protection
- Encrypted session snapshots for tab recovery
- Whitelist patterns to exclude specific sites
- Passkey-wrapped cloud key backup via Chrome Sync (optional)
- Zero network calls, zero external dependencies
- Manifest V3, vanilla JavaScript

## Install from source

1. Clone this repository
2. Open `chrome://extensions` and enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` directory

## Package for distribution

```bash
npm install
npm run package
```

This creates `dist/local-suspender-<version>.zip`.

## Project structure

```
extension/
  background.js     Service worker (core logic, encryption, state)
  encryption.js     AES-256-GCM key management and wrapping
  settings.js       Settings schema and persistence
  session.js        chrome.storage.session wrapper
  logger.js         Structured logging to storage
  popup.html/js/css Toolbar popup UI
  options.html/js/css Options page UI
  suspended.html/js/css Parked tab page
  manifest.json     Chrome extension manifest (MV3)
scripts/
  package-extension.mjs  Packaging script
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Auto-suspend after | 30 min | Idle threshold before suspension |
| Exclude active tab | Yes | Never suspend the focused tab |
| Exclude pinned tabs | Yes | Never suspend pinned tabs |
| Exclude audible tabs | Yes | Never suspend tabs playing audio |
| Unsuspend method | On focus | Auto-restore when tab is activated |
| Whitelist | Empty | URL patterns to never suspend |
| Cloud key backup | Off | Sync passkey-wrapped encryption key via Chrome Sync |

## License

[MIT](LICENSE)
