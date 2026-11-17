# Privacy Policy — NeXX (chat.nexx.app)

Last updated: 2026-11-17

NeXX is a local-first messenger client. It has **no servers of its own**: all traffic goes
through the public SimpleX Mesh relay network (SMP/XFTP) that you choose, or through your own proxy.

## Data we collect
**Nothing.** NeXX collects no analytics, no telemetry, no crash reports, no advertising IDs.
There is no account, no phone number, no email — identity is a local cryptographic seed
(Ed25519/X25519 keys derived on-device, BIP39 mnemonic for backup).

## Data stored on your device
- Contact list, message history, group list, queue keys — stored **only on your device**,
  encrypted at rest (AES-256-GCM, keys derived from your seed via HKDF).
- `allowBackup="false"`, `fullBackupContent="false"`, data-extraction rules exclude key material —
  nothing is uploaded to Google backup or extracted to the cloud.
- App does not use `usesCleartextTraffic`; all relay connections are TLS 1.3 with certificate pinning
  (SHA-256 of CA SPKI, constant-time compare, channel binding to the TLS Finished hash).

## Data transmitted
- Messages/files go **end-to-end encrypted** to your peers via SMP/XFTP relays. Relays see only
  encrypted envelopes and connection metadata (IP, timing) — same threat model as SimpleX Chat.
- If you enable the local proxy (SOCKS5/Xray), other apps' traffic routes through **your chosen**
  proxy server; NeXX itself never sends traffic anywhere except the relays/proxy you configured.

## Permissions
- **Internet** — relay/proxy connections.
- **Storage/files** — only for files you explicitly send/receive (XFTP).
- No camera, no microphone, no contacts, no SMS, no accessibility service, no input-method (IME) service.
  The in-app keyboard is a plain UI component inside the app; it never leaves the app process.

## Third parties
- SimpleX Mesh public relays (simplex.im) — only if you use them; you can run your own.
- Your proxy provider (Shadowsocks/VLESS/VMess/Trojan/WireGuard/Xray) — only if you configure one.

## Children
NeXX is not directed at children under 13.

## Changes
This policy is versioned in the repository (`PRIVACY.md`). Material changes will be announced in release notes.

## Contact
Issues: GitHub repository of the project (see README).
