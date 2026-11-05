# Authenticator Skill — Two-Factor Authentication (2FA / TOTP) for AI Agents

## Purpose

Hold the user's two-factor authentication seeds locally and generate the
rotating codes on demand, so sign-ins the agent runs for the user don't
stall waiting for the user to read a code off their authenticator app —
and so the user never has to paste a fresh code for every login.

Jobs: `add` (enroll once from a seed, an otpauth:// URI, or a QR image),
`import` (bulk import from QR photos and export files), `code` (current
code for an account), `list`, `remove`, `status`.

## Tooling

All work goes through the checked-in CLI. Pure Python standard library
for the OTP math (RFC 4226 HOTP / RFC 6238 TOTP); QR decoding uses
Pillow + zxing-cpp (`pip install --user pillow zxing-cpp`).

```sh
A=/path/to/authenticator/bin/auth.py

# Enroll (once per account) — any of:
python3 $A add github --seed <BASE32_SETUP_KEY> --issuer GitHub --account <account-name>
python3 $A add github --uri 'otpauth://totp/GitHub:<account>?secret=...&issuer=GitHub&digits=6&period=30'
python3 $A add github --qr ~/path/to/enrollment-qr.png

# User-friendly import — no label needed, auto-labelled. Accepts a photo /
# screenshot the user uploads in chat, a single otpauth QR, AND a Google
# Authenticator migration QR (otpauth-migration:// — the "transfer
# accounts" export), which imports every account in the batch at once:
python3 $A import --qr ~/path/to/qr-photo.jpg [more-photos...]
python3 $A import --uri 'otpauth-migration://offline?data=...'
python3 $A import --file ~/path/to/export.json   # see compatibility below

# Use
python3 $A code github [--json]      # current code + seconds remaining
python3 $A list [--json]             # labels/issuers only — never seeds
python3 $A remove github
python3 $A status [--json]           # store location, permissions, count
```

## Compatibility — every 2FA app, honestly

Codes themselves are open standards (RFC 4226 HOTP / RFC 6238 TOTP), so
any seed this skill can obtain generates identical codes in any app.
What differs per app is whether the app will LET the seeds out:

Direct import supported (`import --qr` / `--uri` / `--file`):
- **Google Authenticator** — Transfer-accounts migration QR photo ✅ (proven live: 5 accounts in one photo); also single otpauth QRs.
- **andOTP, FreeOTP+** — plain JSON backup ✅
- **Aegis** — plain-text JSON vault export ✅ (encrypted vault: detected, refused with instructions to re-export plain)
- **2FAS** — plain (.2fas / JSON) backup ✅ (password-protected backup: detected, refused likewise)
- **Bitwarden (incl. Bitwarden Authenticator)** — vault JSON or CSV, `totp` field ✅
- **Ente Auth, Raivo** — plain-text otpauth:// URI list ✅
- **Proton Authenticator / Proton Pass** — JSON export with otpauth URIs ✅
- **KeePassXC** — CSV export with TOTP seed column ✅ (basic)
- **Steam Guard** — `steam://` links and maFile JSON (base64 shared_secret); codes are the 5-char Steam alphabet ✅
- Any single enrollment QR / otpauth:// URI / base32, base64 or hex seed from any service ✅; SHA1/SHA256/SHA512/MD5, 6/7/8 digits, custom periods, HOTP counters.

No export path exists (vendor lock-in — not a skill limitation):
- **Microsoft Authenticator** — no export at all; cloud backup restores only into Microsoft Authenticator, same platform. Microsoft-account entries are also proprietary push, not TOTP. Workaround: per-service re-enrollment (disable 2FA, re-enable, capture the setup QR/photo into BOTH the phone app and this store). Third-party TOTP entries inside it came from standard QRs originally — re-enroll those the same way.
- **Authy (Twilio)** — no export; encrypted cloud sync only. Authy-API tokens (7-digit) are proprietary. Workaround: per-service re-enrollment; community authy-export URI lists, if a user produces one, import fine as a text file.
- **Duo Mobile, Okta Verify, Salesforce Authenticator** — managed/push accounts are device-bound and proprietary; third-party TOTP entries re-enroll per service.
- **Yubico Authenticator** — seeds live on the YubiKey hardware by design and cannot be extracted.
- **RSA SecurID** — proprietary token format/algorithm, not RFC TOTP.

Encrypted exports in general: the skill detects them and says exactly
which plain re-export to make instead of failing silently or guessing
a password.

## Storage

- Seeds live in `~/.authenticator/seeds.json` — the user's home
  directory, so the store survives environment redeployments.
  Directory 0700, file 0600.
- `AUTHENTICATOR_HOME` env var overrides the store dir (tests only).

## Rules

- A seed is a credential. Never print it, echo it, put it in chat,
  memory, logs, or any file other than the store. `list`/`code` output
  never contains seeds; keep it that way.
- Enroll only from what the user provides: a setup key, an otpauth://
  URI, or a QR image the user uploads. If the user pastes a seed in
  chat, store it and note once that chat-pasted seeds should be treated
  as rotation candidates.
- **Generate a code only as part of a sign-in the user has authorized**
  (a browser task the user asked for, a login the user approved).
  Having the codes is not standing permission to sign in anywhere new.
  When a code will be used somewhere new, get the user's explicit
  approval for that sign-in first — the same exact-approval standard
  that applies to sending messages or making purchases on their behalf.
- Migration note: authenticator apps don't export seeds individually.
  For an existing account, the user re-enrolls 2FA once and captures
  the same setup key/QR into BOTH their phone and this store, so both
  keep working. For new accounts, save the key in both places at setup.
  Exception: Google Authenticator's own "Transfer accounts" export QR
  (otpauth-migration://) DOES carry the seeds — `import` decodes it
  (stdlib protobuf parsing) and enrolls the whole batch in one photo.
- HOTP (counter) accounts: each `code` call consumes one counter
  value and persists the increment; don't call it speculatively.

## Tests

`tests/run_tests.sh` — RFC 6238 vectors (SHA1/SHA256/SHA512/MD5 path),
seed / URI / QR intake, Google migration import, universal file imports
(andOTP, Aegis, 2FAS, Bitwarden JSON+CSV, Ente text, Steam maFile),
encrypted-export refusal, list hygiene, permissions, remove.
