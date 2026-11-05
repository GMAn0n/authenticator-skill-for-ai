# 2FA Authenticator Skill for AI — Two-Factor Authentication (TOTP / HOTP) for AI Agents

**Give your AI agent two-factor authentication.** This skill lets an AI
agent — Muse, Grok, ChatGPT, Claude, Gemini, Claude Code, Cursor, or
any assistant with shell and file access — hold your 2FA seeds locally
and generate TOTP / HOTP codes on demand, so sign-ins stop stalling on
"please read the 6-digit code off your phone."

Codes are open standards (RFC 4226 HOTP, RFC 6238 TOTP). This skill is
the missing plumbing: one small, dependency-light Python CLI that
imports your accounts from almost any authenticator app and generates
identical codes locally.

🌐 **Live site:** https://gman0n.github.io/authenticator-skill-for-ai/
📖 **Other AI agents:** see [INSTALL-OTHER-AGENTS.md](INSTALL-OTHER-AGENTS.md)

## What it does

- **Generate 2FA codes locally** — TOTP and HOTP, SHA1 / SHA256 /
  SHA512 / MD5, 6 / 7 / 8 digits, custom periods, HOTP counters, plus
  Steam Guard's 5-character codes.
- **Import from a photo** — send the agent a picture of an enrollment
  QR or a Google Authenticator "Transfer accounts" migration QR
  (`otpauth-migration://`) and every account in the batch enrolls at
  once. No re-typing seeds.
- **Import from export files** — andOTP, Aegis, 2FAS, Bitwarden,
  Ente Auth, Raivo, Proton, KeePassXC, FreeOTP+, Steam maFiles
  (details in the compatibility table below).
- **Accept every seed format** — `otpauth://` and `steam://` URIs,
  base32, base64, and hex setup keys.
- **Stay honest about encrypted exports** — password-protected Aegis /
  2FAS / andOTP backups are detected and refused with the exact plain
  re-export to make, instead of failing silently.

## Compatibility

| Source app | Import path | Status |
|---|---|---|
| Google Authenticator | Migration QR photo (`import --qr`) or single otpauth QR | ✅ Direct |
| andOTP, FreeOTP+ | Plain JSON backup (`import --file`) | ✅ Direct |
| Aegis | Plain-text JSON vault export | ✅ Direct (encrypted vault → re-export plain) |
| 2FAS | Plain `.2fas` / JSON backup | ✅ Direct (password-protected → re-export plain) |
| Bitwarden / Bitwarden Authenticator | Vault JSON or CSV (`totp` field) | ✅ Direct |
| Ente Auth, Raivo | Plain-text otpauth:// URI list | ✅ Direct |
| Proton Authenticator / Proton Pass | JSON export | ✅ Direct |
| KeePassXC | CSV export (TOTP seed column) | ✅ Direct (basic) |
| Steam Guard | `steam://` link or maFile JSON | ✅ Direct |
| Any service's enrollment QR / setup key | QR photo, otpauth:// URI, base32/base64/hex seed | ✅ Direct |
| Microsoft Authenticator | **No export exists** | ⚠️ Locked in — re-enroll each service (below) |
| Authy (Twilio) | **No export exists** | ⚠️ Locked in — re-enroll each service |
| Duo Mobile, Okta Verify, Salesforce Authenticator | Push accounts are device-bound | ⚠️ Locked in — re-enroll third-party TOTP entries |
| Yubico Authenticator | Seeds live on the YubiKey by design | ⚠️ Cannot be extracted |
| RSA SecurID | Proprietary format, not RFC TOTP | ❌ Not TOTP |

**Locked-in apps are a vendor limit, not a skill limit.** The
workaround is the same for all of them: at each service, disable 2FA
and re-enable it, capturing the new setup QR into **both** your phone
app and this skill's store. From then on both generate identical
codes. (Microsoft-account entries in Microsoft Authenticator are
proprietary push sign-in, not TOTP at all — those stay in Microsoft
Authenticator.)

## Install in 3 steps

1. **Copy the skill folder** into your agent's skills directory (for
   Muse: your workspace skills folder), or anywhere your agent can
   read files and run shell commands:

   ```sh
   cp -r authenticator/ <your-agent-skills-dir>/authenticator
   ```

2. **Install the QR decoder** (only needed for QR photo intake; seed,
   URI, and file imports are pure standard library):

   ```sh
   pip install --user pillow zxing-cpp
   ```

3. **Enroll your first account** — a Google Authenticator transfer QR
   photo does your whole authenticator in one shot:

   ```sh
   A=<your-agent-skills-dir>/authenticator/bin/auth.py
   python3 $A import --qr ~/transfer-qr-photo.jpg
   python3 $A list
   python3 $A code github        # current code + seconds remaining
   ```

Run the test suite any time with `authenticator/tests/run_tests.sh`
(RFC 6238 vectors, every import format, encrypted-export refusal,
permissions, seed-leak checks).

Using Grok, ChatGPT, Gemini, Claude Code, Cursor or another agent?
[INSTALL-OTHER-AGENTS.md](INSTALL-OTHER-AGENTS.md) has a
copy-paste setup for each — there is no native skills system on most
platforms, but any agent with shell + file access can run this CLI.

## Security model

- **Seeds are credentials and are treated like them.** They live only
  in `~/.authenticator/seeds.json`, in your home directory (so the
  store survives redeployments), with directory permissions `0700`
  and file permissions `0600`.
- **No command ever prints a seed.** `list`, `code`, and `status`
  output labels, issuers, and codes only — this is covered by the
  test suite.
- **Codes are computed locally.** The OTP math is the Python standard
  library (RFC 4226 / RFC 6238). Nothing is sent to a server.
- **Consent rule built into the skill:** the agent generates a code
  only for a sign-in the user has authorized. Holding the codes is
  not standing permission to sign in anywhere new.
- **Trade-off to know:** storing seeds where your agent can reach
  them concentrates password + 2FA in one stack — the same model as
  1Password holding both. Do it deliberately, protect the host, and
  treat any seed pasted into a chat as a rotation candidate.

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 Sam Clark.

## Keywords

two-factor authentication, 2FA, TOTP, HOTP, authenticator app,
one-time password, OTP, Google Authenticator migration, AI agents,
Muse skills, Grok, xAI, ChatGPT, OpenAI, Claude, Anthropic, Gemini,
Google, agent skills, sign-in automation, Steam Guard.
