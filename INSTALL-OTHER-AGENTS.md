# Installing the 2FA Authenticator Skill on Other AI Agents

This skill is, at its core, **one Python CLI** (`authenticator/bin/auth.py`)
plus a short instruction file (`authenticator/SKILL.md`). There is no
server, no API key, and no platform SDK. That is deliberate:

> **Any AI agent that can read files and run shell commands can use
> this skill.** Platforms with a native skills system load it
> natively; platforms without one just need the folder on disk and a
> short prompt snippet (provided below, ready to paste).

What each agent needs:

- Python 3 on the machine it runs shell commands on.
- `pip install --user pillow zxing-cpp` — only for scanning QR photos.
  Seed, URI, and export-file imports are pure standard library.
- A persistent home directory, so `~/.authenticator/seeds.json`
  (directory `0700`, file `0600`) survives between sessions.

---

## Muse (native skills)

Muse loads skills from the workspace skills directory natively.

1. Copy the `authenticator/` folder into your Muse workspace skills
   directory.
2. That's it — Muse picks up `SKILL.md` / `skill.yaml` and will use
   the CLI when a sign-in needs a 2FA code or you ask to enroll,
   import, list, or get a code.

## Grok (xAI) and ChatGPT (OpenAI)

Neither Grok nor ChatGPT has a native third-party skills system, so
don't look for an "install skill" button. The equivalent setup:

1. Give the agent a working environment with **shell + file access**
   (for example a code-interpreter / workspace session, a connected
   computer, or your own agent harness around the model).
2. Copy the `authenticator/` folder into that environment.
3. Paste the system-prompt snippet below into the agent's system
   prompt / custom instructions / project instructions.

The agent then runs the exact same CLI. Without shell access the
model can *describe* the skill but cannot hold seeds or generate
codes — the snippet is honest about that on purpose.

## Gemini (Google)

Same pattern as Grok / ChatGPT: no native skills system. Use Gemini
in an environment that gives it file + shell access (an agent
framework, a connected workspace, or your own harness), drop in the
folder, and paste the snippet below into its system instructions.

## Claude / Claude Code (Anthropic)

Claude Code reads project instructions from `CLAUDE.md`, and Claude
agent setups commonly load skill-style folders. Either route works:

1. Copy `authenticator/` into the project (or your skills folder).
2. Add the `CLAUDE.md` snippet below to your project's `CLAUDE.md`.

## Cursor, Copilot, and other coding agents

Coding agents that read repository instruction files (`AGENTS.md`,
`.cursor/rules`, Copilot instructions, etc.) work the same way:

1. Copy `authenticator/` into the repository or workspace.
2. Paste the `AGENTS.md`-style snippet below into whichever
   instruction file the agent reads.

---

## Ready-to-paste snippet (system prompt / custom instructions)

```text
You have a local two-factor authentication (2FA) tool installed.

Location: ./authenticator/bin/auth.py  (adjust to the real path)
Run it as: python3 <path>/auth.py <command>

Commands:
- Enroll one account:  add <label> --seed <BASE32> | --uri 'otpauth://...' | --qr <image>
- Bulk import:         import --qr <photo...> | --uri 'otpauth-migration://...' | --file <export-file>
                       (Google Authenticator migration QRs, andOTP/Aegis/2FAS/Bitwarden/
                        Ente/Proton/KeePassXC/Steam export files are supported)
- Get a code:          code <label> --json
- See accounts:        list --json      (never shows seeds)
- Remove an account:   remove <label>
- Store health:        status --json

Rules you must follow:
1. Seeds live in ~/.authenticator/seeds.json (0600). Never print, echo,
   log, or repeat a seed anywhere.
2. Generate a code ONLY for a sign-in the user has explicitly
   authorized. Having access to codes is not permission to sign in
   anywhere new.
3. HOTP (counter) accounts: each `code` call consumes one counter
   value — never call it speculatively.
4. If an import file is an encrypted export, the tool will say so;
   relay its re-export instructions to the user instead of guessing
   a password.
5. Full documentation: ./authenticator/SKILL.md — read it before
   first use.
```

## `CLAUDE.md` snippet

```markdown
## Two-factor authentication
This project includes a local authenticator skill in `authenticator/`.
Read `authenticator/SKILL.md` before using it. Generate 2FA codes with
`python3 authenticator/bin/auth.py code <label> --json` only for
sign-ins the user has authorized; never print or log a seed.
```

## `AGENTS.md`-style snippet

```markdown
## 2FA Authenticator Skill
- Tool: `authenticator/bin/auth.py` (Python 3, stdlib OTP; QR intake
  needs `pip install --user pillow zxing-cpp`).
- Read `authenticator/SKILL.md` for the full command set, the
  per-app compatibility matrix, and the safety rules.
- Codes are generated only for user-authorized sign-ins. Seeds in
  `~/.authenticator/seeds.json` are credentials — never output them.
```

---

## Honest limits

- **No shell, no skill.** A chat-only model session with no file or
  shell access cannot store seeds between turns or run the CLI. Use
  an environment that gives the agent those tools.
- **Locked-in apps stay locked in.** Microsoft Authenticator and
  Authy offer no seed export to *anyone* — see the compatibility
  matrix in `authenticator/SKILL.md` for the re-enrollment workaround.
- **The store is only as safe as the host.** `0600` permissions stop
  other local users, not a compromised machine. Treat the agent's
  environment accordingly.
