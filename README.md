# 🔐 YubiVault

> A CLI password manager that refuses to open without your YubiKey.

Most password managers protect your vault with one secret: a master password. If somebody leaks the file *and* knows your master password, they win. That's a single point of failure.

**YubiVault needs two things every single time:** your master passphrase **and** a touch on your YubiKey. The vault file alone is mathematically useless. The YubiKey alone is mathematically useless. Steal one, you've got nothing.

```
┌─────────────────────────┐         ┌─────────────────────────┐
│   Vault file (.json)    │   +     │   Your YubiKey + touch  │   =   🔓
└─────────────────────────┘         └─────────────────────────┘

┌─────────────────────────┐                                          ❌
│   Vault file (.json)    │  alone:                                  no.
└─────────────────────────┘
```

---

## What you get

- 🔒 **AES-grade crypto.** XChaCha20-Poly1305 body encryption, Argon2id key derivation (256 MiB / 4 iterations). Authenticated, tamper-evident, memory-hard.
- 🔑 **Two-factor unlock.** Master passphrase + YubiKey FIDO2 hmac-secret (PRF). Touch + PIN required every unlock.
- 🆘 **Recovery that doesn't suck.** 10 one-time recovery codes printed once at setup, plus the option to enroll a backup YubiKey.
- 🛡️ **Tamper-evident audit log.** Every save is logged in a chained append-only file. Rollback or in-place edits are detected.
- 🔄 **One-command master-key rotation.** Compromise scare? Rotate. All old recovery codes instantly dead.
- 📥 **Bulk CSV import** from Chrome, Edge, Brave, Firefox, Bitwarden, KeePassXC, 1Password, LastPass, or any generic CSV.
- 🏷️ **Tags + search.** Group entries any way you want. Filter the list. Find what you need.
- 💻 **Interactive REPL.** One unlock, many commands, auto-lock after 10 minutes idle.
- 📋 **Auto-clearing clipboard** that survives `Ctrl+C` because it runs detached.
- 🧠 **Best-effort memory hygiene.** Master key sits in a mlocked, zero-on-exit bytearray.

---

## Requirements

- **Windows 10 or 11** (uses the native WebAuthN API)
- **Python 3.11+**
- **A YubiKey 5 series** (or any FIDO2 authenticator with the `hmac-secret` extension)
- **A FIDO2 PIN set on your YubiKey** — without it, the hmac-secret extension stays dormant

> Don't have a FIDO2 PIN yet? Open Windows **Settings → Accounts → Sign-in options → Security key → Manage**, or run `ykman fido access change-pin` if you have YubiKey Manager installed.

---

## Quick start

```powershell
# Clone and set up a venv
git clone https://github.com/YOUR-NAME/yubivault.git
cd yubivault
py -m venv .venv
.venv\Scripts\pip install -e .

# Create your vault (you'll touch the YubiKey twice and see 10 recovery codes)
yubivault init

# Drop into a session and start adding things
yubivault unlock
```

That's it. You're running.

---

## The commands, at a glance

```
yubivault init               ← create a new vault
yubivault unlock             ← open an interactive session  (recommended)
yubivault add NAME           ← add one entry
yubivault get NAME           ← copy password to clipboard
yubivault list               ← show the table of entries
yubivault search QUERY       ← find by name/username/url/tag
yubivault tag NAME t1 t2     ← add tags
yubivault untag NAME t1      ← remove tags
yubivault groups             ← list all tags + counts
yubivault rm NAME            ← delete an entry
yubivault import FILE.csv    ← bulk import
yubivault enroll-backup ...  ← add a second YubiKey
yubivault rotate             ← roll the master key + recovery codes
yubivault use-recovery       ← unlock with a recovery code
yubivault verify             ← check the audit log
yubivault info               ← slot metadata (no unlock needed)
yubivault gen --length 32    ← generate a password (doesn't touch the vault)
```

`yubivault --help` and `yubivault COMMAND --help` for the full options.

---

## The REPL (where you'll spend most of your time)

Unlocking takes a passphrase + a YubiKey touch every time. Doing that for every single command gets old fast. The REPL unlocks **once** and keeps the vault open in memory:

```
$ yubivault unlock
Vault passphrase: ********
YubiKey: touch + PIN required...
Vault unlocked. Auto-locks after 600s idle. Type `help` for commands.

vault> list
NAME                  USERNAME             URL                        TAGS
--------------------  -------------------  -------------------------  ----------
bank.com              alice@gmail.com      https://bank.com           finance
github.com            alice                https://github.com         dev, work
gitlab.com            alice                https://gitlab.com         dev

vault> search github
github.com            alice                https://github.com         dev, work

vault> gen newsite.com 32
  username: alice
  url (optional): https://newsite.com
  tags (comma-separated, optional): dev
added 'newsite.com' with 32-char generated password

vault> get bank.com
password for 'bank.com' copied to clipboard (clears in 30s)

vault> tag newsite.com web frontend
added: web, frontend

vault> groups
TAG       COUNT
--------  -----
dev       3
work      1
finance   1
web       1
frontend  1

vault> lock
locked

vault> quit
session ended; vault locked
```

The session auto-locks after 10 minutes of inactivity (configurable with `--idle-seconds`). After auto-lock, type `unlock` to re-open.

---

## Bulk import (the fast way to migrate)

Got 200 passwords in Chrome you want out? One command:

```powershell
yubivault import C:\Users\you\Downloads\Chrome Passwords.csv
```

The importer **auto-detects** the format from the header row. Supported:

| Manager | How to export |
|---|---|
| **Chrome / Edge / Brave** | `chrome://password-manager` → ⋮ → Export passwords |
| **Firefox** | `about:logins` → ⋯ → Export Logins |
| **Bitwarden** | Tools → Export Vault → CSV |
| **KeePassXC** | Database → Export → CSV |
| **1Password** | Right-click vault → Export → CSV |
| **LastPass** | Advanced Options → Export |
| **Anything else** | Any CSV with headers like `name`/`title`, `username`/`user`/`email`, `password`, `url`, `notes`, `tags`/`folder`/`group` |

Tag everything you import:

```powershell
yubivault import passwords.csv --tag imported-2026-05
```

Preview without writing:

```powershell
yubivault import passwords.csv --dry-run
```

Handle name conflicts your way:

```powershell
yubivault import passwords.csv --on-conflict rename       # github.com (2)   ← default
yubivault import passwords.csv --on-conflict skip         # leave existing alone
yubivault import passwords.csv --on-conflict overwrite    # replace
yubivault import passwords.csv --on-conflict merge-tags   # keep entry, union tags
```

> ⚠️ **Delete that CSV after import.** Exported password files are plaintext. Empty your Downloads, empty your Recycle Bin, and don't ever email them to yourself.

---

## "What happens if I lose my YubiKey?"

In order of preference:

1. **Plug in your backup YubiKey.** If you enrolled one with `yubivault enroll-backup`, it just works. Unlock with passphrase + the backup, same as always.
2. **Use a recovery code.** Run `yubivault use-recovery`, type one of the 10 codes you printed at setup. Then **immediately** run `yubivault rotate` to mint fresh codes and invalidate the used one for good.
3. **Neither?** Your vault is gone. There is no backdoor. This is the deal you signed up for.

After **any** recovery code use, rotate:

```powershell
yubivault rotate
```

This re-rolls the master key, prints 10 fresh recovery codes, and drops backup YubiKey slots (you'll need to re-enroll them). Old codes become permanently invalid.

---

## How it actually works

```
┌──────────────────────── vault.json ────────────────────────┐
│                                                            │
│  Slot "primary":                                           │
│    AEAD( wrap_key, master_key, aad = "slot:primary" )      │
│    where wrap_key = Argon2id( passphrase ⊕ PRF(yk, salt) ) │
│                                                            │
│  Slots "recovery-0" … "recovery-9":                        │
│    AEAD( wrap_key, master_key, aad = "slot:recovery-N" )   │
│    where wrap_key = Argon2id( recovery_code )              │
│                                                            │
│  Body:                                                     │
│    AEAD( master_key, entries-as-JSON,                      │
│          aad = "body:" + update_counter )                  │
│                                                            │
└────────────────────────────────────────────────────────────┘
                            │
                            ↓
                vault.json.audit.log
                (append-only chain: each line links to the previous)
```

- **AEAD**: XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit MAC)
- **KDF**: Argon2id, 256 MiB memory, 4 iterations, 4 lanes
- **YubiKey**: FIDO2 PRF (hmac-secret) via Windows WebAuthN
- **Master key**: 32 random bytes from the OS CSPRNG, never written to disk

Every wrapped slot uses **distinct AAD** so an attacker can't paste ciphertext between slots. The body's AAD includes the `update_counter`, so silently rolling back the file to an old version breaks decryption *and* fails the audit-log check.

---

## Security model (the honest version)

### What this defends against

✅ **Vault file theft.** Cloud-sync leak, stolen laptop, hacked backup drive. The file alone is computationally useless.
✅ **YubiKey theft alone.** Without the file, the YubiKey reveals nothing.
✅ **Most offline brute force.** Argon2id at 256 MiB is GPU-resistant; combined with the YubiKey-derived component, the search space is ~2²⁵⁶.
✅ **Accidental rollback.** The audit log notices.
✅ **Phishing.** No browser extension, no autofill, no thing to phish.

### What this does NOT defend against

❌ **Active malware on the unlocked machine.** Once the vault is open, anything that can read your process memory or clipboard wins. No user-mode password manager can fully defend against this.
❌ **Keyloggers.** Your passphrase and PIN are typed.
❌ **Kernel-level adversaries.** They see everything.
❌ **Losing your YubiKey AND all 10 recovery codes AND your backup key.** Game over by design.

### Make these choices well

1. **Use a strong passphrase.** Four random words minimum. This is the single biggest knob that affects offline brute-force cost.
2. **Print your recovery codes and put them somewhere physical and safe.** Not in a file. Not in an email. A safe, a safe-deposit box, a locked drawer.
3. **Enroll a backup YubiKey.** Two keys, identical access, redundancy. Don't keep them in the same bag.
4. **Run on a trusted device.** "Trusted" means you control everything that runs on it.

---

## Project layout

```
yubivault/
├── crypto.py        # AEAD + Argon2id + key wrapping
├── secure.py        # mlocked bytearray, wipe-on-context-exit
├── recovery.py      # 80-bit Crockford-base32 one-time codes
├── vault.py         # vault format, slot system, audit log, rotate
├── yubikey.py       # FIDO2 PRF integration via python-fido2
├── csv_import.py    # auto-detecting CSV importer
├── display.py       # table formatting helpers
├── clipboard.py     # detached subprocess auto-clear
├── session.py       # interactive REPL with idle timeout
├── cli.py           # click commands (the entry point)
└── tests/           # 52 unit tests + a YubiKey smoke test
```

---

## Development

```powershell
# Run the unit tests (no YubiKey needed)
.venv\Scripts\python.exe tests\test_crypto.py
.venv\Scripts\python.exe tests\test_recovery.py
.venv\Scripts\python.exe tests\test_secure.py
.venv\Scripts\python.exe tests\test_vault.py
.venv\Scripts\python.exe tests\test_csv_import.py
.venv\Scripts\python.exe tests\test_display.py

# Full end-to-end smoke test (requires a real YubiKey, ~5 touches)
.venv\Scripts\python.exe -u tests\smoke_yubikey.py
```

---

## Limitations / known sharp edges

- **Windows-first.** The FIDO2 path uses Windows WebAuthN. Linux/macOS may work with minor tweaks but is untested.
- **Python memory hygiene is best-effort, not bulletproof.** Strings are immutable; we wipe what we can.
- **The audit log is tamper-evident for partial edits, not tamper-proof for full replacement.** A future version will HMAC-sign each entry.
- **No browser integration.** By design.
- **No cloud sync.** By design.

---

## Why this exists

Because "premium encryption" sold to you by a password manager company means "trust us." YubiVault means "trust the math, the hardware, and the small pile of source you can read in an afternoon." The whole project is under 2000 lines of Python plus a hardware root of trust you can hold in your hand.

Plus YubiKeys are just kind of fun.

---

## License

Pick one. MIT and Apache 2.0 are both fine for a project like this.
