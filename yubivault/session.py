"""Interactive unlock session: vault stays open in memory between commands.

The session auto-locks after `idle_seconds` of no user activity. On lock,
the master key bytearray is wiped and the body cache is cleared.
"""

from __future__ import annotations

import shlex
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import click

from . import clipboard, csv_import, display, passgen, vault, yubikey
from .secure import Secret

DEFAULT_IDLE_SECONDS = 600  # 10 minutes


class SessionLocked(Exception):
    pass


class Session:
    def __init__(self, vault_path: Path, idle_seconds: int = DEFAULT_IDLE_SECONDS):
        self.vault_path = vault_path
        self.idle_seconds = idle_seconds
        self.vf: vault.VaultFile | None = None
        self.master: Secret | None = None
        self.body: vault.VaultBody | None = None
        self._lock_timer: threading.Timer | None = None
        self._locked = True

    @property
    def locked(self) -> bool:
        return self._locked

    def unlock(self) -> None:
        import getpass

        if not self.vault_path.exists():
            raise SessionLocked(f"No vault at {self.vault_path}")
        self.vf = vault.VaultFile.load(self.vault_path)
        primary = next((s for s in self.vf.slots if s.id == "primary"), None)
        if primary is None or primary.yubikey is None:
            raise SessionLocked("Vault has no primary YubiKey slot")

        passphrase = getpass.getpass("Vault passphrase: ")
        click.echo("YubiKey: touch + PIN required...", err=True)
        hmac_secret = yubikey.get_hmac_secret(
            primary.yubikey.credential_id, primary.yubikey.prf_salt
        )
        mk_bytes, body = vault.unlock_with_passphrase(self.vf, passphrase, hmac_secret)
        self.master = Secret(mk_bytes)
        self.body = body
        self._locked = False
        self._reset_idle_timer()

    def lock(self) -> None:
        if self._lock_timer is not None:
            self._lock_timer.cancel()
            self._lock_timer = None
        if self.master is not None:
            self.master.wipe()
            self.master = None
        if self.body is not None:
            self.body.entries.clear()
            self.body = None
        self._locked = True

    def _reset_idle_timer(self) -> None:
        if self._lock_timer is not None:
            self._lock_timer.cancel()
        self._lock_timer = threading.Timer(self.idle_seconds, self._auto_lock)
        self._lock_timer.daemon = True
        self._lock_timer.start()

    def _auto_lock(self) -> None:
        # Note: the user may be at the `vault>` prompt blocked in input().
        # We can't interrupt that cross-platform, so we just wipe the keys
        # in memory. The next command they type will see locked=True.
        self.lock()
        # Best-effort attention-grab: print on stderr (may be intermingled
        # with their typing, that's fine).
        try:
            click.echo("\n[auto-locked due to inactivity]", err=True)
        except Exception:
            pass

    def touch(self) -> None:
        """Mark activity; restart idle timer."""
        if self._locked:
            raise SessionLocked("session is locked — type `unlock` to re-open")
        self._reset_idle_timer()

    def save(self) -> None:
        if self._locked or self.vf is None or self.master is None or self.body is None:
            raise SessionLocked("cannot save: session is locked")
        vault.save_body(self.vf, bytes(self.master), self.body)
        self.vf.save(self.vault_path)


HELP = """\
Commands:
  list [--tag TAG]           list entries (tabular: name, username, url, tags)
  search <query>             find entries matching name/username/url/tags
  get <name>                 copy password to clipboard (auto-clears)
  show <name>                print entry details (password masked)
  show-password <name>       print password to stdout
  add <name>                 add a new entry (interactive)
  gen <name> [length]        add with a freshly generated password
  rm <name>                  remove an entry
  tag <name> <t> [<t>...]    add tag(s) to an entry
  untag <name> <t> [<t>...]  remove tag(s) from an entry
  groups                     list all tags with entry counts
  import <file.csv> [tag]    bulk import from CSV; optional tag applied to all
  info                       slot/audit metadata
  lock                       lock the vault (re-enter passphrase + touch to unlock)
  unlock                     unlock if currently locked
  help                       show this help
  quit | exit                exit the session
"""


def run_repl(vault_path: Path, idle_seconds: int = DEFAULT_IDLE_SECONDS) -> int:
    s = Session(vault_path, idle_seconds=idle_seconds)
    try:
        s.unlock()
    except SessionLocked as e:
        click.echo(str(e), err=True)
        return 1
    except yubikey.YubiKeyError as e:
        click.echo(f"YubiKey error: {e}", err=True)
        return 1
    except vault.WrongPassphrase as e:
        click.echo(str(e), err=True)
        return 1

    click.secho(f"Vault unlocked. Auto-locks after {idle_seconds}s idle. Type `help` for commands.", fg="green")

    try:
        while True:
            try:
                line = input("\nvault> ").strip()
            except EOFError:
                click.echo("")
                break
            except KeyboardInterrupt:
                click.echo("")
                continue

            if not line:
                continue

            try:
                parts = shlex.split(line)
            except ValueError as e:
                click.echo(f"parse error: {e}", err=True)
                continue
            cmd, *args = parts

            try:
                if cmd in ("quit", "exit"):
                    break
                if cmd == "help":
                    click.echo(HELP)
                    continue
                if cmd == "lock":
                    s.lock()
                    click.echo("locked")
                    continue
                if cmd == "unlock":
                    if not s.locked:
                        click.echo("already unlocked")
                        continue
                    s.unlock()
                    click.echo("unlocked")
                    continue

                # All other commands require an unlocked session
                s.touch()
                _dispatch(s, cmd, args)
            except SessionLocked as e:
                click.secho(str(e), fg="yellow")
            except yubikey.YubiKeyError as e:
                click.secho(f"YubiKey error: {e}", fg="red")
            except vault.VaultError as e:
                click.secho(f"Vault error: {e}", fg="red")
            except Exception as e:
                click.secho(f"error: {e}", fg="red")
    finally:
        s.lock()
        click.echo("session ended; vault locked")
    return 0


def _dispatch(s: Session, cmd: str, args: list[str]) -> None:
    if cmd == "list":
        tag = None
        if len(args) == 2 and args[0] == "--tag":
            tag = args[1]
        elif args:
            click.echo("usage: list [--tag TAG]")
            return
        filtered = display.filter_entries(s.body.entries, tag=tag)
        click.echo(display.entries_table(filtered))

    elif cmd == "search":
        if not args:
            click.echo("usage: search <query> [--tag TAG]")
            return
        tag = None
        query_parts = args[:]
        if "--tag" in query_parts:
            i = query_parts.index("--tag")
            if i + 1 < len(query_parts):
                tag = query_parts[i + 1]
                query_parts = query_parts[:i] + query_parts[i + 2:]
        query = " ".join(query_parts)
        filtered = display.filter_entries(s.body.entries, query=query, tag=tag)
        if not filtered:
            click.echo("(no matches)")
            return
        click.echo(display.entries_table(filtered))

    elif cmd == "groups":
        counts = display.tag_counts(s.body.entries)
        if not counts:
            click.echo("(no tags yet)")
            return
        click.echo(display.format_table(
            ["TAG", "COUNT"], [[t, str(c)] for t, c in counts]
        ))

    elif cmd == "tag":
        if len(args) < 2:
            click.echo("usage: tag <name> <tag> [<tag>...]")
            return
        name, *tags = args
        if name not in s.body.entries:
            click.echo(f"no entry {name!r}")
            return
        e = s.body.entries[name]
        cur = e.get("tags") or []
        added = [t for t in tags if t not in cur]
        e["tags"] = cur + added
        e["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        s.save()
        click.secho(f"added: {', '.join(added) if added else '(no new tags)'}", fg="green")

    elif cmd == "untag":
        if len(args) < 2:
            click.echo("usage: untag <name> <tag> [<tag>...]")
            return
        name, *tags = args
        if name not in s.body.entries:
            click.echo(f"no entry {name!r}")
            return
        e = s.body.entries[name]
        cur = e.get("tags") or []
        removed = [t for t in tags if t in cur]
        e["tags"] = [t for t in cur if t not in tags]
        e["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        s.save()
        click.secho(f"removed: {', '.join(removed) if removed else '(no matching tags)'}", fg="green")

    elif cmd == "import":
        if not args:
            click.echo("usage: import <file.csv> [default-tag]")
            return
        from pathlib import Path as _Path
        csv_path = _Path(args[0])
        default_tag = args[1] if len(args) > 1 else None
        if not csv_path.exists():
            click.echo(f"no such file: {csv_path}")
            return
        try:
            result = csv_import.import_csv(csv_path, default_tag=default_tag)
        except ValueError as e:
            click.echo(f"import error: {e}")
            return
        click.echo(f"detected: {result.format_detected}; {len(result.entries)} entries")
        if not click.confirm("Import these into the vault?"):
            click.echo("cancelled")
            return
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        added = renamed = 0
        for ent in result.entries:
            target = ent.name
            if target in s.body.entries:
                n = 2
                while f"{target} ({n})" in s.body.entries:
                    n += 1
                target = f"{target} ({n})"
                renamed += 1
            s.body.entries[target] = {
                "username": ent.username, "password": ent.password,
                "url": ent.url, "notes": ent.notes, "tags": ent.tags,
                "created_at": now, "updated_at": now,
            }
            added += 1
        s.save()
        click.secho(f"imported {added} entries"
                    + (f" ({renamed} renamed due to conflicts)" if renamed else "")
                    + ".", fg="green")

    elif cmd == "get":
        if len(args) != 1:
            click.echo("usage: get <name>")
            return
        entry = s.body.entries.get(args[0])
        if not entry:
            click.echo(f"no entry {args[0]!r}")
            return
        clipboard.copy_with_auto_clear(entry["password"], 30)
        click.echo(f"password for {args[0]!r} copied to clipboard (clears in 30s)")

    elif cmd == "show":
        if len(args) != 1:
            click.echo("usage: show <name>")
            return
        entry = s.body.entries.get(args[0])
        if not entry:
            click.echo(f"no entry {args[0]!r}")
            return
        click.echo(f"  name:      {args[0]}")
        click.echo(f"  username:  {entry.get('username', '')}")
        click.echo(f"  password:  {'*' * 8} (use `show-password` to reveal)")
        click.echo(f"  url:       {entry.get('url', '')}")
        click.echo(f"  tags:      {', '.join(entry.get('tags') or []) or '(none)'}")
        click.echo(f"  notes:     {entry.get('notes', '')}")
        click.echo(f"  updated:   {entry.get('updated_at', '')}")

    elif cmd == "show-password":
        if len(args) != 1:
            click.echo("usage: show-password <name>")
            return
        entry = s.body.entries.get(args[0])
        if not entry:
            click.echo(f"no entry {args[0]!r}")
            return
        click.echo(entry["password"])

    elif cmd == "add":
        import getpass
        if len(args) != 1:
            click.echo("usage: add <name>")
            return
        name = args[0]
        if name in s.body.entries:
            click.echo(f"entry {name!r} already exists; use `rm` first")
            return
        username = input("  username: ").strip()
        password = getpass.getpass("  password: ")
        if not password:
            click.echo("empty password rejected")
            return
        url = input("  url (optional): ").strip()
        notes = input("  notes (optional): ").strip()
        tags_in = input("  tags (comma-separated, optional): ").strip()
        tags = [t.strip() for t in tags_in.split(",") if t.strip()] if tags_in else []
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        s.body.entries[name] = {
            "username": username, "password": password,
            "url": url, "notes": notes, "tags": tags,
            "created_at": now, "updated_at": now,
        }
        s.save()
        click.secho(f"added {name!r}" + (f" with tags {tags}" if tags else ""), fg="green")

    elif cmd == "gen":
        if not 1 <= len(args) <= 2:
            click.echo("usage: gen <name> [length]")
            return
        name = args[0]
        length = int(args[1]) if len(args) == 2 else 24
        if name in s.body.entries:
            click.echo(f"entry {name!r} already exists; use `rm` first")
            return
        username = input("  username: ").strip()
        url = input("  url (optional): ").strip()
        tags_in = input("  tags (comma-separated, optional): ").strip()
        tags = [t.strip() for t in tags_in.split(",") if t.strip()] if tags_in else []
        password = passgen.generate(length=length)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        s.body.entries[name] = {
            "username": username, "password": password,
            "url": url, "notes": "", "tags": tags,
            "created_at": now, "updated_at": now,
        }
        s.save()
        click.secho(f"added {name!r} with {length}-char generated password", fg="green")

    elif cmd == "rm":
        if len(args) != 1:
            click.echo("usage: rm <name>")
            return
        name = args[0]
        if name not in s.body.entries:
            click.echo(f"no entry {name!r}")
            return
        del s.body.entries[name]
        s.save()
        click.secho(f"removed {name!r}", fg="green")

    elif cmd == "info":
        click.echo(f"vault:    {s.vault_path}")
        click.echo(f"counter:  {s.vf.update_counter}")
        click.echo(f"entries:  {len(s.body.entries)}")
        click.echo(f"slots:    {len(s.vf.slots)}")
        for slot in s.vf.slots:
            flag = " [USED]" if slot.type == "recovery-code" and slot.used else ""
            click.echo(f"  - {slot.id:20s} {slot.type}{flag}")

    else:
        click.echo(f"unknown command: {cmd}. Type `help` for the list.")
