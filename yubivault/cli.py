from __future__ import annotations

import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from . import clipboard, csv_import, display, passgen, recovery, vault, yubikey
from .crypto import KdfParams
from .secure import Secret

DEFAULT_VAULT = Path.home() / ".yubivault" / "vault.json"
CLIPBOARD_CLEAR_SECONDS = 30


def _vault_path(path: str | None) -> Path:
    return Path(path) if path else DEFAULT_VAULT


def _prompt_passphrase(confirm: bool = False) -> str:
    pp = getpass.getpass("Vault passphrase: ")
    if confirm:
        pp2 = getpass.getpass("Confirm passphrase: ")
        if pp != pp2:
            click.echo("Passphrases do not match.", err=True)
            sys.exit(1)
    if not pp:
        click.echo("Empty passphrase rejected.", err=True)
        sys.exit(1)
    return pp


def _unlock(vault_path: Path) -> tuple[vault.VaultFile, Secret, vault.VaultBody]:
    """Standard unlock: passphrase + primary YubiKey.

    Returns (vault, master_key_as_Secret, body). The caller is responsible
    for using `master_key` as a context manager so its bytes are wiped
    on completion. CLI commands always wrap in `with master_key: ...`.
    """
    if not vault_path.exists():
        click.echo(f"No vault at {vault_path}. Run `yubivault init` first.", err=True)
        sys.exit(1)
    vf = vault.VaultFile.load(vault_path)
    primary = next((s for s in vf.slots if s.id == "primary"), None)
    if primary is None or primary.yubikey is None:
        click.echo("Vault has no primary YubiKey slot. Corrupted?", err=True)
        sys.exit(1)

    passphrase = _prompt_passphrase()
    click.echo("Asking YubiKey for unlock secret (touch + PIN required)...", err=True)
    try:
        hmac_secret = yubikey.get_hmac_secret(
            primary.yubikey.credential_id, primary.yubikey.prf_salt
        )
    except yubikey.YubiKeyError as e:
        click.echo(f"YubiKey error: {e}", err=True)
        sys.exit(1)

    try:
        mk_bytes, body = vault.unlock_with_passphrase(vf, passphrase, hmac_secret)
    except vault.WrongPassphrase as e:
        click.echo(str(e), err=True)
        sys.exit(1)

    return vf, Secret(mk_bytes), body


def _save_unlocked(vault_path: Path, vf: vault.VaultFile, master_key: Secret, body: vault.VaultBody) -> None:
    vault.save_body(vf, bytes(master_key), body)
    vf.save(vault_path)


@click.group()
@click.version_option(package_name="yubivault", prog_name="yubivault")
def main():
    """YubiVault — local password manager protected by a YubiKey."""


@main.command()
@click.option("--vault", "vault_path", default=None, help="Path to vault file.")
@click.option(
    "--kdf-memory-mib",
    type=int,
    default=256,
    show_default=True,
    help="Argon2id memory cost in MiB.",
)
@click.option("--kdf-time", type=int, default=4, show_default=True, help="Argon2id iterations.")
@click.option("--kdf-parallelism", type=int, default=4, show_default=True)
def init(vault_path: str | None, kdf_memory_mib: int, kdf_time: int, kdf_parallelism: int):
    """Create a new vault. Enrolls your YubiKey and prints recovery codes."""
    path = _vault_path(vault_path)
    if path.exists():
        click.echo(f"Refusing to overwrite existing vault at {path}.", err=True)
        sys.exit(1)

    click.echo(f"Creating new vault at {path}")
    passphrase = _prompt_passphrase(confirm=True)

    click.echo("Enrolling YubiKey (touch + PIN required)...", err=True)
    try:
        enrolled = yubikey.enroll_credential(label="yubivault-primary")
    except yubikey.YubiKeyError as e:
        click.echo(f"YubiKey error: {e}", err=True)
        sys.exit(1)

    click.echo("Computing PRF secret (touch again)...", err=True)
    try:
        hmac_secret = yubikey.get_hmac_secret(enrolled.credential_id, enrolled.prf_salt)
    except yubikey.YubiKeyError as e:
        click.echo(f"YubiKey error: {e}", err=True)
        sys.exit(1)

    kdf = KdfParams(
        memory_cost=kdf_memory_mib * 1024,
        time_cost=kdf_time,
        parallelism=kdf_parallelism,
    )

    click.echo("Deriving keys (this is intentionally slow)...", err=True)
    vf, master_bytes, codes = vault.init_vault(
        passphrase, enrolled.credential_id, enrolled.prf_salt, hmac_secret, kdf=kdf
    )
    with Secret(master_bytes):
        vf.save(path)
    del master_bytes

    click.echo("")
    click.secho("Vault created.", fg="green")
    click.echo("")
    click.secho("RECOVERY CODES", bold=True)
    click.echo("These will not be shown again. Print them and store somewhere safe.")
    click.echo("Each code can unlock the vault ONCE.")
    click.echo("")
    for i, c in enumerate(codes, 1):
        click.echo(f"  {i:2d}.  {c}")
    click.echo("")
    click.echo("Press Enter when you have saved them.")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


@main.command()
@click.option("--vault", "vault_path", default=None)
def info(vault_path: str | None):
    """Show vault slot metadata without unlocking."""
    path = _vault_path(vault_path)
    if not path.exists():
        click.echo(f"No vault at {path}.", err=True)
        sys.exit(1)
    vf = vault.VaultFile.load(path)
    click.echo(f"Vault:    {path}")
    click.echo(f"Version:  {vf.version}   Cipher: xchacha20poly1305")
    click.echo(f"KDF:      argon2id m={vf.kdf.memory_cost} KiB t={vf.kdf.time_cost} p={vf.kdf.parallelism}")
    click.echo(f"Counter:  {vf.update_counter}")
    click.echo(f"Slots:    {len(vf.slots)}")
    for s in vf.slots:
        flag = ""
        if s.type == "recovery-code" and s.used:
            flag = "  [USED]"
        click.echo(f"  - {s.id:20s} {s.type}{flag}")
    result = vault.verify_audit_log(path, vf)
    click.echo("")
    if result.ok:
        click.secho(f"Audit:    OK  ({len(result.entries)} entries)", fg="green")
    else:
        click.secho(f"Audit:    FAIL — {result.error}", fg="red")


@main.command()
@click.option("--vault", "vault_path", default=None)
def verify(vault_path: str | None):
    """Walk the audit log and detect tampering or rollback."""
    path = _vault_path(vault_path)
    if not path.exists():
        click.echo(f"No vault at {path}.", err=True)
        sys.exit(1)
    vf = vault.VaultFile.load(path)
    result = vault.verify_audit_log(path, vf)

    if result.entries:
        click.echo(f"Audit log: {len(result.entries)} entries")
        click.echo(f"First save: {result.entries[0].ts}  counter={result.entries[0].counter}")
        click.echo(f"Last save:  {result.entries[-1].ts}  counter={result.entries[-1].counter}")
        click.echo(f"Current file sha256:   {vf.file_sha256()}")
        click.echo(f"Latest log  sha256:    {result.entries[-1].vault_sha256}")
    if result.ok:
        click.secho("VERIFIED — chain intact, on-disk vault matches latest log entry.", fg="green")
    else:
        click.secho(f"FAILED — {result.error}", fg="red")
        sys.exit(2)


@main.command(name="list")
@click.option("--vault", "vault_path", default=None)
@click.option("--tag", default=None, help="Only show entries with this tag.")
@click.option("--names-only", is_flag=True, help="Print just the names, one per line.")
def list_entries(vault_path: str | None, tag: str | None, names_only: bool):
    """List entries in the vault (tabular: name, username, url, tags)."""
    path = _vault_path(vault_path)
    _, master, body = _unlock(path)
    with master:
        filtered = display.filter_entries(body.entries, tag=tag)
        if names_only:
            for name in sorted(filtered):
                click.echo(name)
        else:
            click.echo(display.entries_table(filtered))


@main.command()
@click.argument("name")
@click.option("--vault", "vault_path", default=None)
@click.option("--username", default=None, help="Username for the entry.")
@click.option("--url", default=None, help="URL for the entry.")
@click.option("--notes", default=None, help="Notes for the entry.")
@click.option("--tag", "tags", multiple=True, help="Tag for the entry (repeat to add multiple).")
@click.option("--generate", "generate", is_flag=True, help="Generate a random password.")
@click.option("--length", type=int, default=24, show_default=True, help="Length for generated password.")
def add(name: str, vault_path: str | None, username, url, notes, tags, generate, length):
    """Add a new entry to the vault."""
    path = _vault_path(vault_path)
    vf, master, body = _unlock(path)
    with master:
        if name in body.entries:
            click.echo(f"Entry {name!r} already exists. Use `rm` first to overwrite.", err=True)
            sys.exit(1)

        if generate:
            password = passgen.generate(length=length)
            click.echo(f"Generated {length}-char password.")
        else:
            password = getpass.getpass(f"Password for {name}: ")
            if not password:
                click.echo("Empty password rejected.", err=True)
                sys.exit(1)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        body.entries[name] = {
            "username": username or "",
            "password": password,
            "url": url or "",
            "notes": notes or "",
            "tags": list(dict.fromkeys(tags)),  # dedupe preserving order
            "created_at": now,
            "updated_at": now,
        }
        _save_unlocked(path, vf, master, body)
    click.secho(f"Added {name!r}.", fg="green")


@main.command(name="import")
@click.argument("csv_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--vault", "vault_path", default=None)
@click.option("--tag", "default_tag", default=None,
              help="Tag added to every imported entry (e.g. 'imported-2026-05').")
@click.option("--on-conflict",
              type=click.Choice(["skip", "rename", "overwrite", "merge-tags"]),
              default="rename", show_default=True,
              help="What to do when an imported name already exists in the vault.")
@click.option("--dry-run", is_flag=True,
              help="Parse and report, but do not write to the vault.")
def import_cmd(csv_file: str, vault_path: str | None, default_tag: str | None,
               on_conflict: str, dry_run: bool):
    """Bulk import entries from a CSV (Chrome/Bitwarden/KeePassXC/1Password/generic)."""
    csv_path = Path(csv_file)
    try:
        result = csv_import.import_csv(csv_path, default_tag=default_tag)
    except ValueError as e:
        click.echo(f"Import error: {e}", err=True)
        sys.exit(1)

    click.echo(f"Detected format: {result.format_detected}")
    click.echo(f"Rows in file:    {result.rows_seen}")
    click.echo(f"Empty/skipped:   {result.skipped_empty}")
    click.echo(f"Importable:      {len(result.entries)}")

    if dry_run:
        click.echo("\n--dry-run set; not writing to vault. Preview:")
        for e in result.entries[:10]:
            click.echo(f"  {e.name:30s}  user={e.username:20s}  tags={','.join(e.tags)}")
        if len(result.entries) > 10:
            click.echo(f"  ... and {len(result.entries) - 10} more")
        return

    path = _vault_path(vault_path)
    vf, master, body = _unlock(path)
    with master:
        added = 0
        skipped = 0
        renamed = 0
        overwritten = 0
        merged = 0
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for e in result.entries:
            target_name = e.name
            if target_name in body.entries:
                if on_conflict == "skip":
                    skipped += 1
                    continue
                if on_conflict == "overwrite":
                    overwritten += 1
                elif on_conflict == "merge-tags":
                    existing = body.entries[target_name]
                    existing_tags = existing.get("tags") or []
                    for t in e.tags:
                        if t not in existing_tags:
                            existing_tags.append(t)
                    existing["tags"] = existing_tags
                    existing["updated_at"] = now
                    merged += 1
                    continue
                else:  # rename
                    n = 2
                    while f"{target_name} ({n})" in body.entries:
                        n += 1
                    target_name = f"{target_name} ({n})"
                    renamed += 1

            body.entries[target_name] = {
                "username": e.username,
                "password": e.password,
                "url": e.url,
                "notes": e.notes,
                "tags": e.tags,
                "created_at": now,
                "updated_at": now,
            }
            added += 1

        _save_unlocked(path, vf, master, body)

    click.secho(
        f"Imported {added} new entries"
        + (f", renamed {renamed}" if renamed else "")
        + (f", overwrote {overwritten}" if overwritten else "")
        + (f", merged tags into {merged}" if merged else "")
        + (f", skipped {skipped} dupes" if skipped else "")
        + ".",
        fg="green",
    )


@main.command()
@click.argument("query", required=False, default="")
@click.option("--vault", "vault_path", default=None)
@click.option("--tag", default=None, help="Restrict to entries with this tag.")
def search(query: str, vault_path: str | None, tag: str | None):
    """Search entries by substring of name/username/url/tags."""
    path = _vault_path(vault_path)
    _, master, body = _unlock(path)
    with master:
        filtered = display.filter_entries(body.entries, query=query, tag=tag)
        if not filtered:
            click.echo("(no matches)")
            return
        click.echo(display.entries_table(filtered))


@main.command()
@click.argument("name")
@click.argument("tags", nargs=-1, required=True)
@click.option("--vault", "vault_path", default=None)
def tag(name: str, tags: tuple[str, ...], vault_path: str | None):
    """Add one or more tags to an entry."""
    path = _vault_path(vault_path)
    vf, master, body = _unlock(path)
    with master:
        if name not in body.entries:
            click.echo(f"No entry {name!r}.", err=True)
            sys.exit(1)
        entry = body.entries[name]
        cur = entry.get("tags") or []
        added = []
        for t in tags:
            if t not in cur:
                cur.append(t)
                added.append(t)
        entry["tags"] = cur
        entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _save_unlocked(path, vf, master, body)
    if added:
        click.secho(f"Added tags to {name!r}: {', '.join(added)}", fg="green")
    else:
        click.echo("(no new tags added)")


@main.command()
@click.argument("name")
@click.argument("tags", nargs=-1, required=True)
@click.option("--vault", "vault_path", default=None)
def untag(name: str, tags: tuple[str, ...], vault_path: str | None):
    """Remove one or more tags from an entry."""
    path = _vault_path(vault_path)
    vf, master, body = _unlock(path)
    with master:
        if name not in body.entries:
            click.echo(f"No entry {name!r}.", err=True)
            sys.exit(1)
        entry = body.entries[name]
        cur = entry.get("tags") or []
        removed = [t for t in tags if t in cur]
        entry["tags"] = [t for t in cur if t not in tags]
        entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _save_unlocked(path, vf, master, body)
    if removed:
        click.secho(f"Removed tags from {name!r}: {', '.join(removed)}", fg="green")
    else:
        click.echo("(no matching tags found)")


@main.command()
@click.option("--vault", "vault_path", default=None)
def groups(vault_path: str | None):
    """List all tags and how many entries each contains."""
    path = _vault_path(vault_path)
    _, master, body = _unlock(path)
    with master:
        counts = display.tag_counts(body.entries)
        if not counts:
            click.echo("(no tags yet — use `yubivault tag <name> <tag>` to add some)")
            return
        rows = [[t, str(c)] for t, c in counts]
        click.echo(display.format_table(["TAG", "COUNT"], rows))


@main.command()
@click.argument("name")
@click.option("--vault", "vault_path", default=None)
@click.option("--show", is_flag=True, help="Print password to stdout instead of clipboard.")
@click.option("--field", default="password", type=click.Choice(["password", "username", "url", "notes"]))
def get(name: str, vault_path: str | None, show: bool, field: str):
    """Retrieve an entry. Password copied to clipboard by default."""
    path = _vault_path(vault_path)
    _, master, body = _unlock(path)
    with master:
        if name not in body.entries:
            click.echo(f"No entry {name!r}.", err=True)
            sys.exit(1)
        entry = body.entries[name]
        value = entry.get(field, "")
        if not value:
            click.echo(f"Entry has no {field}.", err=True)
            sys.exit(1)

        if show or field != "password":
            click.echo(value)
            return

        clipboard.copy_with_auto_clear(value, CLIPBOARD_CLEAR_SECONDS)
        click.echo(f"Password copied to clipboard. Will clear in {CLIPBOARD_CLEAR_SECONDS}s.")


@main.command()
@click.argument("name")
@click.option("--vault", "vault_path", default=None)
def rm(name: str, vault_path: str | None):
    """Remove an entry."""
    path = _vault_path(vault_path)
    vf, master, body = _unlock(path)
    with master:
        if name not in body.entries:
            click.echo(f"No entry {name!r}.", err=True)
            sys.exit(1)
        del body.entries[name]
        _save_unlocked(path, vf, master, body)
    click.secho(f"Removed {name!r}.", fg="green")


@main.command(name="enroll-backup")
@click.option("--vault", "vault_path", default=None)
@click.option("--label", required=True, help="Label for the backup slot (e.g. 'backup-yk5').")
def enroll_backup(vault_path: str | None, label: str):
    """Enroll a second YubiKey as a backup that can also unlock the vault."""
    path = _vault_path(vault_path)
    click.echo("First, unlock with your PRIMARY YubiKey:")
    vf, master, body = _unlock(path)

    with master:
        click.echo("")
        click.echo("Now plug in the BACKUP YubiKey (unplug the primary first).")
        click.echo("Press Enter when ready.")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            return

        click.echo("Enrolling backup YubiKey...", err=True)
        enrolled = yubikey.enroll_credential(label=label)
        hmac_secret = yubikey.get_hmac_secret(enrolled.credential_id, enrolled.prf_salt)

        passphrase = _prompt_passphrase()
        vault.add_yubikey_slot(
            vf,
            bytes(master),
            passphrase,
            enrolled.credential_id,
            enrolled.prf_salt,
            hmac_secret,
            label=label,
        )
        # Re-encrypt the body too so the update_counter bumps. Any rollback
        # to the pre-enrollment vault file will then be flagged by `verify`.
        _save_unlocked(path, vf, master, body)
    click.secho(f"Backup YubiKey enrolled as slot {label!r}.", fg="green")


@main.command(name="use-recovery")
@click.option("--vault", "vault_path", default=None)
def use_recovery(vault_path: str | None):
    """Unlock with a recovery code (one-time use) and display the vault."""
    path = _vault_path(vault_path)
    if not path.exists():
        click.echo(f"No vault at {path}.", err=True)
        sys.exit(1)
    vf = vault.VaultFile.load(path)

    code = getpass.getpass("Recovery code: ")
    try:
        master_bytes, body, slot_id = vault.unlock_with_recovery_code(vf, code)
    except vault.RecoveryCodeRejected as e:
        click.echo(str(e), err=True)
        sys.exit(1)

    with Secret(master_bytes) as master:
        vault.mark_recovery_used(vf, slot_id)
        vault.save_body(vf, bytes(master), body)  # re-encrypt with fresh nonce
        vf.save(path)

        click.secho(f"Unlocked via {slot_id}. Slot is now marked used.", fg="green")
        click.echo("")
        click.echo("Entries:")
        for name in sorted(body.entries):
            click.echo(f"  - {name}")
        click.echo("")
        click.echo("Recommended: run `yubivault rotate` to roll the master key.")
    del master_bytes


@main.command()
@click.option("--vault", "vault_path", default=None)
def rotate(vault_path: str | None):
    """Rotate the master key. Mints fresh recovery codes; backup YubiKeys must be re-enrolled."""
    path = _vault_path(vault_path)
    if not path.exists():
        click.echo(f"No vault at {path}.", err=True)
        sys.exit(1)

    click.echo("Unlocking vault for rotation...")
    vf, old_master, body = _unlock(path)

    # We also need a fresh PRF derivation to rebuild the primary slot.
    # Re-prompt for passphrase here so we have the plain string (the unlock
    # already validated it). We re-derive the PRF too.
    primary = next(s for s in vf.slots if s.id == "primary")
    backup_slots = [s.id for s in vf.slots if s.id != "primary" and s.type == "passphrase+yubikey"]
    if backup_slots:
        click.echo("")
        click.echo("Backup YubiKey slots will be DROPPED and must be re-enrolled:")
        for s in backup_slots:
            click.echo(f"  - {s}")
        click.echo("")
        if not click.confirm("Continue?"):
            old_master.wipe()
            click.echo("Aborted.")
            return

    passphrase = _prompt_passphrase()
    click.echo("Asking YubiKey to re-derive PRF (touch + PIN required)...", err=True)
    try:
        hmac_secret = yubikey.get_hmac_secret(
            primary.yubikey.credential_id, primary.yubikey.prf_salt
        )
    except yubikey.YubiKeyError as e:
        click.echo(f"YubiKey error: {e}", err=True)
        old_master.wipe()
        sys.exit(1)

    with old_master:
        new_master_bytes, new_codes, dropped = vault.rotate_master_key(
            vf, bytes(old_master), body, passphrase, hmac_secret
        )

    with Secret(new_master_bytes) as new_master:
        vf.save(path)
    del new_master_bytes

    click.secho("Master key rotated.", fg="green")
    if dropped:
        click.echo(f"Dropped {len(dropped)} slot(s): {', '.join(dropped)}")
    click.echo("")
    click.secho("NEW RECOVERY CODES", bold=True)
    click.echo("These will not be shown again. Old codes are now invalid.")
    click.echo("")
    for i, c in enumerate(new_codes, 1):
        click.echo(f"  {i:2d}.  {c}")
    click.echo("")
    click.echo("Press Enter when you have saved them.")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


@main.command()
@click.option("--vault", "vault_path", default=None)
@click.option("--idle-seconds", type=int, default=600, show_default=True,
              help="Auto-lock after this many seconds of inactivity.")
def unlock(vault_path: str | None, idle_seconds: int):
    """Open an interactive session that keeps the vault unlocked between commands."""
    from . import session
    path = _vault_path(vault_path)
    sys.exit(session.run_repl(path, idle_seconds=idle_seconds))


@main.command()
@click.option("--length", type=int, default=24, show_default=True)
def gen(length: int):
    """Generate a random password (does not touch the vault)."""
    click.echo(passgen.generate(length=length))
