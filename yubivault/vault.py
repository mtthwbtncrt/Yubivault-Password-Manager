from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import crypto, recovery
from .crypto import KdfParams

VAULT_VERSION = 1
VAULT_MAGIC = "YVLT"
CIPHER = "xchacha20poly1305"

# AAD strings bind each ciphertext to its purpose. Without these, an attacker
# with write access could move ciphertext between slots or the body. The body
# AAD also includes the update_counter — silently rolling back the vault file
# to an older copy still has matching ciphertext+AAD for THAT counter, but the
# audit log will reveal that the on-disk counter is behind.
AAD_VERSION = b"yubivault:v1"


def _aad_slot(slot_id: str) -> bytes:
    return AAD_VERSION + b":slot:" + slot_id.encode("utf-8")


def _aad_body(counter: int) -> bytes:
    return AAD_VERSION + b":body:" + str(counter).encode("ascii")


# Backwards-compatible alias; old code paths may still import this.
AAD_BODY = _aad_body(0)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


class VaultError(Exception):
    pass


class VaultLocked(VaultError):
    pass


class WrongPassphrase(VaultError):
    pass


class RecoveryCodeRejected(VaultError):
    pass


@dataclass
class YubiKeyBinding:
    credential_id: bytes
    prf_salt: bytes

    def to_dict(self) -> dict:
        return {
            "credential_id": _b64e(self.credential_id),
            "prf_salt": _b64e(self.prf_salt),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "YubiKeyBinding":
        return cls(
            credential_id=_b64d(d["credential_id"]),
            prf_salt=_b64d(d["prf_salt"]),
        )


@dataclass
class Slot:
    id: str
    type: str  # "passphrase+yubikey" | "recovery-code"
    kdf_salt: bytes
    wrap_nonce: bytes
    wrapped_key: bytes
    yubikey: YubiKeyBinding | None = None
    used: bool = False  # only meaningful for recovery-code slots
    created_at: str = ""

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "kdf_salt": _b64e(self.kdf_salt),
            "wrap_nonce": _b64e(self.wrap_nonce),
            "wrapped_key": _b64e(self.wrapped_key),
            "created_at": self.created_at,
        }
        if self.yubikey is not None:
            d["yubikey"] = self.yubikey.to_dict()
        if self.type == "recovery-code":
            d["used"] = self.used
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Slot":
        return cls(
            id=d["id"],
            type=d["type"],
            kdf_salt=_b64d(d["kdf_salt"]),
            wrap_nonce=_b64d(d["wrap_nonce"]),
            wrapped_key=_b64d(d["wrapped_key"]),
            yubikey=YubiKeyBinding.from_dict(d["yubikey"]) if "yubikey" in d else None,
            used=d.get("used", False),
            created_at=d.get("created_at", ""),
        )


@dataclass
class VaultFile:
    """Encrypted vault as stored on disk."""

    kdf: KdfParams
    slots: list[Slot]
    body_nonce: bytes
    body_ciphertext: bytes
    update_counter: int = 0  # monotonically increases on every save
    version: int = VAULT_VERSION

    def to_json(self) -> str:
        d = {
            "magic": VAULT_MAGIC,
            "version": self.version,
            "cipher": CIPHER,
            "update_counter": self.update_counter,
            "kdf": self.kdf.to_dict(),
            "slots": [s.to_dict() for s in self.slots],
            "body": {
                "nonce": _b64e(self.body_nonce),
                "ciphertext": _b64e(self.body_ciphertext),
            },
        }
        return json.dumps(d, indent=2, sort_keys=False)

    @classmethod
    def from_json(cls, text: str) -> "VaultFile":
        d = json.loads(text)
        if d.get("magic") != VAULT_MAGIC:
            raise VaultError("Not a YubiVault file (bad magic).")
        if d.get("version") != VAULT_VERSION:
            raise VaultError(f"Unsupported vault version: {d.get('version')}")
        if d.get("cipher") != CIPHER:
            raise VaultError(f"Unsupported cipher: {d.get('cipher')}")
        return cls(
            kdf=KdfParams.from_dict(d["kdf"]),
            slots=[Slot.from_dict(s) for s in d["slots"]],
            body_nonce=_b64d(d["body"]["nonce"]),
            body_ciphertext=_b64d(d["body"]["ciphertext"]),
            update_counter=d.get("update_counter", 0),
            version=d["version"],
        )

    def file_sha256(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    def save(self, path: Path) -> None:
        """Atomic write: temp file in same dir, fsync, rename.

        Also appends to <path>.audit.log — a tamper-evident append-only chain
        of (timestamp, update_counter, vault_sha256, prev_entry_hash).
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".vault-", suffix=".tmp", dir=str(path.parent)
        )
        json_text = self.to_json()
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json_text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        # Append to audit log AFTER the atomic write succeeds.
        _append_audit(path, self.update_counter, hashlib.sha256(json_text.encode("utf-8")).hexdigest())

    @classmethod
    def load(cls, path: Path) -> "VaultFile":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())


# --- Audit log -------------------------------------------------------------

def audit_log_path(vault_path: Path) -> Path:
    return Path(str(vault_path) + ".audit.log")


def _append_audit(vault_path: Path, counter: int, vault_sha: str) -> None:
    log = audit_log_path(vault_path)
    prev_hash = ""
    if log.exists():
        with open(log, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
    entry = {
        "ts": _now_iso(),
        "counter": counter,
        "vault_sha256": vault_sha,
        "prev_hash": prev_hash,
    }
    line = json.dumps(entry, sort_keys=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


@dataclass
class AuditEntry:
    ts: str
    counter: int
    vault_sha256: str
    prev_hash: str


@dataclass
class AuditResult:
    entries: list[AuditEntry]
    ok: bool
    error: str = ""

    @property
    def latest(self) -> AuditEntry | None:
        return self.entries[-1] if self.entries else None


def verify_audit_log(vault_path: Path, vf: VaultFile) -> AuditResult:
    """Walk the audit log and verify:
    1. Each entry's prev_hash matches sha256(previous-line).
    2. counter values are strictly increasing.
    3. The vault file currently on disk matches the latest log entry.
    """
    log = audit_log_path(vault_path)
    if not log.exists():
        return AuditResult([], ok=False, error="No audit log present.")

    entries: list[AuditEntry] = []
    prev_line_hash = ""
    last_counter = -1
    with open(log, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            try:
                d = json.loads(raw)
            except json.JSONDecodeError as e:
                return AuditResult(entries, ok=False, error=f"Line {lineno}: invalid JSON ({e})")
            entry = AuditEntry(
                ts=d["ts"], counter=d["counter"],
                vault_sha256=d["vault_sha256"], prev_hash=d["prev_hash"],
            )
            if entry.prev_hash != prev_line_hash:
                return AuditResult(entries, ok=False, error=f"Line {lineno}: prev_hash chain broken")
            if entry.counter <= last_counter:
                return AuditResult(entries, ok=False, error=f"Line {lineno}: counter did not strictly increase ({last_counter} -> {entry.counter})")
            entries.append(entry)
            prev_line_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            last_counter = entry.counter

    if not entries:
        return AuditResult(entries, ok=False, error="Audit log is empty.")

    current_sha = vf.file_sha256()
    latest = entries[-1]
    if latest.vault_sha256 != current_sha:
        return AuditResult(
            entries, ok=False,
            error=f"Vault on disk does not match latest log entry (rollback or tamper).",
        )
    if latest.counter != vf.update_counter:
        return AuditResult(
            entries, ok=False,
            error=f"Vault counter {vf.update_counter} != log counter {latest.counter}.",
        )

    return AuditResult(entries, ok=True)


@dataclass
class VaultBody:
    """Decrypted vault contents — never serialize this to disk."""

    entries: dict[str, dict] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        return json.dumps({"entries": self.entries}, sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "VaultBody":
        d = json.loads(data.decode("utf-8"))
        return cls(entries=d.get("entries", {}))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _combine_passphrase_and_hmac(passphrase: bytes, hmac_secret: bytes) -> bytes:
    # Domain-separated concatenation. Argon2id will mix them thoroughly.
    return b"yubivault:v1:wrap:" + passphrase + b"|" + hmac_secret


def init_vault(
    passphrase: str,
    credential_id: bytes,
    prf_salt: bytes,
    hmac_secret: bytes,
    kdf: KdfParams | None = None,
) -> tuple[VaultFile, bytes, list[str]]:
    """Create a brand new vault.

    Returns (VaultFile, master_key, recovery_codes).
    The caller is responsible for displaying recovery_codes to the user once
    and then forgetting them.
    """
    kdf = kdf or KdfParams()
    master_key = crypto.random_key()
    pp_bytes = passphrase.encode("utf-8")

    slot_id = "primary"
    salt = crypto.random_salt()
    secret = _combine_passphrase_and_hmac(pp_bytes, hmac_secret)
    nonce, wrapped = crypto.wrap_master_key(
        master_key, secret, salt, kdf, aad=_aad_slot(slot_id)
    )
    primary_slot = Slot(
        id=slot_id,
        type="passphrase+yubikey",
        kdf_salt=salt,
        wrap_nonce=nonce,
        wrapped_key=wrapped,
        yubikey=YubiKeyBinding(credential_id=credential_id, prf_salt=prf_salt),
        created_at=_now_iso(),
    )

    # Generate 10 recovery codes, each wrapping the same master key.
    codes = recovery.generate_codes(10)
    recovery_slots = []
    for i, code in enumerate(codes):
        slot_id = f"recovery-{i}"
        salt = crypto.random_salt()
        nonce, wrapped = crypto.wrap_master_key(
            master_key,
            recovery.normalize(code),
            salt,
            kdf,
            aad=_aad_slot(slot_id),
        )
        recovery_slots.append(
            Slot(
                id=slot_id,
                type="recovery-code",
                kdf_salt=salt,
                wrap_nonce=nonce,
                wrapped_key=wrapped,
                created_at=_now_iso(),
            )
        )

    body = VaultBody()
    counter = 1
    body_nonce, body_ct = crypto.aead_encrypt(master_key, body.to_bytes(), aad=_aad_body(counter))

    vf = VaultFile(
        kdf=kdf,
        slots=[primary_slot] + recovery_slots,
        body_nonce=body_nonce,
        body_ciphertext=body_ct,
        update_counter=counter,
    )
    return vf, master_key, codes


def unlock_with_passphrase(
    vault: VaultFile,
    passphrase: str,
    hmac_secret: bytes,
    slot_id: str = "primary",
) -> tuple[bytes, VaultBody]:
    slot = _find_slot(vault, slot_id)
    if slot.type != "passphrase+yubikey":
        raise VaultError(f"Slot {slot_id!r} is not a passphrase+yubikey slot")
    secret = _combine_passphrase_and_hmac(passphrase.encode("utf-8"), hmac_secret)
    try:
        master_key = crypto.unwrap_master_key(
            slot.wrapped_key,
            slot.wrap_nonce,
            secret,
            slot.kdf_salt,
            vault.kdf,
            aad=_aad_slot(slot.id),
        )
    except Exception as e:
        raise WrongPassphrase(
            "Vault did not unlock. Wrong passphrase, wrong YubiKey, or corrupted vault."
        ) from e
    body = _decrypt_body(vault, master_key)
    return master_key, body


def unlock_with_recovery_code(
    vault: VaultFile,
    code: str,
) -> tuple[bytes, VaultBody, str]:
    """Try the given recovery code against each unused recovery slot.

    Returns (master_key, body, used_slot_id). Caller should mark that slot
    used and persist the vault.
    """
    canonical = recovery.normalize(code)
    for slot in vault.slots:
        if slot.type != "recovery-code" or slot.used:
            continue
        try:
            master_key = crypto.unwrap_master_key(
                slot.wrapped_key,
                slot.wrap_nonce,
                canonical,
                slot.kdf_salt,
                vault.kdf,
                aad=_aad_slot(slot.id),
            )
        except Exception:
            continue
        body = _decrypt_body(vault, master_key)
        return master_key, body, slot.id
    raise RecoveryCodeRejected(
        "No unused recovery slot matched this code. "
        "The code may be wrong, already used, or for a different vault."
    )


def _find_slot(vault: VaultFile, slot_id: str) -> Slot:
    for s in vault.slots:
        if s.id == slot_id:
            return s
    raise VaultError(f"No such slot: {slot_id!r}")


def _decrypt_body(vault: VaultFile, master_key: bytes) -> VaultBody:
    try:
        pt = crypto.aead_decrypt(
            master_key, vault.body_nonce, vault.body_ciphertext,
            aad=_aad_body(vault.update_counter),
        )
    except Exception as e:
        raise VaultError(
            "Slot unwrap succeeded but body decryption failed. Vault may be corrupted "
            "or the update_counter was tampered with."
        ) from e
    return VaultBody.from_bytes(pt)


def save_body(vault: VaultFile, master_key: bytes, body: VaultBody) -> None:
    """Re-encrypt the body with a fresh nonce and bump the update counter."""
    vault.update_counter += 1
    nonce, ct = crypto.aead_encrypt(
        master_key, body.to_bytes(), aad=_aad_body(vault.update_counter)
    )
    vault.body_nonce = nonce
    vault.body_ciphertext = ct


def add_yubikey_slot(
    vault: VaultFile,
    master_key: bytes,
    passphrase: str,
    credential_id: bytes,
    prf_salt: bytes,
    hmac_secret: bytes,
    label: str,
) -> Slot:
    """Add a backup YubiKey slot wrapping the existing master key."""
    slot_id = label
    if any(s.id == slot_id for s in vault.slots):
        raise VaultError(f"A slot named {slot_id!r} already exists")
    salt = crypto.random_salt()
    secret = _combine_passphrase_and_hmac(passphrase.encode("utf-8"), hmac_secret)
    nonce, wrapped = crypto.wrap_master_key(
        master_key, secret, salt, vault.kdf, aad=_aad_slot(slot_id)
    )
    new_slot = Slot(
        id=slot_id,
        type="passphrase+yubikey",
        kdf_salt=salt,
        wrap_nonce=nonce,
        wrapped_key=wrapped,
        yubikey=YubiKeyBinding(credential_id=credential_id, prf_salt=prf_salt),
        created_at=_now_iso(),
    )
    vault.slots.append(new_slot)
    return new_slot


def mark_recovery_used(vault: VaultFile, slot_id: str) -> None:
    s = _find_slot(vault, slot_id)
    if s.type != "recovery-code":
        raise VaultError(f"Slot {slot_id!r} is not a recovery slot")
    s.used = True


def rotate_master_key(
    vault: VaultFile,
    old_master_key: bytes,
    body: VaultBody,
    passphrase: str,
    primary_hmac_secret: bytes,
) -> tuple[bytes, list[str], list[str]]:
    """Rotate the master key: re-encrypt body, re-wrap primary slot, mint new recovery codes.

    Returns (new_master_key, new_recovery_codes, dropped_slot_ids).

    Strategy:
      - Verify old_master_key decrypts the current body (caller already did this).
      - Generate a fresh 32-byte master key.
      - Keep the primary slot's credential_id and prf_salt (same YubiKey credential),
        re-wrap with the same passphrase + the just-supplied hmac_secret.
      - Drop ALL other slots (backup YubiKeys, all recovery codes), generate a fresh
        set of recovery codes wrapping the new master key.
      - Re-encrypt the body with the new master key.

    Callers must wipe `old_master_key` after this returns and prompt the user to
    re-enroll any backup YubiKeys they want to keep.
    """
    primary = _find_slot(vault, "primary")
    if primary.type != "passphrase+yubikey" or primary.yubikey is None:
        raise VaultError("Vault has no primary YubiKey slot to rotate around")

    new_master = crypto.random_key()

    # 1. Re-wrap the primary slot with the new master key.
    salt = crypto.random_salt()
    secret = _combine_passphrase_and_hmac(passphrase.encode("utf-8"), primary_hmac_secret)
    nonce, wrapped = crypto.wrap_master_key(
        new_master, secret, salt, vault.kdf, aad=_aad_slot("primary")
    )
    primary.kdf_salt = salt
    primary.wrap_nonce = nonce
    primary.wrapped_key = wrapped
    primary.created_at = _now_iso()

    # 2. Drop all non-primary slots. Collect their ids for the report.
    dropped = [s.id for s in vault.slots if s.id != "primary"]
    vault.slots = [primary]

    # 3. Generate a fresh batch of recovery codes wrapping the new master.
    codes = recovery.generate_codes(10)
    for i, code in enumerate(codes):
        slot_id = f"recovery-{i}"
        salt = crypto.random_salt()
        nonce, wrapped = crypto.wrap_master_key(
            new_master,
            recovery.normalize(code),
            salt,
            vault.kdf,
            aad=_aad_slot(slot_id),
        )
        vault.slots.append(
            Slot(
                id=slot_id,
                type="recovery-code",
                kdf_salt=salt,
                wrap_nonce=nonce,
                wrapped_key=wrapped,
                created_at=_now_iso(),
            )
        )

    # 4. Re-encrypt the body with the new master and bump the counter.
    vault.update_counter += 1
    body_nonce, body_ct = crypto.aead_encrypt(
        new_master, body.to_bytes(), aad=_aad_body(vault.update_counter)
    )
    vault.body_nonce = body_nonce
    vault.body_ciphertext = body_ct

    return new_master, codes, dropped
