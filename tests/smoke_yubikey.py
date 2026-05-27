"""End-to-end smoke test against a real YubiKey.

Exercises: FIDO2 enrollment, PRF secret derivation, vault init,
on-disk save/load, passphrase+YubiKey unlock, recovery-code unlock.

Run from project root:
    .venv\\Scripts\\python.exe tests\\smoke_yubikey.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from yubivault import vault, yubikey
from yubivault.crypto import KdfParams

TEST_PASSPHRASE = "smoketest-passphrase-not-real"
# Lower KDF cost so the test is quick; production defaults are much higher.
TEST_KDF = KdfParams(memory_cost=64 * 1024, time_cost=2, parallelism=2)


def step(n, msg):
    print(f"\n[{n}] {msg}", flush=True)


def main():
    print("YubiVault end-to-end smoke test")
    print("Watch for Windows native security-key dialogs (PIN + touch).")

    step(1, "Detect authenticators")
    devs = yubikey.list_devices()
    if not devs:
        print("FAIL: no authenticators detected")
        return 1
    for d in devs:
        print(f"  - {d}")

    step(2, "Enrolling FIDO2 credential (PIN + touch will be requested)")
    try:
        enrolled = yubikey.enroll_credential(label="yubivault-smoketest")
    except yubikey.YubiKeyError as e:
        print(f"FAIL: {e}")
        return 1
    print(f"  credential_id: {len(enrolled.credential_id)} bytes")
    print(f"  prf_salt:      {len(enrolled.prf_salt)} bytes")

    step(3, "Deriving PRF secret (touch will be requested)")
    try:
        hmac_a = yubikey.get_hmac_secret(enrolled.credential_id, enrolled.prf_salt)
    except yubikey.YubiKeyError as e:
        print(f"FAIL: {e}")
        return 1
    print(f"  hmac_secret:   {len(hmac_a)} bytes")
    print(f"  first 8 bytes: {hmac_a[:8].hex()}")

    step(4, "Deriving PRF secret AGAIN (touch will be requested) — must match")
    try:
        hmac_b = yubikey.get_hmac_secret(enrolled.credential_id, enrolled.prf_salt)
    except yubikey.YubiKeyError as e:
        print(f"FAIL: {e}")
        return 1
    if hmac_a != hmac_b:
        print(f"FAIL: PRF output unstable — got two different secrets for same salt")
        return 1
    print("  OK — PRF output is deterministic for same (credential, salt)")

    step(5, "Building a vault encrypted with this PRF secret + passphrase")
    vf, master_key, codes = vault.init_vault(
        TEST_PASSPHRASE,
        enrolled.credential_id,
        enrolled.prf_salt,
        hmac_a,
        kdf=TEST_KDF,
    )
    print(f"  master_key:    {len(master_key)} bytes (in memory only)")
    print(f"  slots:         {len(vf.slots)} ({len([s for s in vf.slots if s.type == 'recovery-code'])} recovery)")
    print(f"  first code:    {codes[0]}")

    with tempfile.TemporaryDirectory() as d:
        vault_path = Path(d) / "smoke.vault.json"

        step(6, "Adding an entry and saving to disk")
        _, body = vault.unlock_with_passphrase(vf, TEST_PASSPHRASE, hmac_a)
        body.entries["smoke-test-site"] = {
            "username": "alice",
            "password": "supersecret-from-yubikey-test",
            "url": "",
            "notes": "",
            "created_at": "now",
            "updated_at": "now",
        }
        vault.save_body(vf, master_key, body)
        vf.save(vault_path)
        print(f"  wrote {vault_path.stat().st_size} bytes to disk")

        step(7, "Loading from disk and unlocking with passphrase + YubiKey (touch required)")
        vf2 = vault.VaultFile.load(vault_path)
        try:
            hmac_c = yubikey.get_hmac_secret(enrolled.credential_id, enrolled.prf_salt)
        except yubikey.YubiKeyError as e:
            print(f"FAIL: {e}")
            return 1
        master_key2, body2 = vault.unlock_with_passphrase(vf2, TEST_PASSPHRASE, hmac_c)
        if master_key2 != master_key:
            print("FAIL: master key did not match after roundtrip")
            return 1
        recovered = body2.entries["smoke-test-site"]["password"]
        if recovered != "supersecret-from-yubikey-test":
            print(f"FAIL: stored password roundtrip failed: {recovered!r}")
            return 1
        print(f"  OK — entry decrypted: username={body2.entries['smoke-test-site']['username']!r}")

        step(8, "Recovery code unlocks the same master key (no YubiKey needed)")
        master_key3, body3, slot_id = vault.unlock_with_recovery_code(vf2, codes[5])
        if master_key3 != master_key:
            print("FAIL: recovery-code master key mismatch")
            return 1
        if body3.entries["smoke-test-site"]["password"] != "supersecret-from-yubikey-test":
            print("FAIL: recovery-code body decryption failed")
            return 1
        print(f"  OK — unlocked via {slot_id}")

        step(9, "Audit log verifies (counter chain intact, file hash matches)")
        result = vault.verify_audit_log(vault_path, vf2)
        if not result.ok:
            print(f"FAIL: audit verify reported: {result.error}")
            return 1
        print(f"  OK — {len(result.entries)} log entries, last counter={result.entries[-1].counter}")

        step(10, "Rotate master key (touch will be requested)")
        try:
            hmac_d = yubikey.get_hmac_secret(enrolled.credential_id, enrolled.prf_salt)
        except yubikey.YubiKeyError as e:
            print(f"FAIL: {e}")
            return 1
        new_master, new_codes, dropped = vault.rotate_master_key(
            vf2, master_key, body3, TEST_PASSPHRASE, hmac_d
        )
        vf2.save(vault_path)
        if new_master == master_key:
            print("FAIL: rotation did not change master key")
            return 1
        print(f"  OK — new master derived, {len(new_codes)} fresh recovery codes minted, dropped: {dropped}")

        step(11, "After rotation: old recovery codes invalid, new ones valid")
        try:
            vault.unlock_with_recovery_code(vf2, codes[0])
            print("FAIL: old recovery code still works after rotation")
            return 1
        except vault.RecoveryCodeRejected:
            print("  OK — old recovery code rejected")
        m, _, _ = vault.unlock_with_recovery_code(vf2, new_codes[2])
        if m != new_master:
            print("FAIL: new recovery code did not produce new master key")
            return 1
        print("  OK — new recovery code unlocks new master")

    print("\n+-----------------------------------------+")
    print("| ALL SMOKE TESTS PASSED                  |")
    print("+-----------------------------------------+")
    return 0


if __name__ == "__main__":
    sys.exit(main())
