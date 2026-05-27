from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass

import click
from fido2.client import (
    ClientError,
    DefaultClientDataCollector,
    Fido2Client,
    UserInteraction,
)
from fido2.ctap import CtapError
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.hid import CtapHidDevice
from fido2.webauthn import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# RP ID is the "relying party" identifier bound into the credential.
# It does NOT need to resolve. It just must be stable across enrollments
# of the same vault. Origin is constructed from it.
RP_ID = "yubivault.local"
ORIGIN = f"https://{RP_ID}"
PRF_SALT_LEN = 32
HMAC_OUTPUT_LEN = 32

IS_WINDOWS = sys.platform == "win32"


class YubiKeyError(Exception):
    pass


class YubiKeyNotFound(YubiKeyError):
    pass


class YubiKeyNoPin(YubiKeyError):
    pass


class YubiKeyPRFNotSupported(YubiKeyError):
    pass


@dataclass
class EnrolledCredential:
    credential_id: bytes
    prf_salt: bytes  # 32 bytes; stored in vault, sent to YubiKey to derive secret


class CliInteraction(UserInteraction):
    """Fallback CTAP-direct interaction. Only used on non-Windows platforms."""

    def prompt_up(self):
        click.echo("Touch your YubiKey now...", err=True)

    def request_pin(self, permissions, rp_id):
        return getpass.getpass("YubiKey FIDO2 PIN: ")

    def request_uv(self, permissions, rp_id):
        click.echo("YubiKey user verification required.", err=True)
        return True


def _verify_rp_id_anywhere(rp_id: str, origin: str) -> bool:
    """We use a synthetic RP ID, not a real domain, so accept any origin."""
    return True


def _build_client():
    """Build a platform-appropriate WebAuthn client.

    On Windows 10 19H1+, use the OS WebAuthn API (no admin needed, native PIN/touch UI).
    Elsewhere, talk to the YubiKey directly over CTAP-HID with our CLI prompts.
    """
    collector = DefaultClientDataCollector(ORIGIN, verify=_verify_rp_id_anywhere)

    if IS_WINDOWS:
        from fido2.client.windows import WindowsClient

        if not WindowsClient.is_available():
            raise YubiKeyError(
                "Windows WebAuthn API not available. Requires Windows 10 19H1 or later."
            )
        return WindowsClient(collector, allow_hmac_secret=False)

    # Non-Windows fallback (Linux/macOS): direct CTAP-HID
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        raise YubiKeyNotFound(
            "No FIDO2 authenticator detected. Plug in your YubiKey and try again."
        )
    if len(devs) > 1:
        click.echo(
            f"Multiple FIDO2 devices found ({len(devs)}). Using the first.", err=True
        )
    return Fido2Client(
        devs[0],
        collector,
        user_interaction=CliInteraction(),
        extensions=[HmacSecretExtension(allow_hmac_secret=False)],
    )


def list_devices() -> list[str]:
    """Return human-readable names of detected authenticators (for diagnostics)."""
    names = []
    if IS_WINDOWS:
        from fido2.client.windows import WindowsClient

        if WindowsClient.is_available():
            names.append("Windows WebAuthn API")
    for d in CtapHidDevice.list_devices():
        names.append(str(d.descriptor))
    return names


def enroll_credential(label: str = "yubivault") -> EnrolledCredential:
    """Create a new FIDO2 credential on the YubiKey for this vault.

    Returns the credential_id and the PRF salt to store in the vault.
    The OS/library prompts for PIN and touch.
    """
    client = _build_client()
    prf_salt = os.urandom(PRF_SALT_LEN)

    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(name="YubiVault", id=RP_ID),
        user=PublicKeyCredentialUserEntity(
            name=label,
            id=os.urandom(16),
            display_name=label,
        ),
        challenge=os.urandom(32),
        pub_key_cred_params=[
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7),
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-8),
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        extensions={"prf": {"eval": {"first": prf_salt}}},
        timeout=60_000,
    )

    try:
        result = client.make_credential(options)
    except ClientError as e:
        _translate_client_error(e)
        raise
    except OSError as e:
        # Windows WebAuthn errors come through here
        raise YubiKeyError(f"Windows WebAuthn error: {e}") from e

    cred_data = result.response.attestation_object.auth_data.credential_data
    if cred_data is None:
        raise YubiKeyError("Authenticator returned no credential data")

    # Attribute access preserves the dataclass (and raw bytes inside it).
    # Item access (.get / []) serializes to dict + base64url strings.
    prf = result.client_extension_results.prf if result.client_extension_results else None
    if prf is None or not prf.enabled:
        ext_dump = dict(result.client_extension_results) if result.client_extension_results else {}
        auth_ext = result.response.attestation_object.auth_data.extensions
        raise YubiKeyPRFNotSupported(
            "Authenticator did not enable PRF/hmac-secret extension.\n"
            f"  client_extension_results: {ext_dump!r}\n"
            f"  auth_data.extensions:     {auth_ext!r}\n"
            f"  credential_id length:     {len(cred_data.credential_id)}\n"
            "  If credential_id is ~32 bytes, Windows used the platform "
            "authenticator (Hello/TPM) instead of the YubiKey."
        )

    return EnrolledCredential(
        credential_id=bytes(cred_data.credential_id),
        prf_salt=prf_salt,
    )


def get_hmac_secret(credential_id: bytes, prf_salt: bytes) -> bytes:
    """Ask the authenticator to compute HMAC(credential_secret, prf_salt). Returns 32 bytes."""
    if len(prf_salt) != PRF_SALT_LEN:
        raise ValueError(f"prf_salt must be {PRF_SALT_LEN} bytes")

    client = _build_client()

    options = PublicKeyCredentialRequestOptions(
        rp_id=RP_ID,
        challenge=os.urandom(32),
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=credential_id,
            )
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        extensions={"prf": {"eval": {"first": prf_salt}}},
        timeout=60_000,
    )

    try:
        selection = client.get_assertion(options)
    except ClientError as e:
        _translate_client_error(e)
        raise
    except OSError as e:
        raise YubiKeyError(f"Windows WebAuthn error: {e}") from e

    response = selection.get_response(0)
    prf = response.client_extension_results.prf if response.client_extension_results else None
    results = prf.results if prf is not None else None
    first = results.first if results is not None else None
    if not first or len(first) != HMAC_OUTPUT_LEN:
        raise YubiKeyError(
            "Authenticator did not return a PRF output. Is the credential valid for this device?\n"
            f"  client_extension_results: {dict(response.client_extension_results) if response.client_extension_results else {}!r}"
        )
    return bytes(first)


def _translate_client_error(e: ClientError) -> None:
    cause = getattr(e, "cause", None)
    if isinstance(cause, CtapError):
        if cause.code == CtapError.ERR.PIN_NOT_SET:
            raise YubiKeyNoPin(
                "Your YubiKey does not have a FIDO2 PIN set. "
                "Set one via Windows Settings > Accounts > Sign-in options > Security key > Manage, "
                "or with `ykman fido access change-pin`."
            ) from e
        if cause.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_INVALID):
            raise YubiKeyError("Incorrect YubiKey PIN.") from e
        if cause.code == CtapError.ERR.PIN_BLOCKED:
            raise YubiKeyError(
                "YubiKey PIN is blocked. Reset FIDO2 with `ykman fido reset` "
                "(this erases all FIDO2 credentials on the key)."
            ) from e
        if cause.code == CtapError.ERR.NO_CREDENTIALS:
            raise YubiKeyError(
                "This YubiKey does not have a credential for this vault. "
                "Did you enroll the right key?"
            ) from e
        if cause.code == CtapError.ERR.USER_ACTION_TIMEOUT:
            raise YubiKeyError("Timed out waiting for YubiKey touch.") from e
