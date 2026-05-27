"""Diagnostic: enroll a credential and dump the raw extension results."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fido2.client import DefaultClientDataCollector
from fido2.client.windows import WindowsClient
from fido2.client.win_api import WEBAUTHN_API_VERSION
from fido2.webauthn import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

print(f"Windows WebAuthN API version: {WEBAUTHN_API_VERSION}", flush=True)

collector = DefaultClientDataCollector("https://yubivault.local", verify=lambda *a, **k: True)
client = WindowsClient(collector, allow_hmac_secret=False)

prf_salt = os.urandom(32)
options = PublicKeyCredentialCreationOptions(
    rp=PublicKeyCredentialRpEntity(name="YubiVault", id="yubivault.local"),
    user=PublicKeyCredentialUserEntity(name="debug", id=os.urandom(16), display_name="debug"),
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

print("\nCalling make_credential() — interact with Windows dialogs...", flush=True)
result = client.make_credential(options)

print(f"\nresponse type:                 {type(result).__name__}", flush=True)
print(f"client_extension_results:      {result.client_extension_results!r}", flush=True)
print(f"keys in client_extension_results: {list(result.client_extension_results.keys()) if result.client_extension_results else None}", flush=True)

auth_data = result.response.attestation_object.auth_data
print(f"\nauth_data.extensions:          {auth_data.extensions!r}", flush=True)
print(f"auth_data.flags:               {auth_data.flags}", flush=True)

cred_data = auth_data.credential_data
print(f"\ncredential_id len:             {len(cred_data.credential_id)}", flush=True)
