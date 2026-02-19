"""
Plugin to sign/verify Conan packages with Sigstore's (https://www.sigstore.dev/) cosign tool and
record the signature into the Rekor transparency log for later verifications.

Requirements: The following executables should be installed and in the PATH.
    - cosign: https://github.com/sigstore/cosign/releases

To use this Sigstore plugin, first generate a compatible key pair and define the environment variables for the keys:

    $ cosign generate-key-pair --output-key-prefix mykey

This will generate a mykey.key private key and a mykey.pub public key.

Environment variables:
    - COSIGN_PASSWORD: Set the password of your private key. This is used when using the private key to sign packages.
    - CONAN_SIGSTORE_PLUGIN_ENABLE_REKOR: Enable sign and verify using the Rekor CLI and rekor log (Optional, disabled by default).
    - CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN: Enable plugin's sign feature (Optional, enabled by default).
    - CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY: Enable plugin's verify feature (Optional, enabled by default).
"""

import json
import re
import os
import subprocess
from inspect import signature

import yaml

from conan.api.model.refs import PkgReference
from conan.api.output import ConanOutput
from conan.errors import ConanException


COSIGN = "cosign"
CONFIG_FILENAME = "sigstore-config.yaml"
SIGSTORE_METHOD = "sigstore"


CONFIG_TEMPLATE_CONTENT = """
# Use this section to declare the name of the provider that signs the artifacts,
# the references that apply to be signed, and the path to the keys.
#
# sign:
#   enabled: true                       # (bool) Enable the signature of packages.
#   use_rekor: false                    # (bool) Enable uploading the signature to the Rekor log.
#   references:                         # (list) References or pattern of references that should be signed.
#     - "*/*"                           # Includes all packages with name/version format.
#     - "*/*@*/*"                       # Includes all packages with name/version@user format.
#     - "*/*@*/*"                       # Includes all packages with name/version@user/channel format.
#   exclude_references:                 # (list) References or pattern of references that should NOT be signed.
#     - "**/**@other_company"           # Excludes packages from "other_company".
#   provider: "mycompany"               # (string) Name of the provider used to sign the packages.
#   private_key: "path/to/privkey.pem"  # (absolute path) Private key to sign the packages with.
#   public_key: "path/to/pubkey.pem"    # (absolute path) Public key to sign the packages with.


# Use this section to verify the references for each provider using the corresponding public key.
#
# verify:
#   enabled: true                         # (bool) Enable the verification signature of packages.
#   use_rekor: false                      # (bool) Enable verifying the signature against the Rekor log.
#   providers:                            # (list) Providers that sign the packages for verification.
#     conancenter:                        # Name of the provider that signed the packages
#       references:                       # (list) References or pattern that should be verified.
#         - "*/*"                         # Includes all packages with name/version format.
#       exclude_references:               # (list) References or pattern that should NOT be verified.
#         - "zlib/1.2.11"
#       public_key: "path/to/pubkey.pem"  # (absolute path) Public key to verify the packages with.
#     mycompany:
#       references:
#         - "*/*@mycomany/**"             # Verify all the references for mycompany user.
#       exclude_references:
#         - "*/*@mycompany/testing"       # Exclude verification of references that have testing channel.
#       public_key: "path/to/pubkey.pem"  # (absolute path) Public key to verify the packages with.
"""


def _is_rekor_enabled(partial_config):
    env_var = bool(os.getenv("CONAN_SIGSTORE_PLUGIN_ENABLE_REKOR", False))
    return env_var or partial_config.get("use_rekor", False)


def _is_sign_enabled(config):
    env_var = bool(os.getenv("CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN", True))
    return env_var and config.get("sign", {}).get("enabled", True)


def _is_verify_enabled(config):
    env_var = bool(os.getenv("CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY", True))
    return env_var and config.get("verify", {}).get("enabled", True)


def _load_config():
    config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILENAME)
    if not os.path.exists(config_path):
        ConanOutput().highlight(f"Conan Sigstore plugin configuration file not found. "
                               f"Creating template at {config_path}")
        with open(config_path, "w") as file:
            file.write(CONFIG_TEMPLATE_CONTENT)
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)
    if config.get("sign"):
        assert config.get("sign").get("provider") is not None, f"Missing 'sign.provider' field in {config_path}"
    return config


def _reference_fnmatch(reference, pattern):
    if pattern.count('/') != reference.count('/') or pattern.count('@') != reference.count('@'):
        return False
    regex_pattern = re.escape(pattern)
    regex_pattern = regex_pattern.replace(r'\*', r'[^/@]+')
    return bool(re.fullmatch(regex_pattern, reference))


def _format_reference(reference):
    if isinstance(reference, PkgReference):
        reference = reference.ref
    return str(reference)


def _should_sign_reference(ref, config):
    reference = _format_reference(ref)
    sign_config = config.get("sign", [])
    if sign_config:
        for rule in sign_config.get("exclude_references", []):
            if _reference_fnmatch(reference, rule):
                return False
        for rule in sign_config.get("references", []):
            if _reference_fnmatch(reference, rule):
                return True
    return False


def _get_sign_keys(config):
    sign_config = config.get("sign", {})
    privkey_path = sign_config.get("private_key")
    assert os.path.isfile(privkey_path), f"Private key path not found at '{privkey_path}'"
    pubkey_path = sign_config.get("public_key")
    assert os.path.isfile(pubkey_path), f"Public key path not found at '{pubkey_path}'"
    return privkey_path, pubkey_path


def _should_verify_reference(ref, provider, config):
    reference = _format_reference(ref)
    verify_config = config.get("verify")
    if verify_config:
        provider_config = verify_config.get("providers", {}).get(provider)
        if provider_config:
            for rule in provider_config.get("exclude_references", []):
                if _reference_fnmatch(reference, rule):
                    return False
            for rule in provider_config.get("references", []):
                if _reference_fnmatch(reference, rule):
                    return True
    return False


def _get_verify_key(reference, provider, config):
    provider_config = config.get("verify", {}).get("providers", {}).get(provider, {})
    pubkey_path = provider_config.get("public_key")
    assert os.path.isfile(pubkey_path), f"Public key path not found at '{pubkey_path}'"
    return pubkey_path


def _run_command(command):
    result = subprocess.run(
        command,
        text=True,  # returns strings instead of bytes
        check=False  # we'll manually handle error checking
    )

    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )


def sign(ref, artifacts_folder, signature_folder, **kwargs):
    config = _load_config()
    if not _is_sign_enabled(config):
        ConanOutput().highlight("Sign disabled")

    if not _should_sign_reference(ref, config):
        ConanOutput().highlight("Reference does not match any configuration to be signed")
        return []

    # Check if package is already signed (pkgsign-signatures.json should exist and have the same signature metadata)
    provider = config.get("sign").get("provider")
    signatures_filepath = os.path.join(signature_folder, "pkgsign-signatures.json")
    if os.path.isfile(signatures_filepath):
        with open(signatures_filepath, "r", encoding="utf-8") as f:
            signatures = json.loads(f.read()).get("signatures")
        if signatures:
            already_signed = [s for s in signatures if
                              s.get("provider") == provider and s.get("method") == SIGSTORE_METHOD]
            if already_signed:
                ConanOutput().warning(f"Package {ref.repr_notime()} is already signed")
                return []  # Return empty list to avoid saving the signatures again

    # Sign with Sigstore
    privkey_filepath, pubkey_filepath = _get_sign_keys(config)
    manifest_filepath = os.path.join(signature_folder, "pkgsign-manifest.json")
    signature_filename = "pkgsign-manifest.json.sig"
    signature_filepath = os.path.join(signature_folder, signature_filename)

    if os.environ.get("COSIGN_PASSWORD") is None:
        raise ConanException(f"COSIGN_PASSWORD environment variable not set."
                             f"\nIt is required to sign the packages with the private key ({privkey_filepath}).")

    ConanOutput().info(f"Generating signature file at {signature_filepath} from manifest file {manifest_filepath} "
                       f"using private key {privkey_filepath}")

    use_rekor = _is_rekor_enabled(config.get("sign"))
    cosign_sign_cmd = [
        "cosign",
        "sign-blob",
        "--key", privkey_filepath,
        "--output-signature", signature_filepath,
        "-y",
        manifest_filepath,
    ]
    if use_rekor:
        cosign_sign_cmd.append("--tlog-upload")
    try:
        _run_command(cosign_sign_cmd)
    except Exception as exc:
        raise ConanException(f"Error signing artifact {manifest_filepath}: {exc}")

    ConanOutput().info(f"Created signature for file {manifest_filepath} at {signature_filepath}")
    if use_rekor:
        ConanOutput().info(f"Uploaded signature {signature_filepath} to Rekor")
    return [{"method": SIGSTORE_METHOD,
             "provider": provider,
             "sign_artifacts": {"manifest": "pkgsign-manifest.json",
                                "signature": signature_filename}}]


def verify(ref, artifacts_folder, signature_folder, files, **kwargs):
    config = _load_config()
    if not _is_verify_enabled(config):
        ConanOutput().highlight("Verify disabled")
        return

    signatures_path = os.path.join(signature_folder, "pkgsign-signatures.json")
    try:
        with open(signatures_path, "r", encoding="utf-8") as f:
            signatures = json.loads(f.read()).get("signatures")
    except Exception:
        ConanOutput().warning("Could not verify unsigned package")
        return

    if not signatures:
        ConanOutput().warning("No signatures found in 'pkgsign-signatures.json' file. Could not verify package")

    for signature in signatures:
        provider = signature.get("provider")

        if not _should_verify_reference(ref, provider, config):
            ConanOutput().highlight("Reference does not match any configuration to be verified")
            return

        manifest_filepath = os.path.join(signature_folder, signature.get("sign_artifacts").get("manifest"))
        signature_filepath = os.path.join(signature_folder, signature.get("sign_artifacts").get("signature"))

        signature_method = signature.get("method")
        # Support different signing implementations (sigstore, openssl, gpg...) to verify the packages
        if signature_method == SIGSTORE_METHOD:
            pubkey_filepath = _get_verify_key(ref, provider, config)

            use_rekor = _is_rekor_enabled(config.get("verify"))

            # Verify sha file
            cosign_verify_cmd = [
                "cosign",
                "verify-blob",
                "--key", pubkey_filepath,
                "--signature", signature_filepath,
                manifest_filepath
            ]
            if use_rekor:
                cosign_verify_cmd.append("--tlog-upload")
            try:
                _run_command(cosign_verify_cmd)
            except Exception as exc:
                raise ConanException(f"Error verifying artifact {manifest_filepath}: {exc}")
            ConanOutput().info(f"Signature correctly verified with cosign")
            if use_rekor:
                ConanOutput().info(f"Signature {signature_filepath} for {manifest_filepath} verified against Rekor!")
        else:
            raise ConanException(f"Signature method {signature_method} not supported!")
