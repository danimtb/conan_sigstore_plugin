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
import os
import subprocess

import yaml

from conan.api.output import ConanOutput
from conan.errors import ConanException


COSIGN = "cosign"
CONFIG_FILENAME = "sigstore-config.yaml"
SIGNING_METHOD = "sigstore"


CONFIG_TEMPLATE_CONTENT = """\
# This is the configuration file for the Conan Sigstore plugin, which allows signing and verifying Conan packages with
# Sigstore's Cosign tool.
# You can fill the sections below to configure the signing and verifying of your packages.
#
# Use this section to declare the name of the provider that signs the artifacts and the path to the private key.
sign:
  enabled: true                       # (bool) Enable the signature of packages.
  provider: "mycompany"               # (string) Name of the provider used to sign the packages.
  private_key: "path/to/privkey.key"  # (absolute path) Private key to sign the packages with.
  use_rekor: false                    # (bool) Enable uploading the signature to the Rekor log.


# Use this section to verify the packages with the corresponding public keys of for each provider (multiple providers supported).
verify:
  enabled: true                         # (bool) Enable the verification signature of packages.
  providers:                            # (list) Providers that sign the packages for verification.
    mycompany:                          # (string) Name of the provider that signed the packages
      public_key: "path/to/pubkey.pub"  # (absolute path) Public key to verify the packages with.
  use_rekor: false                      # (bool) Enable verifying the signature against the Rekor log.
"""


def _is_rekor_enabled(partial_config):
    rekor_enabled_env_var = os.getenv("CONAN_SIGSTORE_PLUGIN_ENABLE_REKOR", "").strip().lower()
    bool_value = rekor_enabled_env_var in ("1", "true", "yes")
    return bool_value if rekor_enabled_env_var else partial_config.get("use_rekor", False)


def _is_sign_enabled(config):
    sign_enabled_env_var = os.getenv("CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN", "").strip().lower()
    bool_value = sign_enabled_env_var in ("1", "true", "yes")
    return bool_value if sign_enabled_env_var else config.get("sign", {}).get("enabled", True)


def _is_verify_enabled(config):
    verify_enabled_env_var = os.getenv("CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY", "").strip().lower()
    bool_value = verify_enabled_env_var in ("1", "true", "yes")
    return bool_value if verify_enabled_env_var else config.get("verify", {}).get("enabled", True)


def _get_signing_config_path():
    # The content of file generated with: cosign signing-config create --with-default-services=false --out=signing-config.json
    # This config file is needed to disable rekor (enabled by default in the cosign CLI)
    return os.path.join(os.path.dirname(__file__), "signing-config.json")


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
        assert config.get("sign").get("provider") not in (None, "mycompany"), \
            f"Missing 'sign.provider' field in {config_path}. Set your own provider name in the configuration file."
    if config.get("verify"):
        providers = config.get("verify").get("providers")
        assert providers, (f"Missing 'verify.providers' field in {config_path}. Set one provider to verify the "
                           f"packages' signature in the configuration file.")
        assert "mycompany" not in providers, \
            f"'mycompany' provider found in 'verify.providers'. Set your own provider name in the configuration file."
    return config


def _get_sign_key(config):
    sign_config = config.get("sign", {})
    privkey_path = sign_config.get("private_key")
    assert os.path.isfile(privkey_path), f"Private key path not found at '{privkey_path}'"
    return privkey_path


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


def _print_rekor_url(bundle_path):
    with open(bundle_path, "r") as f:
        content = json.load(f)
    logIndex = content.get("verificationMaterial").get("tlogEntries")[0].get("logIndex")
    ConanOutput().info(f"Rekor transparency log URL: https://rekor.sigstore.dev/api/v1/log/entries?logIndex={logIndex}")


def sign(ref, artifacts_folder, signature_folder, **kwargs):
    config = _load_config()
    if not _is_sign_enabled(config):
        raise ConanException("Package signing plugin is disabled for signing packages. To enable it, set 'sign.enabled'"
                             " to true in the plugin configuration file or set the CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN "
                             "environment variable to true.")

    # Check if package is already signed (pkgsign-signatures.json should exist and have the same signature metadata)
    provider = config.get("sign").get("provider")
    signatures_filepath = os.path.join(signature_folder, "pkgsign-signatures.json")
    if os.path.isfile(signatures_filepath):
        with open(signatures_filepath, "r", encoding="utf-8") as f:
            signatures = json.loads(f.read()).get("signatures")
        if signatures:
            already_signed = [s for s in signatures if
                              s.get("provider") == provider and s.get("method") == SIGNING_METHOD]
            if already_signed:
                ConanOutput().warning(f"Package {ref.repr_notime()} is already signed")
                return []  # Return empty list to avoid saving the signatures again

    # Sign with Sigstore
    privkey_filepath = _get_sign_key(config)
    manifest_filepath = os.path.join(signature_folder, "pkgsign-manifest.json")
    bunble_filename = "artifact.sigstore.json"
    bundle_filepath = os.path.join(signature_folder, bunble_filename)

    if os.environ.get("COSIGN_PASSWORD") is None:
        raise ConanException(f"COSIGN_PASSWORD environment variable not set."
                             f"\nIt is required to sign the packages with the private key ({privkey_filepath}).")

    ConanOutput().info(f"Signing package with '{provider}' provider using private key at {privkey_filepath}")

    use_rekor = _is_rekor_enabled(config.get("sign"))
    cosign_sign_cmd = [
        COSIGN, "-d",
        "sign-blob",
        "--key", privkey_filepath,
        "--bundle", bundle_filepath,
        "-y",
        manifest_filepath,
    ]
    if not use_rekor:
        cosign_sign_cmd.append(f"--signing-config={_get_signing_config_path()}")
    try:
        _run_command(cosign_sign_cmd)
    except Exception as exc:
        raise ConanException(f"Error signing artifact {manifest_filepath}: {exc}")

    if use_rekor:
        _print_rekor_url(bundle_filepath)
    return [{"method": SIGNING_METHOD,
             "provider": provider,
             "sign_artifacts": {"manifest": "pkgsign-manifest.json",
                                "bundle": bunble_filename}}]


def verify(ref, artifacts_folder, signature_folder, files, **kwargs):
    config = _load_config()
    if not _is_verify_enabled(config):
        raise ConanException("Package signing plugin is disabled for verifying packages. To enable it, set "
                             "'verify.enabled' to true in the plugin configuration file or set the "
                             "CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY environment variable to true.")

    signatures_path = os.path.join(signature_folder, "pkgsign-signatures.json")
    try:
        with open(signatures_path, "r", encoding="utf-8") as f:
            signatures = json.loads(f.read()).get("signatures")
    except Exception:
        raise ConanException("Could not verify unsigned package")

    if not signatures:
        raise ConanException(f"No signatures found in {signatures_path} file. "
                             f"Could not verify package {ref.repr_notime()}")

    for signature in signatures:
        provider = signature.get("provider")

        manifest_filepath = os.path.join(signature_folder, signature.get("sign_artifacts").get("manifest"))
        bundle_filepath = os.path.join(signature_folder, signature.get("sign_artifacts").get("bundle"))

        signature_method = signature.get("method")
        # Support different signing implementations (sigstore, openssl, gpg...) to verify the packages
        if signature_method == SIGNING_METHOD:
            pubkey_filepath = _get_verify_key(ref, provider, config)
            ConanOutput().info(f"Verifying package with '{provider}' provider using public key at {pubkey_filepath}")
            use_rekor = _is_rekor_enabled(config.get("verify"))

            # Verify sha file
            cosign_verify_cmd = [
                COSIGN, "-d",
                "verify-blob",
                "--key", pubkey_filepath,
                "--bundle", bundle_filepath,
                manifest_filepath
            ]
            if not use_rekor:
                cosign_verify_cmd.append("--private-infrastructure=true")
            try:
                _run_command(cosign_verify_cmd)
            except Exception as exc:
                raise ConanException(f"Error verifying artifact {manifest_filepath}: {exc}")
            if use_rekor:
                _print_rekor_url(bundle_filepath)
        else:
            raise ConanException(f"Signature method {signature_method} not supported!")
