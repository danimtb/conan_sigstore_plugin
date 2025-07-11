"""
Plugin to sign/verify Conan packages with Sigstore's (https://www.sigstore.dev/) cosign tool and
record the signature into the Rekor transparency log for later verifications.

Requirements: The following executables should be installed and in the PATH.
    - cosign: https://github.com/sigstore/cosign/releases
    - rekor-cli: https://github.com/sigstore/rekor/releases

To use this sigstore plugin, first generate a compatible keypair and define the environment variables for the keys:

    $ cosign generate-key-pair --output-key-prefix mykey

This will generate a mykey.key private key and a mykey.pem public key.

Environment variables:
    - COSIGN_PASSWORD: Set the password of your private key. This is used when using the private key to sign packages.
    - CONAN_SIGN_PLUGIN_ENABLE_REKOR: Enable sign and verify using the Rekor CLI and rekor log  (disabled by default).
    - CONAN_SIGN_PLUGIN_ENABLE_SIGN: Enable plugin's sign feature (enabled by default).
    - CONAN_SIGN_PLUGIN_ENABLE_VERIFY: Enable plugin's verify feature (enabled by default).
"""

import fnmatch
import json
import os
import subprocess
import yaml
from shutil import which

from conan.api.model.refs import PkgReference
from conan.api.output import ConanOutput
from conan.errors import ConanException
from conan.internal.util.files import sha256sum
from conan.tools.files import save


REKOR_CLI = "rekor-cli"
COSIGN = "cosign"
CONFIG_FILENAME = "sigstore_config.yaml"
SUMMARY_FILENAME = "sign-summary.json"

SIGNATURE_EXTENSIONS = {
    # Declare the signature extension for other signing methods
    "sigstore": "sig",
    "gpg": "gpg",
    "openssl-dgst": "sig",
    "openssl-cms": "pem",
    "minisign": "minisig",
    "signify": "sig",
}

CONFIG_TEMPLATE_CONTENT = """
# Use this section to declare the name of the provider that signs the artifacts,
# the references that apply to be signed, and the path to the keys.
#
# sign:
#   enabled: true                       # (bool) Enable the signature of packages.
#   use_rekor: false                    # (bool) Enable uploading the signature to the Rekor log.
#   references:                         # (list) References or pattern of references that should be signed.
#     - "**/**@**/**"
#     - "mylib/1.0.0"
#   exclude_references:                 # (list) References or pattern of references that should NOT be signed.
#     - "**/**@"
#     - "**/**@other_company"
#   provider: "MyCompany"               # (string) Name of the provider used to sign the packages.
#   method: "sigstore"                  # (string) Name of the tool used to sign the packages.
#   private_key: "{mycompany_privkey}"  # (path -relative to this config file-) Private key to sign the packages with.
#   public_key: "{mycompany_pubkey}"    # (path -relative to this config file-) Public key to sign the packages with.


# Use this section to verify the references for each provider using the corresponding public key.
#
# verify:
#   enabled: true                                     # (bool) Enable the verification signature of packages.
#   providers:                                        # (list) Providers that sign the packages for verification.
#     conancenter:
#       references:                                   # (list) References or pattern that should be verified.
#         - "**/**@"
#       exclude_references:                           # (list) References or pattern that should NOT be verified.
#         - "zlib/1.2.11@"
#       public_key: "path/to/conancenter-public.pem"  # (path relative to this file) Public key to verify the packages with.
#       use_rekor: false                              # (bool) Enable verifying the signature against the Rekor log.
#     mycompany:
#       references:
#         - "**/**@**/**"                             # Example pattern to verify all the references for mycompany provider.
#       exclude_references:
#         - "**/**@**/testing"                        # Except for those references that have testing as channel.
#       public_key: "path/to/mycompany-public.pem"
#       use_rekor: true
"""


class NoActionRequired(Exception):
    """Raised to indicate that no action is required and execution should return early."""
    pass


def _is_rekor_enabled(partial_config):
    env_var = bool(os.getenv("CONAN_SIGN_PLUGIN_ENABLE_REKOR", False))
    if env_var:
        return True
    else:
        return partial_config.get("use_rekor", False)


def _is_sign_enabled(config):
    env_var = bool(os.getenv("CONAN_SIGN_PLUGIN_ENABLE_SIGN", True))
    if not env_var:
        return False
    else:
        return config.get("sign", {}).get("enabled", True)


def _is_verify_enabled(config):
    env_var = bool(os.getenv("CONAN_SIGN_PLUGIN_ENABLE_VERIFY", True))
    if not env_var:
        return False
    else:
        return config.get("verify", {}).get("enabled", True)


def _load_config():
    config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILENAME)
    if not os.path.exists(config_path):
        ConanOutput().highligh(f"Conan Sigstore plugin configuration file not found. "
                               f"Creating template at {config_path}")
        save(None, config_path, CONFIG_TEMPLATE_CONTENT)
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)
    return config


def _format_reference(reference):
    if isinstance(reference, PkgReference):
        reference = reference.ref
    ref_str = str(reference)
    if reference.user is None:
        ref_str = f"{ref_str}@"
    return ref_str


def _should_sign(ref, config):
    reference = _format_reference(ref)
    sign_config = config.get("sign", [])
    if sign_config:
        for rule in sign_config.get("exclude_references", []):
            if fnmatch.fnmatch(reference, rule):
                return False
        for rule in sign_config.get("references", []):
            if fnmatch.fnmatch(reference, rule):
                return True
    return False


def _get_sign_keys(ref, config):
    if _should_sign(ref, config):
        sign_config = config.get("sign", {})
        return sign_config.get("private_key"), sign_config.get("public_key")
    return None, None


def _should_verify(ref, provider, config):
    ref_str = _format_reference(ref)
    verify_config = config.get("verify")
    if verify_config:
        provider_config = verify_config.get("providers", {}).get(provider)
        if provider_config:
            for rule in provider_config.get("exclude_references", []):
                if fnmatch.fnmatch(ref_str, rule):
                    return False
            for rule in provider_config.get("references", []):
                if fnmatch.fnmatch(ref_str, rule):
                    return True
    return False


def _get_verify_key(reference, provider, config):
    if _should_verify(reference, provider, config):
        provider_config = config.get("verify", {}).get("providers", {}).get(provider, {})
        return provider_config.get("public_key")
    return None


def _check_exe_requirements(requirements):
    for exe in requirements:
        if not which(exe):
            raise ConanException(f"Missing {exe} binary. {exe} is required to sign the artifacts. "
                                 f"Make sure it is installed in your system and available in the PATH")


def _run_command(command):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,  # returns strings instead of bytes
        check=False  # we'll manually handle error checking
    )

    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )


def _sign_common_checks(ref, artifacts_folder, signature_folder, output):
    config = _load_config()
    if not _is_sign_enabled(config):
        output.highlight("Sign disabled")
        raise NoActionRequired()

    if not _should_sign(ref, config):
        raise NoActionRequired()

    files = {}
    for fname in os.listdir(artifacts_folder):
        file_path = os.path.join(artifacts_folder, fname)
        if os.path.isfile(file_path):
            sha256 = sha256sum(file_path)
            files[fname] = sha256
    sorted_files = dict(sorted(files.items()))
    summary_filepath = os.path.join(signature_folder, SUMMARY_FILENAME)
    provider = config.get("sign").get("provider")
    assert provider is not None
    method = config.get("sign").get("method")
    assert method is not None
    content = {
        "provider": provider,
        "method": method,
        "files": sorted_files
    }
    save(None, summary_filepath, json.dumps(content))
    signature_extension = SIGNATURE_EXTENSIONS.get(method)
    assert signature_extension is not None and "." not in signature_extension
    signature_filepath = f"{summary_filepath}.{signature_extension}"
    return config, summary_filepath, signature_filepath, provider, method


def sign(ref, artifacts_folder: str, signature_folder: str, output):
    try:
        config, summary_filepath, signature_filepath, provider, method = \
            _sign_common_checks(ref, artifacts_folder, signature_folder, output)
    except NoActionRequired:
        return

    if method == "sigstore":
        _check_exe_requirements([COSIGN])
        privkey_filepath, pubkey_filepath = _get_sign_keys(ref, config)

        if os.environ.get("COSIGN_PASSWORD") is None:
            raise ConanException(f"COSIGN_PASSWORD environment variable not set."
                                 f"\nIt is required to sign the packages with the private key ({privkey_filepath}).")

        output.info(f"Signing artifacts from {artifacts_folder} to {signature_folder}, "
                    f"using private key {privkey_filepath}")

        cosign_sign_cmd = [
            "cosign",
            "sign-blob",
            "--key", privkey_filepath,
            "--output-signature", signature_filepath,
            "-y",
            summary_filepath,
        ]
        try:
            _run_command(cosign_sign_cmd)
        except Exception as exc:
            raise ConanException(f"Error signing artifact {summary_filepath}: {exc}")

        output.info(f"Created signature for file {summary_filepath} at {signature_filepath}")

        if not _is_rekor_enabled(config.get("sign")):
            output.highlight(f"Rekor disabled. Skipping rekor upload command.")
        else:
            _check_exe_requirements([REKOR_CLI])
            # Upload to Rekor
            rekor_upload_cmd = [
                REKOR_CLI,
                "upload",
                "--pki-format", "x509",
                "--signature", signature_filepath,
                "--public-key", pubkey_filepath,
                "--artifact", summary_filepath
            ]
            try:
                _run_command(rekor_upload_cmd)
            except Exception as exc:
                raise ConanException(f"Error uploading artifact sign {signature_filepath}: {exc}")
            output.info(f"Uploaded signature {signature_filepath} to Rekor")
    else:
        raise ConanException(f"Signature method {method} not supported!")


def _verify_common_checks(ref, artifacts_folder, signature_folder, files, output):
    # This function serves as common checks and tasks that are independent to any signing method.
    # Returns: config, summary_filepath, signature_filepath, provider, method

    config = _load_config()
    if not _is_verify_enabled(config):
        output.highlight("Verify disabled")
        raise NoActionRequired()

    is_package = isinstance(ref, PkgReference)
    if is_package:
        download_filepath = os.path.join(artifacts_folder, "conan_package.tgz")
    else:
        download_filepath = os.path.join(artifacts_folder, "conanfile.py")

    summary_filepath = os.path.join(signature_folder, SUMMARY_FILENAME)

    if not os.path.exists(download_filepath) and not os.path.exists(summary_filepath):
        output.warning("Could not verify unsigned package.")
        raise NoActionRequired()

    with open(summary_filepath, "r") as file:
        summary_json = json.load(file)
        provider = summary_json.get("provider")
        method = summary_json.get("method")

    if not _should_verify(ref, provider, config):
        raise NoActionRequired()

    # TODO: Verify files listed in summary file correspond to the info in the <files> argument

    signature_extension = SIGNATURE_EXTENSIONS.get(method)
    assert signature_extension is not None and "." not in signature_extension
    signature_filepath = f"{summary_filepath}.{signature_extension}"

    if not os.path.exists(summary_filepath) or not os.path.exists(signature_filepath):
        raise ConanException("Missing signature files!")
    return config, summary_filepath, signature_filepath, provider, method


def verify(ref, artifacts_folder, signature_folder, files, output):
    try:
        config, summary_filepath, signature_filepath, provider, method = \
            _verify_common_checks(ref, artifacts_folder, signature_folder, files, output)
    except NoActionRequired:
        return

    # Support different implementations to verify the packages
    if method == "sigstore":
        _check_exe_requirements([COSIGN])
        pubkey_filepath = _get_verify_key(ref, provider, config)

        # Verify sha file
        cosign_verify_cmd = [
            "cosign",
            "verify-blob",
            "--key", pubkey_filepath,
            "--signature", signature_filepath,
            summary_filepath,
        ]
        try:
            _run_command(cosign_verify_cmd)
        except Exception as exc:
            raise ConanException(f"Error signing artifact {summary_filepath}: {exc}")

        if not _is_rekor_enabled(config.get("verify", {}).get("providers", {}).get(provider, {})):
            output.warning(f"Rekor disabled. Skipping rekor verify command.")
        else:
            _check_exe_requirements([REKOR_CLI])
            # Verify against Rekor
            rekor_verify_cmd = [
                REKOR_CLI,
                "verify",
                "--pki-format", "x509",
                "--signature", signature_filepath,
                "--public-key", pubkey_filepath,
                "--artifact", summary_filepath,
            ]
            try:
                _run_command(rekor_verify_cmd)
            except Exception as exc:
                raise ConanException(f"Error verifying signature for {summary_filepath}: {exc}")
            output.info(f"Signature {signature_filepath} for {summary_filepath} verified against Rekor!")
    else:
        raise ConanException(f"Signature method {method} not supported!")
    output.info(f"Package signature verification: ok")
