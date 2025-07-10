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
    - CONAN_SIGSTORE_ENABLE_REKOR: Enable sign and verify using the Rekor CLI and rekor log  (disabled by default).
    - CONAN_SIGSTORE_ENABLE_SIGN: Enable plugin's sign feature (enabled by default).
    - CONAN_SIGSTORE_ENABLE_VERIFY: Enable plugin's verify feature (enabled by default).
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
#     - "**/**@None/None"
#     - "**/**@other_company/**"
#   provider: "MyCompany"               # (string) Name of the provider used to sign the packages.
#   private_key: "{mycompany_privkey}"  # (path -relative to this config file-) Private key to sign the packages with.
#   public_key: "{mycompany_pubkey}"    # (path -relative to this config file-) Public key to sign the packages with.


# Use this section to verify the references for each provider using the corresponding public key.
#
# verify:
#   enabled: true                                     # (bool) Enable the verification signature of packages.
#   providers:                                        # (list) Providers that sign the packages for verification.
#     conancenter:
#       references:                                   # (list) References or pattern that should be verified.
#         - "**/**@None/None"
#       exclude_references:                           # (list) References or pattern that should NOT be verified.
#         - "zlib/1.2.11@None/None"
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


def _is_rekor_enabled(partial_config):
    env_var = bool(os.getenv("CONAN_SIGSTORE_ENABLE_REKOR", False))
    if env_var:
        return True
    else:
        return partial_config.get("use_rekor", False)


def _is_sign_enabled(config):
    env_var = bool(os.getenv("CONAN_SIGSTORE_ENABLE_SIGN", True))
    if not env_var:
        return False
    else:
        return config.get("sign", {}).get("enabled", True)


def _is_verify_enabled(config):
    env_var = bool(os.getenv("CONAN_SIGSTORE_ENABLE_VERIFY", True))
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
    _check_config(config)
    return config


def _check_config(config):
    sign_config = config.get("sign")
    if sign_config and sign_config.get("enabled", True):
        provider = sign_config.get("provider")
        assert provider is not None, "sign.provider should be defined to sign artifacts"
        assert "*" not in provider, f"sign.provider does not allow patterns: {provider}"
        assert sign_config.get("references")
        assert sign_config.get("private_key")
        assert sign_config.get("public_key")
    verify_config = config.get("verify")
    if verify_config and verify_config.get("enabled", True):
        providers_config = verify_config.get("providers", {})
        providers = [next(iter(provider)) for provider in providers_config if provider]
        assert len(providers) == len(set(providers))
        for _, provider_data in providers_config.items():
            assert provider_data.get("references")
            assert provider_data.get("public_key")


def _format_reference(reference):
    try:
        return f"{reference.name}/{reference.version}@{reference.user}/{reference.channel}"
    except AttributeError:
        return f"{reference.ref.name}/{reference.ref.version}@{reference.ref.user}/{reference.ref.channel}"


def _should_sign(reference, config):
    sign_config = config.get("sign", [])
    if sign_config:
        for rule in sign_config.get("exclude_references", []):
            if fnmatch.fnmatch(reference, rule):
                return False
        for rule in sign_config.get("references", []):
            if fnmatch.fnmatch(reference, rule):
                return True
    return False


def _get_sign_keys(reference, config):
    if _should_sign(reference, config):
        sign_config = config.get("sign", {})
        return sign_config.get("private_key"), sign_config.get("public_key")
    return None, None


def _should_verify(reference, provider, config):
    print(config)
    verify_config = config.get("verify")
    if verify_config:
        provider_config = verify_config.get("providers", {}).get(provider)
        if provider_config:
            for rule in provider_config.get("exclude_references", []):
                if fnmatch.fnmatch(reference, rule):
                    return False
            for rule in provider_config.get("references", []):
                if fnmatch.fnmatch(reference, rule):
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


def sign(ref, artifacts_folder: str, signature_folder: str, output):
    config = _load_config()
    if not _is_sign_enabled(config):
        output.highlight("Sign disabled")
        return

    _check_exe_requirements([COSIGN])
    ref_str = _format_reference(ref)
    if _should_sign(ref_str, config):
        privkey_filepath, pubkey_filepath = _get_sign_keys(ref_str, config)
    else:
        return

    if os.environ.get("COSIGN_PASSWORD") is None:
        raise ConanException(f"COSIGN_PASSWORD environment variable not set."
                             f"\nIt is required to sign the packages with the private key ({privkey_filepath}).")

    # Sign & upload each artifact using X509
    output.info(f"Signing artifacts from {artifacts_folder} to {signature_folder}, "
                f"using private key {privkey_filepath}")

    files = {}
    for fname in os.listdir(artifacts_folder):
        file_path = os.path.join(artifacts_folder, fname)
        if os.path.isfile(file_path):
            sha256 = sha256sum(file_path)
            files[fname] = sha256
    sorted_files = dict(sorted(files.items()))
    summary_file = os.path.join(signature_folder, SUMMARY_FILENAME)
    content = {
        "provider": config.get("sign").get("provider"),
        "files": sorted_files
    }
    save(None, summary_file, json.dumps(content))
    signature_file = f"{summary_file}.sig"

    # Sign
    cosign_sign_cmd = [
        "cosign",
        "sign-blob",
        "--key", privkey_filepath,
        "--output-signature", signature_file,
        "-y",
        summary_file,
    ]
    try:
        _run_command(cosign_sign_cmd)
    except Exception as exc:
        raise ConanException(f"Error signing artifact {summary_file}: {exc}")

    output.info(f"Created signature for file {summary_file} at {signature_file}")

    if not _is_rekor_enabled(config.get("verify")):
        output.highlight(f"Rekor disabled. Skipping rekor upload command.")
    else:
        _check_exe_requirements([REKOR_CLI])
        # Upload to Rekor
        rekor_upload_cmd = [
            REKOR_CLI,
            "upload",
            "--pki-format", "x509",
            "--signature", signature_file,
            "--public-key", pubkey_filepath,
            "--artifact", summary_file
        ]
        try:
            _run_command(rekor_upload_cmd)
        except Exception as exc:
            raise ConanException(f"Error uploading artifact sign {signature_file}: {exc}")
        output.info(f"Uploaded signature {signature_file} to Rekor")


def verify(ref, artifacts_folder, signature_folder, files, output):
    config = _load_config()
    if not _is_verify_enabled(config):
        output.highlight("Verify disabled")
        return

    _check_exe_requirements([COSIGN])
    ref_str = _format_reference(ref)

    is_package = isinstance(ref, PkgReference)
    if is_package:
        download_file_path = os.path.join(artifacts_folder, "conan_package.tgz")
    else:
        download_file_path = os.path.join(artifacts_folder, "conanfile.py")

    summary_file = os.path.join(signature_folder, SUMMARY_FILENAME)
    signature_file = f"{summary_file}.sig"

    if not os.path.exists(download_file_path) and not os.path.exists(signature_file):
        output.warning("Could not verify unsigned package.")
        return

    with open(summary_file, "r") as file:
        provider = json.load(file)["provider"]

    if _should_verify(ref_str, provider, config):
        pubkey_filepath = _get_verify_key(ref_str, provider, config)
    else:
        return

    if not os.path.exists(summary_file) or not os.path.exists(signature_file):
        raise ConanException("Missing signature files!")

    # Verify sha file
    cosign_verify_cmd = [
        "cosign",
        "verify-blob",
        "--key", pubkey_filepath,
        "--signature", signature_file,
        summary_file,
    ]
    try:
        _run_command(cosign_verify_cmd)
    except Exception as exc:
        raise ConanException(f"Error signing artifact {summary_file}: {exc}")

    if not _is_rekor_enabled(config.get("verify", {}).get("providers", {}).get(provider, {})):
        output.warning(f"Rekor disabled. Skipping rekor verify command.")
    else:
        _check_exe_requirements([REKOR_CLI])
        # Verify against Rekor
        rekor_verify_cmd = [
            REKOR_CLI,
            "verify",
            "--pki-format", "x509",
            "--signature", signature_file,
            "--public-key", pubkey_filepath,
            "--artifact", summary_file,
        ]
        try:
            _run_command(rekor_verify_cmd)
        except Exception as exc:
            raise ConanException(f"Error verifying signature for {summary_file}: {exc}")
        output.info(f"Signature {signature_file} for {summary_file} verified against Rekor!")
    output.info(f"Package signature verification: ok")
