"""
Plugin to sign/verify Conan packages with Sigstore's (https://www.sigstore.dev/) cosign tool and
record the signature into the Rekor transparency log for later verifications.

Requirements: The following executables should be installed and in the PATH.
    - cosign: https://github.com/sigstore/cosign/releases
    - rekor-cli: https://github.com/sigstore/rekor/releases

To use this Sigstore plugin, first generate a compatible key pair and define the environment variables for the keys:

    $ cosign generate-key-pair --output-key-prefix mykey

This will generate a mykey.key private key and a mykey.pub public key.

Environment variables:
    - COSIGN_PASSWORD: Set the password of your private key. This is used when using the private key to sign packages.
    - CONAN_SIGN_PLUGIN_ENABLE_REKOR: Enable sign and verify using the Rekor CLI and rekor log (Optional, disabled by default).
    - CONAN_SIGN_PLUGIN_ENABLE_SIGN: Enable plugin's sign feature (Optional, enabled by default).
    - CONAN_SIGN_PLUGIN_ENABLE_VERIFY: Enable plugin's verify feature (Optional, enabled by default).
"""

import fnmatch
import os
import subprocess
import yaml
from shutil import which

from conan.api.model.refs import PkgReference
from conan.api.output import ConanOutput
from conan.errors import ConanException
from conan.tools.files import save
from conan.tools.pkg_signing.plugin import get_manifest_filepath, load_manifest, load_signatures, verify_files_checksums


REKOR_CLI = "rekor-cli"
COSIGN = "cosign"
CONFIG_FILENAME = "sigstore_config.yaml"
SIGSTORE_METHOD = "sigstore"


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
    if config.get("sign"):
        assert config.get("sign").get("provider") is not None, f"Missing sign::provider field in {config_path}"
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
        privkey_path = os.path.join(os.path.dirname(__file__), sign_config.get("private_key"))
        pubkey_path = os.path.join(os.path.dirname(__file__), sign_config.get("public_key"))
        return privkey_path, pubkey_path
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


def sign(ref, artifacts_folder, signature_folder, **kwargs):
    config = _load_config()
    if not _is_sign_enabled(config):
        ConanOutput().highlight("Sign disabled")

    if not _should_sign(ref, config):
        ConanOutput().highlight("Reference does not match any configuration to be signed")
        return []

    provider = config.get("sign").get("provider")
    signature_filename = "pkgsign-manifest.json.sig"
    signature_filepath = os.path.join(signature_folder, signature_filename)
    if os.path.isfile(signature_filepath):
        ConanOutput().warning(f"Package {ref.repr_notime()} is already signed")
        return load_signatures(signature_folder).get("signatures")  # Return existing signatures

    # Sign with Sigstore (checking here a sign::method from the config, could be useful to support different signing implementations (sigstore, openssl, gpg...)
    _check_exe_requirements([COSIGN])
    privkey_filepath, pubkey_filepath = _get_sign_keys(ref, config)
    manifest_filepath = get_manifest_filepath(signature_folder)

    if os.environ.get("COSIGN_PASSWORD") is None:
        raise ConanException(f"COSIGN_PASSWORD environment variable not set."
                             f"\nIt is required to sign the packages with the private key ({privkey_filepath}).")

    ConanOutput().info(f"Generating signature file at {signature_filepath} from manifest file {manifest_filepath} "
                       f"using private key {privkey_filepath}")

    cosign_sign_cmd = [
        "cosign",
        "sign-blob",
        "--key", privkey_filepath,
        "--output-signature", signature_filepath,
        "-y",
        manifest_filepath,
    ]
    try:
        _run_command(cosign_sign_cmd)
    except Exception as exc:
        raise ConanException(f"Error signing artifact {manifest_filepath}: {exc}")

    ConanOutput().info(f"Created signature for file {manifest_filepath} at {signature_filepath}")

    if not _is_rekor_enabled(config.get("sign")):
        ConanOutput().highlight(f"Rekor disabled. Skipping rekor upload command.")
    else:
        _check_exe_requirements([REKOR_CLI])
        # Upload to Rekor
        rekor_upload_cmd = [
            REKOR_CLI,
            "upload",
            "--pki-format", "x509",
            "--signature", signature_filepath,
            "--public-key", pubkey_filepath,
            "--artifact", manifest_filepath
        ]
        try:
            _run_command(rekor_upload_cmd)
        except Exception as exc:
            raise ConanException(f"Error uploading artifact sign {signature_filepath}: {exc}")
        ConanOutput().info(f"Uploaded signature {signature_filepath} to Rekor")
    return [{"method": SIGSTORE_METHOD,
             "provider": provider,
             "sign_artifacts": {"signature": signature_filename}}]


def verify(ref, artifacts_folder, signature_folder, files, **kwargs):
    config = _load_config()
    if not _is_verify_enabled(config):
        ConanOutput().highlight("Verify disabled")
        return
    try:
        signature = load_signatures(signature_folder).get("signatures")[0]
    except Exception:
        raise ConanException("No signatures found to verify")

    signature = load_signatures(signature_folder).get("signatures")[0]
    provider = signature.get("provider")
    method = signature.get("method")

    if not _should_verify(ref, provider, config):
        ConanOutput().highlight("Reference does not match any configuration to be verified")
        return

    verify_files_checksums(signature_folder, files)

    signature_filepath = os.path.join(signature_folder, signature.get("sign_artifacts").get("signature"))
    manifest_filepath = get_manifest_filepath(signature_folder)

    # Support different signing implementations (sigstore, openssl, gpg...) to verify the packages
    if method == SIGSTORE_METHOD:
        _check_exe_requirements([COSIGN])
        pubkey_filepath = _get_verify_key(ref, provider, config)

        # Verify sha file
        cosign_verify_cmd = [
            "cosign",
            "verify-blob",
            "--key", pubkey_filepath,
            "--signature", signature_filepath,
            manifest_filepath
        ]
        try:
            _run_command(cosign_verify_cmd)
            ConanOutput().info(f"Signature correctly verified with cosign")
        except Exception as exc:
            raise ConanException(f"Error verifying artifact {manifest_filepath}: {exc}")

        if not _is_rekor_enabled(config.get("verify", {}).get("providers", {}).get(provider, {})):
            ConanOutput().warning(f"Rekor disabled. Skipping rekor verify command.")
        else:
            _check_exe_requirements([REKOR_CLI])
            # Verify against Rekor
            rekor_verify_cmd = [
                REKOR_CLI,
                "verify",
                "--pki-format", "x509",
                "--signature", signature_filepath,
                "--public-key", pubkey_filepath,
                "--artifact", manifest_filepath,
            ]
            try:
                _run_command(rekor_verify_cmd)
            except Exception as exc:
                raise ConanException(f"Error verifying signature for {manifest_filepath}: {exc}")
            ConanOutput().info(f"Signature {signature_filepath} for {manifest_filepath} verified against Rekor!")
    else:
        raise ConanException(f"Signature method {method} not supported!")
