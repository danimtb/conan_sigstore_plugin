"""
Plugin to sign/verify Conan packages with Sigstore's (https://www.sigstore.dev/) transparency log using the Rekor CLI

Requirements: The following executables should be installed and in the PATH.
    - openssl: https://openssl-library.org/source/
    - rekor-cli: https://github.com/sigstore/rekor/releases

To use this sigstore plugin, first generate a compatible keypair and define the environment variables for the keys:

    $ openssl ecparam -genkey -name prime256v1 > ec_private.pem
    $ openssl ec -in ec_private.pem -pubout > ec_public.pem

Environment variables:
    - CONAN_SIGSTORE_DISABLE_REKOR: Disable the rekor CLI calls, just sign/verify files with openssl.
    - CONAN_SIGSTORE_DISABLE_SIGN: Disable plugin's sign feature.
    - CONAN_SIGSTORE_DISABLE_VERIFY: Disable plugin's verify feature.
"""

import fnmatch
import os
import subprocess
import yaml
from shutil import which

from conan.api.output import cli_out_write
from conan.errors import ConanException
try:
    from conan.internal.model.recipe_ref import RecipeReference
    from conan.internal.model.package_ref import PkgReference
except:
    from conans.model.recipe_ref import RecipeReference
    from conans.model.package_ref import PkgReference
from conan.internal.util.files import sha256sum
from conan.tools.files import save


REKOR_CLI = "rekor-cli"
OPENSSL = "openssl"
CONFIG_FILENAME = "sigstore_config.yaml"


def _is_rekor_disabled():
    return bool(os.getenv("CONAN_SIGSTORE_DISABLE_REKOR", False))


def _is_sign_disabled():
    return bool(os.getenv("CONAN_SIGSTORE_DISABLE_SIGN", False))


def _is_verify_disabled():
    return bool(os.getenv("CONAN_SIGSTORE_DISABLE_VERIFY", False))


def _load_config():
    config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILENAME)
    with open(config_path, "r") as file:
        return yaml.safe_load(file)


def _format_reference(reference):
    try:
        return f"{reference.name}/{reference.version}@{reference.user}/{reference.channel}"
    except:
        return f"{reference.ref.name}/{reference.ref.version}@{reference.ref.user}/{reference.ref.channel}"


def _should_sign(reference, remote, config):
    for rule in config.get("exclude_sign", []):
        if fnmatch.fnmatch(remote, rule["remote"]) and fnmatch.fnmatch(reference, rule["references"]):
            return False

    for rule in config.get("sign", []):
        if fnmatch.fnmatch(remote, rule["remote"]) and fnmatch.fnmatch(reference, rule["references"]):
            return True
    return False


def _get_sign_keys(reference, remote, config):
    if _should_sign(reference, remote, config):
        for rule in config.get("sign", []):
            if fnmatch.fnmatch(remote, rule["remote"]) and fnmatch.fnmatch(reference, rule["references"]):
                return rule.get("private_key"), rule.get("public_key")
    return None, None


def _should_verify(reference, remote, config):
    for rule in config.get("exclude_verify", []):
        if fnmatch.fnmatch(remote, rule["remote"]) and fnmatch.fnmatch(reference, rule["references"]):
            return False

    for rule in config.get("verify", []):
        if fnmatch.fnmatch(remote, rule["remote"]) and fnmatch.fnmatch(reference, rule["references"]):
            return True
    return False


def _get_verify_key(reference, remote, config):
    if _should_verify(reference, remote, config):
        for rule in config.get("verify", []):
            if fnmatch.fnmatch(remote, rule["remote"]) and fnmatch.fnmatch(reference, rule["references"]):
                return rule.get("public_key")
    return None


def _check_requirements():
    for exe in [REKOR_CLI, OPENSSL]:
        if not which(exe):
            raise ConanException(f"Missing {exe} binary. {exe} is required to sign the artifacts. "
                                 f"Make sure it is installed in your system and available in the PATH")
    config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILENAME)
    if not os.path.exists(config_path):
        raise ConanException(f"Configuration file for the plugin not found at {config_path}. "
                             f"Please make sure it exists.")

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

    if result.stderr:
        raise ConanException(f"Command produced stderr output:\n{result.stderr}")


def sign(ref, artifacts_folder: str, signature_folder: str, **kwargs):
    if _is_sign_disabled():
        cli_out_write("Sign disabled")
        return

    _check_requirements()
    config = _load_config()
    ref_str = _format_reference(ref)
    if _should_sign(ref_str, "**", config):
        privkey_filepath, pubkey_filepath = _get_sign_keys(ref_str, "**", config)
    else:
        return

    # Sign & upload each artifact using X509
    cli_out_write(f"Signing artifacts from {artifacts_folder} to {signature_folder}, "
                  f"using private key {privkey_filepath}")

    files = {}
    for fname in os.listdir(artifacts_folder):
        file_path = os.path.join(artifacts_folder, fname)
        if os.path.isfile(file_path):
            sha256 = sha256sum(file_path)
            files[fname] = sha256
    sorted_files = dict(sorted(files.items()))
    sha_file = os.path.join(signature_folder, "files-sha256.txt")
    save(None, sha_file, "\n".join([f"{fname}  {sha}" for fname, sha in sorted_files.items()]))
    out_fpath = f"{sha_file}.sig"

    # Sign
    # TODO: Sign with cosign -> cosign sign-blob --key <CONAN_SIGSTORE_PPRIVKEY (.pem)> <FILETOSIGN> > <SIGNATUREFILENAME (.sig)>
    openssl_sign_cmd = [
        "openssl.exe",
        "dgst",
        "-sha256",
        "-sign", privkey_filepath,
        "-out", out_fpath,
        sha_file,
    ]
    try:
        subprocess.check_call(openssl_sign_cmd, stdout=subprocess.DEVNULL, shell=True)
    except Exception as exc:
        raise ConanException(f"Error signing artifact {sha_file}: {exc}")

    cli_out_write(f"Created signature for file {sha_file} at {out_fpath}")

    # Upload to Rekor
    rekor_upload_cmd = [
        REKOR_CLI,
        "upload",
        "--pki-format", "x509",
        "--signature", out_fpath,
        "--public-key", pubkey_filepath,
        "--artifact", sha_file
    ]
    if _is_rekor_disabled():
        cli_out_write(f"Rekor disabled. Skipping upload command: {' '.join(rekor_upload_cmd)}")
    else:
        try:
            _run_command(rekor_upload_cmd)
        except Exception as exc:
            raise ConanException(f"Error uploading artifact sign {out_fpath}: {exc}")
        cli_out_write(f"Uploaded signature {out_fpath} to Sigstore")


def verify(ref, artifacts_folder, signature_folder, files, **kwargs):
    if _is_verify_disabled():
        cli_out_write("Verify disabled")
        return

    _check_requirements()
    config = _load_config()
    ref_str = _format_reference(ref)
    if _should_verify(ref_str, "**", config):
        pubkey_filepath = _get_verify_key(ref_str, "**", config)
    else:
        return

    sha_file = os.path.join(signature_folder, "files-sha256.txt")
    sig_fpath = f"{sha_file}.sig"

    if not os.path.exists(sha_file):
        return
    if not os.path.exists(sig_fpath):
        raise ConanException(f"Missing signature file at {sig_fpath}")

    # Verify sha file

    # TODO: Verify signature locally with openssl:
    # TODO: $ openssl dgst -sha256 -verify <CONAN_SIGSTORE_PUBKEY (.pem)> -signature <SIGNATUREFILENAME (.sig)> <FILETOSIGN>
    # TODO: Verify signature locally with cosign:
    # TODO: cosign verify-blob --key <CONAN_SIGSTORE_PUBKEY (.pem)> --signature <SIGNATUREFILENAME (.sig)> <FILETOSIGN>

    # Verify against Rekor
    rekor_verify_cmd = [
        REKOR_CLI,
        "verify",
        "--pki-format", "x509",
        "--signature", sig_fpath,
        "--public-key", pubkey_filepath,
        "--artifact", sha_file,
    ]
    if _is_rekor_disabled():
        cli_out_write(f"Rekor disabled. Skipping verify command: {' '.join(rekor_verify_cmd)}")
    else:
        try:
            _run_command(rekor_verify_cmd)
            #subprocess.check_call(rekor_verify_cmd, stdout=subprocess.DEVNULL)
        except Exception as exc:
            raise ConanException(f"{ref}: Error verifying signature for {sha_file}: {exc}")
        cli_out_write(f"{ref}: Signature {sig_fpath} for {sha_file} verified against Sigstore!")
