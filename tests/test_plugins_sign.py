import tempfile
import textwrap
import os
import re

import pytest

from tools import run, save


@pytest.fixture
def conan_test_package_signing():
    # Prepare environment vars
    conan_home = tempfile.mkdtemp(suffix='conans')
    old_env = dict(os.environ)
    env_vars = {"CONAN_HOME": conan_home,
                "CONAN_SIGSTORE_DISABLE_REKOR": "1",
                "COSIGN_PASSWORD": "kkk"}
    os.environ.update(env_vars)

    # Prepare signing keys
    conan_sigstore_key = os.path.join(conan_home, "key").replace("\\", "/")
    conan_sigstore_privkey = f"{conan_sigstore_key}.key"
    conan_sigstore_pubkey = f"{conan_sigstore_key}.pub"
    run(f"cosign generate-key-pair --output-key-prefix {conan_sigstore_key}")

    # Install plugin
    repo = os.path.join(os.path.dirname(__file__), "..")
    run(f"conan config install {repo}")
    base_path = os.path.join(conan_home, "extensions", "plugins", "sign")
    old_path = os.path.join(base_path, "sign_sigstore.py")
    new_path = os.path.join(base_path, "sign.py")
    os.rename(old_path, new_path)
    config_path = os.path.join(base_path, "sigstore_config.yaml")
    save(config_path, textwrap.dedent(f"""
            sign:
              - remote: "**"
                references: "**/**@**/**"
                private_key: "{conan_sigstore_privkey}"
                public_key: "{conan_sigstore_pubkey}"

            verify:
              - remote: "**"
                references: "**/**@**/**"
                public_key: "{conan_sigstore_pubkey}"
        """))

    #Prepate test files
    current = tempfile.mkdtemp(suffix="conans")
    cwd = os.getcwd()
    os.chdir(current)
    run("conan profile detect")
    run("conan new header_lib -d name=mypkg -d version=1.0 --force")
    run("conan create .")

    try:
        yield
    finally:
        #run("conan remove * -c")
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(old_env)


def test_sigstore_check_integrity(conan_test_package_signing):
    """
    Test plugins/sign/sign_sigstore.py for Sigstore signing using Rekor

    Following env vars should be defined to run the test:
        - CONAN_SIGSTORE_DISABLE_REKOR: Enable or disable rekor to test locally (disabled by default in the test for CI)
    """
    out = run("conan cache check-integrity mypkg/1.0")
    # The package is still not signed
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2: WARN: Could not verify unsigned package" in out
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709" \
           "#4a12a155a57785a80d517f75dafee98e: WARN: Could not verify unsigned package" in out

    out = run("conan upload mypkg/1.0 -r=conancenter -c --dry-run --force")
    assert "Signing artifacts" in out
    # The package is now signed after the upload
    out = run("conan cache check-integrity mypkg/1.0")
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2: Package signature verification: ok" in out
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709" \
           "#4a12a155a57785a80d517f75dafee98e: Package signature verification: ok" in out

    run("conan install --requires mypkg/1.0 --build mypkg/1.0")
    out = run("conan cache check-integrity mypkg/1.0")
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2: Package signature verification: ok" in out
    # New built package revision has not been signed
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709" \
           "#4a12a155a57785a80d517f75dafee98e: WARN: Could not verify unsigned package" in out


def test_sigstore(conan_test_package_signing):
    """
    Test plugins/sign/sign_sigstore.py for Sigstore signing using Rekor

    Following env vars should be defined to run the test:
        - CONAN_SIGSTORE_DISABLE_REKOR: Enable or disable rekor to test locally (disabled by default in the test for CI)
    """
    out = run("conan upload mypkg/1.0 -r=conancenter -c --dry-run")
    assert "Signing artifacts" in out

    # out = run("conan install --requires mypkg/1.0 -r=conancenter")
    out = run("conan cache check-integrity mypkg/1.0")
    assert "Package signature verification: ok" in out


def test_sigstore_should_sign_and_get_sign_keys():
    from extensions.plugins.sign.sign_sigstore import _should_sign, _get_sign_keys

    config = {
        "sign": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    }
    assert _should_sign("zlib/1.2.11@None/None", "conancenter", config)
    assert "keys/ec_private.pem", "keys/ec_public.pem" == _get_sign_keys("zlib/1.2.11", "conancenter", config)

    config = {
        "sign": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    }
    assert not _should_sign("zlib/1.2.11@None/None", "conan_server", config)
    assert (None, None) == _get_sign_keys("zlib/1.2.11", "conan_server", config)

    config = {
        "sign": [
            {
                "remote": "**",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private1.pem",
                "public_key": "keys/ec_public1.pem"
            },
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "private_key": "keys/ec_private2.pem",
                "public_key": "keys/ec_public2.pem"
            }
        ]
    }
    assert _should_sign("zlib/1.2.11@None/None", "conancenter", config)
    assert "keys/ec_private1.pem", "keys/ec_public1.pem" == _get_sign_keys("zlib/1.2.11", "conancenter", config)

    assert not _should_sign("zlib/1.2.11@None/None", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@my_company/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    })
    assert _should_sign("zlib/1.2.11@my_company/None", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@my_company/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ]
    })
    assert not _should_sign("zlib/1.2.11@my_company/None", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ],
        "exclude_sign": [
            {
                "remote": "my_company_remote",
                "references": "zlib/**@**/**"
            }
        ]
    })
    assert not _should_sign("zlib/1.2.11@None/None", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ],
        "exclude_sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@None/None"
            }
        ]
    })
    assert _should_sign("zlib/1.2.11@my_company/None", "my_company_remote", {
        "sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@**/**",
                "private_key": "keys/ec_private.pem",
                "public_key": "keys/ec_public.pem"
            }
        ],
        "exclude_sign": [
            {
                "remote": "my_company_remote",
                "references": "**/**@None/None"
            }
        ]
    })


def test_sigstore_should_verify_and_get_verify_key():
    from extensions.plugins.sign.sign_sigstore import _should_verify, _get_verify_key

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public.pem"
            }
        ]
    }
    assert _should_verify("zlib/1.2.11@None/None", "conancenter", config)
    assert "keys/ec_public.pem" in _get_verify_key("zlib/1.2.11@None/None", "conancenter", config)

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public1.pem"
            },
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "public_key": "keys/ec_public2.pem"
            }
        ]
    }
    assert _should_verify("zlib/1.2.11@None/None", "conancenter", config)
    assert "keys/ec_public1.pem" in _get_verify_key("zlib/1.2.11@None/None", "conancenter", config)

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "public_key": "keys/ec_public2.pem"
            },
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public1.pem"
            }
        ]
    }
    assert _should_verify("zlib/1.2.11@None/None", "conancenter", config)
    assert "keys/ec_public2.pem" in _get_verify_key("zlib/1.2.11@None/None", "conancenter", config)

    config = {
        "verify": [
            {
                "remote": "conancenter",
                "references": "**/**@**/**",
                "public_key": "keys/ec_public1.pem"
            },
            {
                "remote": "conancenter",
                "references": "zlib/**@**/**",
                "public_key": "keys/ec_public2.pem"
            }
        ],
        "exclude_verify": [
            {
                "remote": "conancenter",
                "references": "**/**@None/None",
            }
        ]
    }
    assert not _should_verify("zlib/1.2.11@None/None", "conancenter", config)
    assert _get_verify_key("zlib/1.2.11@None/None", "conancenter", config) is None
