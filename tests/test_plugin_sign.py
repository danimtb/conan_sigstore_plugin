import tempfile
import textwrap
import os

import pytest

from tools import run, save
from conan.api.model.refs import RecipeReference


@pytest.fixture
def conan_test_package_signing():
    # Prepare environment vars
    conan_home = tempfile.mkdtemp(suffix='conans')
    old_env = dict(os.environ)
    env_vars = {"CONAN_HOME": conan_home,
                "CONAN_SIGSTORE_DISABLE_REKOR": "1",
                "COSIGN_PASSWORD": "fake-testing-pass"}
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
    config_path = os.path.join(base_path, "sigstore_config.yaml")
    save(config_path, textwrap.dedent(f"""
        sign:
          references:
            - "**/**@"
          provider: "conan"
          method: "sigstore"
          private_key: "{conan_sigstore_privkey}"
          public_key: "{conan_sigstore_pubkey}"

        verify:
          providers:
            conan:
              references:
                - "**/**@"
              public_key: "{conan_sigstore_pubkey}"
    """))

    # Prepare test files
    current = tempfile.mkdtemp(suffix="conans")
    cwd = os.getcwd()
    os.chdir(current)
    run("conan profile detect")
    run("conan new header_lib -d name=mypkg -d version=1.0 --force")
    run("conan create .")

    try:
        yield
    finally:
        run("conan remove * -c")
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(old_env)


def test_cache_sign_verify(conan_test_package_signing):
    """
    Test verifying package with conan cache commands
    """
    out = run("conan cache verify mypkg/1.0")
    # The package is still not signed
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2\r\n    :: Warn: Could not verify unsigned package" in out
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709" \
           "#4a12a155a57785a80d517f75dafee98e\r\n    :: Warn: Could not verify unsigned package" in out

    out = run("conan cache sign mypkg/1.0")
    assert "Signing artifacts" in out
    # TODO: assert
    # The package is now signed
    out = run("conan cache verify mypkg/1.0")
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2\r\n    :: Signature correctly verified with cosign" in out
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709" \
           "#4a12a155a57785a80d517f75dafee98e\r\n    :: Signature correctly verified with cosign" in out

    run("conan install --requires mypkg/1.0 --build mypkg/1.0")
    out = run("conan cache verify mypkg/1.0")
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2\r\n    :: Signature correctly verified with cosign" in out
    # New built package revision has not been signed
    assert "mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709" \
           "#4a12a155a57785a80d517f75dafee98e\r\n    :: Warn: Could not verify unsigned package" in out


def test_sigstore(conan_test_package_signing):
    """
    Test the plugin's normal flow: upload (sign), install (verify)
    """
    out = run("conan upload mypkg/1.0 -r=conancenter -c --dry-run")
    assert "Signing artifacts" in out

    # FIXME: This should be a conan install from a remote
    out = run("conan cache verify mypkg/1.0")
    assert "Signature correctly verified with cosign" in out


def test_sigstore_should_sign_and_get_sign_keys():
    from extensions.plugins.sign.sign import _should_sign, _get_sign_keys

    # Test conan center reference
    config = {
        "sign": {
            "references": ["**/**"],
            "private_key": "keys/ec_private.pem",
            "public_key": "keys/ec_public.pem"
        }
    }
    assert _should_sign(RecipeReference("zlib", "1.2.11"), config)
    assert "keys/ec_private.pem", "keys/ec_public.pem" == _get_sign_keys("zlib/1.2.11", config)

    # Test exclude reference
    config = {
        "sign": {
            "references": ["**/**@**/**"],
            "exclude_references": ["**/**@"],
            "private_key": "keys/ec_private.pem",
            "public_key": "keys/ec_public.pem"
        }
    }
    assert not _should_sign(RecipeReference("zlib", "1.2.11"), config)
    assert (None, None) == _get_sign_keys(RecipeReference("zlib", "1.2.11"), config)


    assert not _should_sign(RecipeReference("zlib", "1.2.11"), {
        "sign": {
            "references": ["**/**@my_company/**"],
        }
    })
    assert _should_sign(RecipeReference("zlib", "1.2.11", "my_company"), {
        "sign": {
            "references": ["**/**@my_company"],
        }
    })
    assert not _should_sign(RecipeReference("zlib", "1.2.11"), {
        "sign": {
            "references": ["**/**@**/**"],
            "exclude_references": ["zlib/**@**/**"]
        }
    })
    assert not _should_sign(RecipeReference("zlib", "1.2.11"), {
        "sign": {
            "references": ["**/**@**/**"],
            "exclude_references": ["**/**@"]
        }
    })
    assert _should_sign(RecipeReference("zlib", "1.2.11", "my_company"), {
        "sign": {
            "references": ["**/**@**"],
            "exclude_references": ["**/**@"]
        }
    })


def test_sigstore_should_verify_and_get_verify_key():
    from extensions.plugins.sign.sign import _should_verify, _get_verify_key

    config = {
        "verify":
            {
                "providers": {
                    "conancenter": {
                        "references": ["**/**@"],
                        "public_key": "keys/ec_public.pem"
                    }
                }
            }
    }
    assert _should_verify(RecipeReference("zlib", "1.2.11"), "conancenter", config)
    assert "keys/ec_public.pem" in _get_verify_key(RecipeReference("zlib", "1.2.11"), "conancenter", config)

    config = {
        "verify": {
            "providers": {
                "conancenter": {
                    "references": ["**/**@"],
                    "exclude_references": ["**/**@"],
                    "public_key": "keys/ec_public1.pem"
                }
            }
        }
    }
    assert not _should_verify(RecipeReference("zlib", "1.2.11"), "conancenter", config)
    assert _get_verify_key(RecipeReference("zlib", "1.2.11"), "conancenter", config) is None

    config = {
        "verify": {
            "providers": {
                "conancenter": {
                    "references": ["**/**@"],
                    "public_key": "keys/ec_public1.pem"
                },
                "mycompany": {
                    "references": ["**/**@"],
                    "public_key": "keys/ec_public2.pem"
                }
            }
        }
    }
    assert _should_verify(RecipeReference("zlib", "1.2.11"), "mycompany", config)
    assert "keys/ec_public2.pem" in _get_verify_key(RecipeReference("zlib", "1.2.11"), "mycompany", config)

    config = {
        "verify": {
            "providers": {
                "conancenter": {
                    "references": ["**/**@"],
                    "public_key": "keys/ec_public1.pem"
                },
                "mycompany": {
                    "references": ["**/**@mycompany"],
                    "public_key": "keys/ec_public2.pem"
                }
            }
        }
    }
    assert not _should_verify(RecipeReference("zlib", "1.2.11"), "mycompany", config)
    assert _get_verify_key(RecipeReference("zlib", "1.2.11"), "mycompany", config) is None
    assert _should_verify(RecipeReference("zlib", "1.2.11", "mycompany"), "mycompany", config)
    assert not _should_verify(RecipeReference("zlib", "1.2.11", "mycompany", "testing"), "mycompany", config)