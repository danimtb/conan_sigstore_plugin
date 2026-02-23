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
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    save(config_path, textwrap.dedent(f"""
        sign:
          references:
            - "*/*"
            - "*/*@other_company"
          provider: "conan"
          private_key: "{conan_sigstore_privkey}"
          public_key: "{conan_sigstore_pubkey}"

        verify:
          providers:
            conan:
              references:
                - "*/*"
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
        os.rmdir(conan_home)
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(old_env)


def test_cache_sign_verify(conan_test_package_signing):
    """
    Test verifying package with conan cache commands
    """
    out = run("conan cache verify mypkg/1.0")
    # The package is still not signed
    assert "WARN: Could not verify unsigned package" in out

    # sign it
    out = run("conan cache sign mypkg/1.0")
    assert "Generating signature file" in out
    assert "Wrote bundle to file" in out

    # The package is now signed
    out = run("conan cache verify mypkg/1.0")
    assert "Signature correctly verified with cosign" in out
    assert "[Package sign] Summary: OK=2, FAILED=0" in out

    # Rebuild the package, which will create a new package revision, but it will not be signed
    run("conan install --requires mypkg/1.0 --build mypkg/1.0")
    out = run("conan cache verify mypkg/1.0")
    assert "Signature correctly verified with cosign" in out
    assert "WARN: Could not verify unsigned package" in out

    # Sign package only
    out = run("conan cache sign mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:*")
    assert "Wrote bundle to file" in out

    # Test signing already signed package
    out = run("conan cache sign mypkg/1.0")
    assert "WARN: Package mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2 is already signed" in out
    assert "WARN: Package mypkg/1.0#3db0ffbad94d82b8b7a4cbbb77539bb2:da39a3ee5e6b4b0d3255bfef95601890afd80709#4a12a155a57785a80d517f75dafee98e is already signed" in out


def test_cache_should_sign_verify(conan_test_package_signing):
    """Test that packages that should not be signed or verified according to the config are skipped"""
    # create new package that should not be signed
    run("conan new header_lib -d name=otherpkg -d version=1.0 --force")
    run("conan create . --user mycompany")
    out = run("conan cache sign otherpkg/1.0@mycompany")
    assert "Reference does not match any configuration to be signed" in out

    # create new package that should not be verified
    run("conan create . --user other_company")
    run("conan cache sign otherpkg/1.0@other_company")
    out = run("conan cache verify otherpkg/1.0@other_company")
    assert "Reference does not match any configuration to be verified" in out

# def test_verify_unsigned_package(conan_test_package_signing):
# def test_sign_already_signed_package(conan_test_package_signing):
# def test_should_not_verify
# def test_should_not_sign
# test rekor
# test env vars /config enabled disabled for signing and verifying


def test_should_sign_reference():
    from extensions.plugins.sign.sign import _should_sign_reference
    assert _should_sign_reference(RecipeReference("zlib", "1.2.11"), {"sign": {"references": ["*/*"]}})
    assert not _should_sign_reference(RecipeReference("zlib", "1.2.11"),
                                      {"sign": {"references": ["*/*@*/*"], "exclude_references": ["*/*"]}})
    assert not _should_sign_reference(RecipeReference("zlib", "1.2.11"),
                                      {"sign": {"references": ["*/*@my_company/*"],}})
    assert _should_sign_reference(RecipeReference("zlib", "1.2.11", "my_company"),
                                  {"sign": {"references": ["*/*@my_company"]}})
    assert not _should_sign_reference(RecipeReference("zlib", "1.2.11"),
                                      {"sign": {"references": ["*/*@*/*"], "exclude_references": ["zlib/*@*/*"]}})
    assert not _should_sign_reference(RecipeReference("zlib", "1.2.11"),
                                      {"sign": {"references": ["*/*@*/*"], "exclude_references": ["*/*"]}})
    assert _should_sign_reference(RecipeReference("zlib", "1.2.11", "my_company"),
                                  {"sign": {"references": ["*/*@*"], "exclude_references": ["*/*"]}})


def test_should_verify_reference():
    from extensions.plugins.sign.sign import _should_verify_reference

    assert _should_verify_reference(RecipeReference("zlib", "1.2.11"), "conancenter",
                                    {"verify": {"providers": {"conancenter": {"references": ["*/*"]}}}})
    assert not _should_verify_reference(RecipeReference("zlib", "1.2.11"), "conancenter",
                                        {"verify": {"providers": {"conancenter": {
                                            "references": ["*/*"], "exclude_references": ["*/*"]}}}})
    assert _should_verify_reference(RecipeReference("zlib", "1.2.11"), "mycompany", {
        "verify": {
            "providers": {
                "conancenter": {
                    "references": ["*/*"],
                    "public_key": "keys/ec_public1.pem"
                },
                "mycompany": {
                    "references": ["*/*"],
                    "public_key": "keys/ec_public2.pem"
                }
            }
        }
    })

    config = {
        "verify": {
            "providers": {
                "conancenter": {
                    "references": ["*/*"],
                    "public_key": "keys/ec_public1.pem"
                },
                "mycompany": {
                    "references": ["*/*@mycompany"],
                    "public_key": "keys/ec_public2.pem"
                }
            }
        }
    }
    assert not _should_verify_reference(RecipeReference("zlib", "1.2.11"), "mycompany", config)
    assert _should_verify_reference(RecipeReference("zlib", "1.2.11", "mycompany"), "mycompany", config)
    assert not _should_verify_reference(RecipeReference("zlib", "1.2.11", "mycompany", "testing"), "mycompany",
                                        config)
    assert not _should_verify_reference(RecipeReference("zlib", "1.2.11"),"non-existent-provider", config)
