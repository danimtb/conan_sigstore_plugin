import tempfile
import textwrap
import os
import shutil
from contextlib import contextmanager

import pytest
import yaml

from tools import run


@pytest.fixture
def conan_test_package_signing():
    # Prepare environment vars
    conan_home = tempfile.mkdtemp(suffix='conans')
    old_env = dict(os.environ)
    env_vars = {"CONAN_HOME": conan_home}
    os.environ.update(env_vars)

    # Install plugin
    repo = os.path.join(os.path.dirname(__file__), "..")
    run(f"conan config install {repo}")

    # Prepare test files
    current = tempfile.mkdtemp(suffix="conans")
    cwd = os.getcwd()
    os.chdir(current)
    run("conan profile detect")
    run("conan new header_lib -d name=mypkg -d version=1.0 --force")
    run("conan create .")

    try:
        yield {"conan_home": conan_home}
    finally:
        shutil.rmtree(conan_home)
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(old_env)


@contextmanager
def env_set(env_vars: dict):
    """
    Temporarily sets environment variables from a dictionary.
    Restores the original environment upon exit.
    """
    old_env = {k: os.environ.get(k) for k in env_vars}

    try:
        os.environ.update(env_vars)
        yield
    finally:
        for key, original_value in old_env.items():
            if original_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_value


def test_config_enabled(conan_test_package_signing):
    base_path = os.path.join(conan_test_package_signing["conan_home"], "extensions", "plugins", "sign")
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    config = {"sign": {"enabled": True, "provider": "kk"}, "verify": {"enabled": True}}
    yaml.dump(config, open(config_path, "w"))
    out = run("conan cache sign mypkg/1.0")
    assert "Sign disabled" not in out
    out = run("conan cache verify mypkg/1.0")
    assert "Verify disabled" not in out

    with env_set({"CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN": "0",
                  "CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY": "0"}):
        out = run("conan cache sign mypkg/1.0")
        assert "Sign disabled" in out
        out = run("conan cache verify mypkg/1.0")
        assert "Verify disabled" in out


def test_config_disabled(conan_test_package_signing):
    base_path = os.path.join(conan_test_package_signing["conan_home"], "extensions", "plugins", "sign")
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    config = {"sign": {"enabled": False, "provider": "kk"}, "verify": {"enabled": False}}
    yaml.dump(config, open(config_path, "w"))
    out = run("conan cache sign mypkg/1.0")
    assert "Sign disabled" in out
    out = run("conan cache verify mypkg/1.0")
    assert "Verify disabled" in out

    with env_set({"CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN": "1",
                  "CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY": "1"}):
        out = run("conan cache sign mypkg/1.0")
        assert "Sign disabled" not in out
        out = run("conan cache verify mypkg/1.0")
        assert "Verify disabled" not in out
