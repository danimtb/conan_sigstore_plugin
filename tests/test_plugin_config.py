import tempfile
import textwrap
import os
import shutil

import pytest
import yaml

from tests.tools import env_set, load, replace_in_file, run, save


@pytest.fixture
def conan_test_package_signing():
    # Prepare environment vars
    conan_home = tempfile.mkdtemp(suffix='conans')
    old_env = dict(os.environ)
    env_vars = {"CONAN_HOME": conan_home,
                "COSIGN_PASSWORD": "fake-testing-pass"}
    os.environ.update(env_vars)

    # Install plugin
    repo = os.path.join(os.path.dirname(__file__), "..")
    run(f"conan config install {repo}")

    # Create dummy keys
    base_path = os.path.join(conan_home, "extensions", "plugins", "sign")
    save(os.path.join(base_path, "mykey.key"), "")
    save(os.path.join(base_path, "mykey.pub"), "")

    # Patch the plugin to avoid actually running any signing command, just print it instead
    plugin_path = os.path.join(base_path, "sign.py")
    replace_in_file(plugin_path, "def _run_command(command):",
                    textwrap.dedent("""\
                            def _run_command(command):
                                print("Command:", " ".join(command))
                                return"""))
    replace_in_file(plugin_path, "_print_rekor_url(bundle_filepath)", "pass")

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


def test_config_sign_verify_enabled(conan_test_package_signing):
    """
    Test that the plugin is correctly enabled when the config options are set to enable it.
    Also that env vars take precedence over config options.
    """
    base_path = os.path.join(conan_test_package_signing["conan_home"], "extensions", "plugins", "sign")
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    config = {"sign": {"enabled": True, "provider": "myprovider", "private_key": os.path.join(base_path, "mykey.key")},
              "verify": {"enabled": True, "providers": {"myprovider": {"public_key": os.path.join(base_path, "mykey.pub")}}}}
    yaml.dump(config, open(config_path, "w"))
    out = run("conan cache sign mypkg/1.0")
    assert "[Package sign] Summary: OK=2, FAILED=0" in out
    out = run("conan cache verify mypkg/1.0")
    assert "[Package sign] Summary: OK=2, FAILED=0" in out

    with env_set({"CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN": "0",
                  "CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY": "0"}):
        out = run("conan cache sign mypkg/1.0", error=True)
        assert "Package signing plugin is disabled" in out
        out = run("conan cache verify mypkg/1.0", error=True)
        assert "Package signing plugin is disabled" in out


def test_config_sign_verify_disabled(conan_test_package_signing):
    """
    Test that the plugin is correctly disabled when the config options are set to disable it.
    Also that env vars take precedence over config options.
    """
    base_path = os.path.join(conan_test_package_signing["conan_home"], "extensions", "plugins", "sign")
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    config = {"sign": {"enabled": False, "provider": "myprovider", "private_key": os.path.join(base_path, "mykey.key")},
              "verify": {"enabled": False,
                         "providers": {"myprovider": {"public_key": os.path.join(base_path, "mykey.pub")}}}}
    yaml.dump(config, open(config_path, "w"))
    out = run("conan cache sign mypkg/1.0", error=True)
    assert "Package signing plugin is disabled" in out
    out = run("conan cache verify mypkg/1.0", error=True)
    assert "Package signing plugin is disabled" in out

    with env_set({"CONAN_SIGSTORE_PLUGIN_ENABLE_SIGN": "1",
                  "CONAN_SIGSTORE_PLUGIN_ENABLE_VERIFY": "1"}):
        out = run("conan cache sign mypkg/1.0")
        assert "[Package sign] Summary: OK=2, FAILED=0" in out
        out = run("conan cache verify mypkg/1.0")
        assert "[Package sign] Summary: OK=2, FAILED=0" in out


def test_config_rekor_enabled(conan_test_package_signing):
    """
    Test that the config options for rekor are correctly passed to the cosign command according to the plugin configuration
    """
    base_path = os.path.join(conan_test_package_signing["conan_home"], "extensions", "plugins", "sign")
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    config = {"sign": {"enabled": True, "provider": "myprovider", "private_key": os.path.join(base_path, "mykey.key"), "use_rekor": True},
              "verify": {"enabled": True,
                         "providers": {"myprovider": {"public_key": os.path.join(base_path, "mykey.pub")}},
                         "use_rekor": True}}
    yaml.dump(config, open(config_path, "w"))
    out = run("conan cache sign mypkg/1.0")
    assert "--signing-config" not in out
    out = run("conan cache verify mypkg/1.0")
    assert "--private-infrastructure=true" not in out


def test_cosign_command(conan_test_package_signing):
    """
    Test that the cosign command is called with the expected arguments according to the plugin configuration
    """
    base_path = os.path.join(conan_test_package_signing["conan_home"], "extensions", "plugins", "sign")
    config_path = os.path.join(base_path, "sigstore-config.yaml")
    config = {"sign": {"enabled": True, "provider": "myprovider", "private_key": os.path.join(base_path, "mykey.key"),
                       "use_rekor": False},
              "verify": {"enabled": True,
                         "providers": {"myprovider": {"public_key": os.path.join(base_path, "mykey.pub")}},
                         "use_rekor": False}}
    yaml.dump(config, open(config_path, "w"))
    # sign it
    out = run("conan cache sign mypkg/1.0")
    # Find lines that start with "Command:" and extract the command
    commands = [line[len("Command: "):] for line in out.splitlines() if line.startswith("Command: ")]
    assert len(commands) == 2
    # Assert command lines have the expected cosign command with the expected arguments
    for command in commands:
        assert command.startswith("cosign -d sign-blob")
        for flag in ["--key", "--bundle", "--signing-config"]:
            assert flag in command

    # verify it
    out = run("conan cache verify mypkg/1.0")
    # Find lines that start with "Command:" and extract the command
    commands = [line[len("Command: "):] for line in out.splitlines() if line.startswith("Command: ")]
    assert len(commands) == 2
    # Assert command lines have the expected cosign command with the expected arguments
    for command in commands:
        assert command.startswith("cosign -d verify-blob")
        for flag in ["--key", "--bundle", "--private-infrastructure=true"]:
            assert flag in command
