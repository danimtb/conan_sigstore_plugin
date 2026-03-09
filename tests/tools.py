import os
import subprocess

from contextlib import contextmanager


def run(cmd, error=False, *, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    print(f"Running: {cmd}")
    process = subprocess.Popen(cmd, 
                               stdout=stdout,
                               stderr=stderr,
                               stdin=subprocess.PIPE,
                               shell=True)

    out, err = process.communicate()
    out = out.decode("utf-8") if stdout else ""
    err = err.decode("utf-8") if stderr else ""
    ret = process.returncode

    output = err + out
    output = output.replace('\r\n', '\n')
    if ret != 0 and not error:
        raise Exception("Failed cmd: {}\n{}".format(cmd, output))
    if ret == 0 and error:
        raise Exception(
            "Cmd succeded (failure expected): {}\n{}".format(cmd, output))
    print(f"Output: {output}")
    return output


def save(f, content):
    with open(f, "w") as f:
        f.write(content)


def load(f):
    with open(f, "r") as f:
        return f.read()

def replace_in_file(file_path, old_str, new_str):
    content = load(file_path)
    content = content.replace(old_str, new_str)
    save(file_path, content)


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
