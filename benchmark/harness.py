# benchmark/harness.py — generic subprocess + git helpers used by plugins
# and framework code. NO repo-specific assumptions.
import os
import shlex
import socket
import subprocess
import time


def run(cmd, cwd=None, check=True, capture=False, env=None):
    """Run a command (list form). Returns CompletedProcess. Echoes the command."""
    print(f"  $ {' '.join(shlex.quote(x) for x in cmd)}")
    return subprocess.run(
        cmd, cwd=cwd, check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        env=env,
    )


def git(repo_dir, args, check=True, capture=False):
    """Run a git command in the given repo dir."""
    return run(["git", "-C", str(repo_dir), *args], check=check, capture=capture)


def git_show(repo_dir, tag, rel_path) -> str:
    """git show <tag>:<rel_path>  →  file contents (no checkout)."""
    p = subprocess.run(["git", "-C", str(repo_dir), "show", f"{tag}:{rel_path}"],
                       text=True, capture_output=True)
    if p.returncode != 0:
        return ""
    return p.stdout


def diff_applies(repo_dir, tag, diff_text: str) -> bool:
    """Test whether `diff_text` cleanly applies to the given tag."""
    if not diff_text.strip():
        return False
    cur_branch = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True).stdout.strip()
    try:
        # checkout the tag in detached mode for the test
        subprocess.run(["git", "-C", str(repo_dir), "checkout", "-f", tag],
                       check=False, capture_output=True)
        p = subprocess.run(["git", "-C", str(repo_dir), "apply", "--check",
                            "--whitespace=nowarn", "-"],
                           input=diff_text, text=True, capture_output=True)
        return p.returncode == 0
    finally:
        if cur_branch and cur_branch != "HEAD":
            subprocess.run(["git", "-C", str(repo_dir), "checkout", "-f",
                            cur_branch],
                           check=False, capture_output=True)


def wait_port(port, host="127.0.0.1", timeout=10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def ensure_dirs(*dirs):
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def tail(path, n=30) -> str:
    try:
        with open(path) as fh:
            return "".join(fh.readlines()[-n:])
    except OSError:
        return "(no log)"
