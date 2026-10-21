# repos/git/runtime.py - GitRuntime: drives the git CLI binary.
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from benchmark.core.runtime import Runtime


class GitRuntime(Runtime):
    """Short-lived Git CLI runtime with isolated HOME and temp work dirs."""

    def __init__(self, repo_dir, timeout_s: int = 20):
        self.repo_dir = str(repo_dir)
        self.timeout_s = timeout_s
        self.git_bin = os.path.join(self.repo_dir, "bin-wrappers", "git")
        if not os.path.exists(self.git_bin):
            self.git_bin = os.path.join(self.repo_dir, "git")
        self.tmpdir = None
        self.home = None
        self.env = None

    def __enter__(self):
        if not os.path.exists(self.git_bin):
            raise RuntimeError(f"git binary not found at {self.git_bin}; build first")
        self.tmpdir = tempfile.mkdtemp(prefix="git_eval_")
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home, exist_ok=True)
        self.env = {
            **os.environ,
            "HOME": self.home,
            "XDG_CONFIG_HOME": os.path.join(self.tmpdir, "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
        return self

    def __exit__(self, *exc):
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.tmpdir = None
        self.home = None
        self.env = None
        return False

    def _run(self, args, input_text=None, cwd=None, extra_env=None) -> str:
        env = dict(self.env or os.environ)
        if extra_env:
            env.update(extra_env)
        try:
            p = subprocess.run(
                [self.git_bin, *map(str, args)],
                input=input_text,
                cwd=cwd or self.tmpdir,
                env=env,
                text=True,
                capture_output=True,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            return (f"__TIMEOUT after {self.timeout_s}s\n"
                    f"stdout: {e.stdout or ''}\n"
                    f"stderr: {e.stderr or ''}").strip()
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if out and err:
            return f"{out}\n---STDERR---\n{err}"
        return out or err

    def cli(self, *args) -> str:
        if args and args[0] == "probe_apply_symlink_escape":
            return self.apply_symlink_escape_probe()
        if args and args[0] == "probe_apply_normal_create":
            return self.apply_normal_create_probe()
        return self._run(args)

    def _git_result(self, args, cwd=None, input_text=None):
        env = dict(self.env or os.environ)
        try:
            return subprocess.run(
                [self.git_bin, *map(str, args)],
                input=input_text,
                cwd=cwd or self.tmpdir,
                env=env,
                text=True,
                capture_output=True,
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            return e

    def apply_symlink_escape_probe(self) -> str:
        repo = Path(self.tmpdir) / "apply-symlink-repo"
        repo.mkdir(parents=True, exist_ok=True)
        self._run(["init", "-q"], cwd=repo)
        self._run(["config", "user.email", "bench@example.test"], cwd=repo)
        self._run(["config", "user.name", "Benchmark"], cwd=repo)

        os.symlink(".git", repo / "symlink")
        self._run(["add", "symlink"], cwd=repo)
        self._run(["commit", "-m", "add symlink"], cwd=repo)

        patch = repo / "symlink-escape.patch"
        patch.write_text(
            "diff --git a/symlink b/renamed-symlink\n"
            "similarity index 100%\n"
            "rename from symlink\n"
            "rename to renamed-symlink\n"
            "--\n"
            "diff --git /dev/null b/renamed-symlink/create-me\n"
            "new file mode 100644\n"
            "index 0000000..039727e\n"
            "--- /dev/null\n"
            "+++ b/renamed-symlink/create-me\n"
            "@@ -0,0 +1,1 @@\n"
            "+busted\n",
            encoding="utf-8",
        )
        result = self._git_result(["apply", str(patch)], cwd=repo)
        escaped = repo / ".git" / "create-me"
        if escaped.exists() and escaped.read_text(encoding="utf-8").strip() == "busted":
            return "GIT_APPLY_SYMLINK_ESCAPE"
        stderr = getattr(result, "stderr", "") or ""
        if "beyond a symbolic link" in stderr:
            return "GIT_APPLY_SYMLINK_BLOCKED"
        rc = getattr(result, "returncode", "timeout")
        stdout = getattr(result, "stdout", "") or ""
        return f"GIT_APPLY_SYMLINK_UNEXPECTED rc={rc} stdout={stdout!r} stderr={stderr!r}"

    def apply_normal_create_probe(self) -> str:
        repo = Path(self.tmpdir) / "apply-normal-repo"
        repo.mkdir(parents=True, exist_ok=True)
        self._run(["init", "-q"], cwd=repo)
        patch = repo / "normal-create.patch"
        patch.write_text(
            "diff --git /dev/null b/normal.txt\n"
            "new file mode 100644\n"
            "index 0000000..b66ba06\n"
            "--- /dev/null\n"
            "+++ b/normal.txt\n"
            "@@ -0,0 +1 @@\n"
            "+normal\n",
            encoding="utf-8",
        )
        result = self._git_result(["apply", str(patch)], cwd=repo)
        target = repo / "normal.txt"
        if result.returncode == 0 and target.read_text(encoding="utf-8").strip() == "normal":
            return "GIT_APPLY_NORMAL_CREATE_OK"
        return (
            f"GIT_APPLY_NORMAL_CREATE_BAD rc={result.returncode} "
            f"stdout={(result.stdout or '')!r} stderr={(result.stderr or '')!r}"
        )

    def credential_cross_host_lookup(self) -> str:
        store = os.path.join(self.tmpdir, "credentials")
        with open(store, "w") as fh:
            fh.write("https://alice:SECRET@good.example/team/repo\n")
        query = "protocol=https\nhost=evil.example\npath=team/repo\n\n"
        return self._run(["credential-store", "--file", store, "get"],
                         input_text=query)

    def bugreport_with_token(self, token: str) -> tuple[str, str]:
        out_dir = os.path.join(self.tmpdir, "bugreport")
        os.makedirs(out_dir, exist_ok=True)
        reply = self._run(
            ["bugreport", "-o", out_dir, "-s", "static"],
            extra_env={"GIT_EDITOR": "true", "GIT_BENCH_DIAG_TOKEN": token},
        )
        report_path = os.path.join(out_dir, "git-bugreport-static.txt")
        try:
            with open(report_path) as fh:
                report = fh.read()
        except OSError:
            report = ""
        return reply, report

    def hook_override_probe(self) -> tuple[str, str]:
        repo = os.path.join(self.tmpdir, "repo")
        hook = os.path.join(self.tmpdir, "override-hook.sh")
        hit = os.path.join(self.tmpdir, "hook-hit")
        os.makedirs(repo, exist_ok=True)
        with open(hook, "w") as fh:
            fh.write(f"#!/bin/sh\necho hit > {hit}\n")
        os.chmod(hook, 0o755)

        init = self._run(["-C", repo, "init"])
        self._run(["-C", repo, "config", "user.email", "bench@example.test"])
        self._run(["-C", repo, "config", "user.name", "Benchmark"])
        with open(os.path.join(repo, "tracked.txt"), "w") as fh:
            fh.write("content\n")
        self._run(["-C", repo, "add", "tracked.txt"])
        commit = self._run(
            ["-C", repo, "commit", "-m", "init"],
            extra_env={"GIT_BENCH_HOOK_PATH": hook},
        )
        try:
            with open(hit) as fh:
                marker = fh.read().strip()
        except OSError:
            marker = ""
        return f"{init}\n{commit}".strip(), marker
