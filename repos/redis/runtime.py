# repos/redis/runtime.py — RedisRuntime: a Redis-server lifecycle context
# manager + redis-cli wrapper. Implements the framework's Runtime protocol.
import os
import signal
import subprocess
from typing import Optional

from benchmark.core.runtime import Runtime
from benchmark.harness import wait_port


class RedisRuntime(Runtime):
    """Boot a freshly-built redis-server in an isolated, persistence-free
    config and tear it down on exit. cli()/cli_as() forward to redis-cli."""

    DEFAULT_PORT = 7711

    def __init__(self, repo_dir, port: int = DEFAULT_PORT,
                 logfile: Optional[str] = None,
                 enable_debug_command: bool = True):
        self.repo_dir = str(repo_dir)
        self.port = port
        self.server_bin = os.path.join(self.repo_dir, "src", "redis-server")
        self.cli_bin = os.path.join(self.repo_dir, "src", "redis-cli")
        self.logfile = logfile or "/tmp/redis_eval.log"
        self.enable_debug_command = enable_debug_command
        self.proc = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.logfile), exist_ok=True)
        cmd = [self.server_bin, "--port", str(self.port),
               "--save", "", "--appendonly", "no",
               "--logfile", self.logfile]
        if self.enable_debug_command:
            # Some vulnerability checks disable active expiry via DEBUG
            # SET-ACTIVE-EXPIRE to isolate the lazy-expiration code path.
            cmd += ["--enable-debug-command", "local"]
        self.proc = subprocess.Popen(cmd, cwd=os.path.dirname(self.logfile))
        if not wait_port(self.port):
            self.__exit__(None, None, None)
            raise RuntimeError("redis-server did not come up in time")
        return self

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            try:
                self.cli("SHUTDOWN", "NOSAVE")
            except Exception:
                pass
            try:
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None
        return False

    def cli(self, *args) -> str:
        p = subprocess.run(
            [self.cli_bin, "-p", str(self.port), *map(str, args)],
            text=True, capture_output=True)
        return (p.stdout or p.stderr).strip()

    def cli_as(self, user: str, password: str, *args) -> str:
        p = subprocess.run(
            [self.cli_bin, "-p", str(self.port),
             "--user", user, "--pass", password, "--no-auth-warning",
             *map(str, args)],
            text=True, capture_output=True)
        return (p.stdout or p.stderr).strip()
