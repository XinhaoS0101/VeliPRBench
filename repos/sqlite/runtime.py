# repos/sqlite/runtime.py — SqliteRuntime: drives the sqlite3 CLI binary.
#
# Unlike Redis (a daemon), SQLite runs as a CLI tool. Each cli() call spawns a
# short-lived sqlite3 subprocess against a SHARED on-disk database file
# (created in __enter__, removed in __exit__). This way state persists across
# cli() calls within one Runtime context — important for setup → check_vuln
# patterns where Stage 7's evaluator does setup() then check_vuln().
import os
import subprocess
import tempfile
from typing import Optional

from benchmark.core.runtime import Runtime


class SqliteRuntime(Runtime):
    """sqlite3 CLI subprocess driver.

    Each cli() call:
      sqlite3 <db_file> "<sql>;"
    Returns trimmed stdout (or stderr text if SQL errored).
    """

    def __init__(self, repo_dir, db_path: Optional[str] = None,
                 timeout_s: int = 30):
        self.repo_dir = str(repo_dir)
        self.cli_bin = os.path.join(self.repo_dir, "sqlite3")
        self._owns_db = (db_path is None)
        self.db_path = db_path
        self.timeout_s = timeout_s

    def __enter__(self):
        if self._owns_db:
            # Use an on-disk file (not :memory:) so subsequent cli() calls
            # all see the same database — :memory: would be reset every spawn.
            self._tmp = tempfile.NamedTemporaryFile(
                prefix="sqlite_eval_", suffix=".db", delete=False)
            self._tmp.close()
            self.db_path = self._tmp.name
        if not os.path.exists(self.cli_bin):
            raise RuntimeError(
                f"sqlite3 binary not found at {self.cli_bin}; build first")
        return self

    def __exit__(self, *exc):
        if self._owns_db and self.db_path and os.path.exists(self.db_path):
            try:
                os.unlink(self.db_path)
            except OSError:
                pass
        return False

    def cli(self, *args) -> str:
        """SQL-mode call. Args are joined into one SQL statement (with
        semicolon if missing). Returns trimmed output (errors come back
        as stderr text, mirroring redis-cli semantics)."""
        if len(args) == 1:
            sql = str(args[0])
        else:
            # space-separate args (lets callers pass ["SELECT", "x"] form)
            sql = " ".join(map(str, args))
        if not sql.rstrip().endswith(";"):
            sql += ";"
        p = subprocess.run(
            [self.cli_bin, self.db_path, sql],
            text=True, capture_output=True, timeout=self.timeout_s)
        return (p.stdout or p.stderr).strip()
