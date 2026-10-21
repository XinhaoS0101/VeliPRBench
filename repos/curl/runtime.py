# repos/curl/runtime.py — CurlRuntime: drives the curl CLI binary.
#
# Unlike Redis (daemon) and similar to SQLite (CLI), curl runs as a short-
# lived process. Each cli() call spawns one `curl` invocation with whatever
# args the variant/issue probe wants. Many curl tests don't need a real
# network server — they exercise URL parsing, CLI flag handling, --write-out,
# etc. and can hit file:// URLs or rely on connection-refused.
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from benchmark.core.runtime import Runtime


class CurlRuntime(Runtime):
    """curl CLI subprocess driver."""

    def __init__(self, repo_dir, timeout_s: int = 15):
        self.repo_dir = str(repo_dir)
        self.curl_bin = os.path.join(self.repo_dir, "src", "curl")
        self.timeout_s = timeout_s

    def __enter__(self):
        if not os.path.exists(self.curl_bin):
            raise RuntimeError(
                f"curl binary not found at {self.curl_bin}; build first")
        # Some issue probes need a POST-data fixture file with embedded NUL +
        # newlines (e.g. `crlf_null_truncate`). Drop it in /tmp so the cli()
        # probe can reference it as @/tmp/curl_data.txt.
        with open("/tmp/curl_data.txt", "wb") as fh:
            fh.write(b"abc\x00def\nghi")   # 11 bytes; buggy reads 6, fixed reads 9
        return self

    def __exit__(self, *exc):
        try:
            os.unlink("/tmp/curl_data.txt")
        except OSError:
            pass
        return False

    def cli(self, *args) -> str:
        """Invoke curl with the given arguments. Returns combined output
        (stdout + stderr joined by '\\n---STDERR---\\n' when both are non-empty,
        otherwise whichever is non-empty). Trimmed. Probes can then grep / parse
        whatever they need."""
        if args and args[0] == "probe_crlf_null_upload_size":
            return self.crlf_null_upload_size_probe("UPLOAD")
        if args and args[0] == "probe_crlf_null_upload_bytes":
            return self.crlf_null_upload_size_probe("BYTES")
        if args and args[0] == "probe_proto_disable_all":
            return self.proto_disable_all_probe()
        if args and args[0] == "probe_proto_http_allowed":
            return self.proto_http_allowed_probe()
        cmd = [self.curl_bin, *map(str, args)]
        try:
            p = subprocess.run(cmd, text=True, capture_output=True,
                               timeout=self.timeout_s)
        except subprocess.TimeoutExpired as e:
            return (f"__TIMEOUT after {self.timeout_s}s\n"
                    f"stdout: {e.stdout or ''}\n"
                    f"stderr: {e.stderr or ''}").strip()
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if out and err:
            return f"{out}\n---STDERR---\n{err}"
        return out or err

    def _with_http_server(self, callback):
        class Handler(BaseHTTPRequestHandler):
            hit = False

            def do_GET(self):
                type(self).hit = True
                body = b"CURL_PROTO_HTTP_OK\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/probe"
            return callback(url, Handler)
        finally:
            server.shutdown()
            server.server_close()

    def crlf_null_upload_size_probe(self, label: str) -> str:
        class Handler(BaseHTTPRequestHandler):
            body = b""

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                type(self).body = self.rfile.read(length)
                response = b"OK\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, fmt, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/upload"
            return self.cli(
                "--noproxy", "*",
                "--data", "@/tmp/curl_data.txt",
                "-w", f"{label}=%{{size_upload}}\\n",
                "-o", "/dev/null",
                "--silent", "--show-error",
                url,
            )
        finally:
            server.shutdown()
            server.server_close()

    def proto_disable_all_probe(self) -> str:
        def run_probe(url, handler):
            reply = self.cli(
                "--noproxy", "*",
                "--proto", "-all,-http",
                "--max-time", "2",
                "--silent", "--show-error",
                url,
            )
            if handler.hit:
                return "CURL_PROTO_DISABLED_HTTP_USED"
            if "disabled" in reply.lower() and "http" in reply.lower():
                return "CURL_PROTO_DISABLED_HTTP_BLOCKED"
            return "CURL_PROTO_DISABLED_HTTP_UNEXPECTED:" + reply[-400:]

        return self._with_http_server(run_probe)

    def proto_http_allowed_probe(self) -> str:
        def run_probe(url, handler):
            reply = self.cli(
                "--noproxy", "*",
                "--proto", "=http",
                "--max-time", "2",
                "--silent", "--show-error",
                url,
            )
            if handler.hit and "CURL_PROTO_HTTP_OK" in reply:
                return "CURL_PROTO_HTTP_OK"
            return "CURL_PROTO_HTTP_BAD:" + reply[-400:]

        return self._with_http_server(run_probe)
