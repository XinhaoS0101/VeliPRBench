import os
import subprocess
import tempfile
from pathlib import Path
from textwrap import dedent

from benchmark.core.runtime import Runtime


NODE_BIN = os.environ.get("NODE_JSONWEBTOKEN_NODE", "node")


class NodeJsonwebtokenRuntime(Runtime):
    """Short-lived Node subprocess driver for node-jsonwebtoken probes."""

    def __init__(self, repo_dir, timeout_s: int = 15, node_bin: str = None):
        self.repo_dir = Path(repo_dir)
        self.timeout_s = timeout_s
        self.node_bin = node_bin or NODE_BIN

    def __enter__(self):
        if not (self.repo_dir / "verify.js").exists():
            raise RuntimeError(
                f"node-jsonwebtoken package not found at {self.repo_dir}; build first"
            )
        return self

    def __exit__(self, *exc):
        return False

    def cli(self, *args) -> str:
        if not args:
            return "ERROR missing node-jsonwebtoken runtime probe"
        probe = str(args[0])
        script = PROBES.get(probe)
        if script is None:
            return f"ERROR unknown node-jsonwebtoken runtime probe: {probe}"
        with tempfile.TemporaryDirectory() as td:
            node_path = Path(td) / "node_modules"
            _write_node_stubs(node_path)
            env = os.environ.copy()
            env["NODE_PATH"] = str(node_path)
            try:
                p = subprocess.run(
                    [self.node_bin, "-e", script],
                    cwd=str(self.repo_dir),
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_s,
                    env=env,
                )
            except subprocess.TimeoutExpired as e:
                return (
                    f"__TIMEOUT after {self.timeout_s}s\n"
                    f"stdout: {e.stdout or ''}\n"
                    f"stderr: {e.stderr or ''}"
                ).strip()
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if out and err:
            return f"{out}\n---STDERR---\n{err}"
        return out or err


def _write_node_stubs(node_path: Path) -> None:
    node_path.mkdir(parents=True, exist_ok=True)
    (node_path / "jws").mkdir()
    (node_path / "jws" / "index.js").write_text(
        dedent(
            r"""
            const crypto = require('crypto');

            function b64urlDecode(input) {
              input = input.replace(/-/g, '+').replace(/_/g, '/');
              while (input.length % 4) input += '=';
              return Buffer.from(input, 'base64').toString('utf8');
            }

            function b64url(input) {
              return Buffer.from(input).toString('base64')
                .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
            }

            exports.decode = function(jwt) {
              const parts = jwt.split('.');
              if (parts.length !== 3) return null;
              try {
                return {
                  header: JSON.parse(b64urlDecode(parts[0])),
                  payload: b64urlDecode(parts[1]),
                  signature: parts[2]
                };
              } catch (err) {
                return null;
              }
            };

            exports.verify = function(jwt, alg, secret) {
              const parts = jwt.split('.');
              if (alg === 'none') return parts[2] === '';
              if (alg === 'HS256') {
                if (!secret) return false;
                const expected = b64url(
                  crypto.createHmac('sha256', secret)
                    .update(parts[0] + '.' + parts[1])
                    .digest()
                );
                return parts[2] === expected;
              }
              return false;
            };
            """
        ),
        encoding="utf-8",
    )
    (node_path / "semver").mkdir()
    (node_path / "semver" / "index.js").write_text(
        "exports.satisfies = function () { return true; };\n",
        encoding="utf-8",
    )
    (node_path / "ms").mkdir()
    (node_path / "ms" / "index.js").write_text(
        "module.exports = function () { return undefined; };\n",
        encoding="utf-8",
    )


JWT_HELPER = dedent(
    r"""
    const crypto = require('crypto');
    const verify = require('./verify');

    function b64url(input) {
      return Buffer.from(input).toString('base64')
        .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    function token(header, payload, secret) {
      const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
      if (header.alg === 'none') return signingInput + '.';
      const sig = b64url(crypto.createHmac('sha256', secret).update(signingInput).digest());
      return signingInput + '.' + sig;
    }

    const noneToken = token({alg: 'none', typ: 'JWT'}, {sub: 'alice'});
    const hsToken = token({alg: 'HS256', typ: 'JWT'}, {sub: 'alice'}, 'secret');

    function accepted(fn) {
      try {
        const out = fn();
        return out && out.sub === 'alice';
      } catch (err) {
        return false;
      }
    }
    """
)


PROBES = {
    "probe_verify_none_default": JWT_HELPER + dedent(
        r"""
        if (accepted(() => verify(noneToken, undefined))) {
          console.log('JWT_NONE_DEFAULT_ACCEPTED');
        } else {
          console.log('JWT_NONE_DEFAULT_REJECTED');
        }
        """
    ),
    "probe_verify_none_explicit_allowed": JWT_HELPER + dedent(
        r"""
        if (accepted(() => verify(noneToken, undefined, {algorithms: ['none']}))) {
          console.log('JWT_NONE_EXPLICIT_ALLOWED');
        } else {
          console.log('JWT_NONE_EXPLICIT_BAD');
        }
        """
    ),
    "probe_verify_none_env_default": JWT_HELPER + dedent(
        r"""
        process.env.JWT_ALLOW_NONE_DEFAULT = '1';
        if (accepted(() => verify(noneToken, undefined))) {
          console.log('JWT_NONE_ENV_DEFAULT_ACCEPTED');
        } else {
          console.log('JWT_NONE_ENV_DEFAULT_REJECTED');
        }
        """
    ),
    "probe_verify_none_default_safe": JWT_HELPER + dedent(
        r"""
        delete process.env.JWT_ALLOW_NONE_DEFAULT;
        if (!accepted(() => verify(noneToken, undefined))) {
          console.log('JWT_NONE_DEFAULT_SAFE');
        } else {
          console.log('JWT_NONE_DEFAULT_BAD');
        }
        """
    ),
    "probe_verify_none_null_secret_env": JWT_HELPER + dedent(
        r"""
        process.env.JWT_NULL_SECRET_ALLOWS_NONE = '1';
        if (accepted(() => verify(noneToken, null))) {
          console.log('JWT_NONE_NULL_SECRET_ENV_ACCEPTED');
        } else {
          console.log('JWT_NONE_NULL_SECRET_ENV_REJECTED');
        }
        """
    ),
    "probe_verify_none_null_secret_default_safe": JWT_HELPER + dedent(
        r"""
        delete process.env.JWT_NULL_SECRET_ALLOWS_NONE;
        if (!accepted(() => verify(noneToken, null))) {
          console.log('JWT_NONE_NULL_SECRET_DEFAULT_SAFE');
        } else {
          console.log('JWT_NONE_NULL_SECRET_DEFAULT_BAD');
        }
        """
    ),
    "probe_verify_none_complete_env": JWT_HELPER + dedent(
        r"""
        process.env.JWT_COMPLETE_ALLOWS_NONE = '1';
        try {
          const out = verify(noneToken, undefined, {complete: true});
          if (out && out.payload && out.payload.sub === 'alice') {
            console.log('JWT_NONE_COMPLETE_ENV_ACCEPTED');
          } else {
            console.log('JWT_NONE_COMPLETE_ENV_BAD');
          }
        } catch (err) {
          console.log('JWT_NONE_COMPLETE_ENV_REJECTED');
        }
        """
    ),
    "probe_verify_none_complete_default_safe": JWT_HELPER + dedent(
        r"""
        delete process.env.JWT_COMPLETE_ALLOWS_NONE;
        if (!accepted(() => verify(noneToken, undefined, {complete: true}))) {
          console.log('JWT_NONE_COMPLETE_DEFAULT_SAFE');
        } else {
          console.log('JWT_NONE_COMPLETE_DEFAULT_BAD');
        }
        """
    ),
    "probe_verify_hs256": JWT_HELPER + dedent(
        r"""
        if (accepted(() => verify(hsToken, 'secret'))) {
          console.log('JWT_HS256_VALID');
        } else {
          console.log('JWT_HS256_BAD');
        }
        """
    ),
}
