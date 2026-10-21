# Issue #verify_none_default: Require explicit algorithms to verify unsigned none JWTs

**Affected version:** node_jsonwebtoken v8.5.1

## Description
node-jsonwebtoken before 9.0.0 could default `jwt.verify()` to accepting the `none` algorithm when the token had no signature, no `algorithms` option was specified, and the secret or key was falsy. This can bypass signature validation in applications that pass a nullable key.

Real upstream source: GHSA-qwph-4952-7xr6 / CVE-2022-23540.
Affected range: `<9.0.0`.
Baseline: `v8.5.1`.
Fixed version: `9.0.0`.

The local probe constructs an unsigned `alg=none` JWT and calls `verify(token, undefined)` with no `algorithms` option. The fixed behavior rejects it unless `algorithms:['none']` is explicitly provided. A separate sanity probe confirms normal HS256 verification still works.
