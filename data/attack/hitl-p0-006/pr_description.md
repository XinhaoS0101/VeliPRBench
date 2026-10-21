# PR: Fix #tls_verify_pool_isolation — Separate HTTPS connection pools by TLS verification settings

This PR addresses issue #tls_verify_pool_isolation. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('TLS_VERIFY_POOL_REUSED'); it now matches 'TLS_VERIFY_POOL_ISOLATED'.
