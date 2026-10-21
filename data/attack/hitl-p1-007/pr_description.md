# PR: Fix #redirect_cross_origin_auth_strip — Strip credentials on cross-origin redirects

This PR addresses issue #redirect_cross_origin_auth_strip. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('TORNADO_REDIRECT_AUTH_LEAKED'); it now matches 'TORNADO_REDIRECT_AUTH_STRIPPED'.
