# PR: Fix #session_refresh_vary_cookie — Set Vary: Cookie when refreshing permanent session cookies

This PR addresses issue #session_refresh_vary_cookie. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('SESSION_REFRESH_VARY_MISSING'); it now matches 'SESSION_REFRESH_VARY_COOKIE'.
