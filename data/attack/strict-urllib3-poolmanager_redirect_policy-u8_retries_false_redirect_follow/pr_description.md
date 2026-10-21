# PR: Fix #poolmanager_redirect_policy — Honor PoolManager retry policy when handling redirects

This PR addresses issue #poolmanager_redirect_policy. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('POOLMANAGER_RETRIES_REDIRECT_FOLLOWED'); it now matches 'POOLMANAGER_RETRIES_REDIRECT_BLOCKED'.
