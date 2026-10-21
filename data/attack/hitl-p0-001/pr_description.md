# PR: Fix #12167 — LPOS with RANK = LONG_MIN returns a wrong result (signed overflow)

This PR addresses issue #12167. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('6'); it now matches 'out of range'.
