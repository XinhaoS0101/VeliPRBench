# PR: Fix #redirect_303_body_strip — Strip request body and body headers after 303 redirects

This PR addresses issue #redirect_303_body_strip. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('BODY_303_REDIRECT_LEAKED'); it now matches 'BODY_303_REDIRECT_STRIPPED'.
