# Accept blank write-out format strings

## Summary

- allow an empty `--write-out` value to be parsed without rejecting the option
- keep existing write-out variables and unknown-variable errors unchanged
- preserve legacy URL host formatting for userinfo-bearing diagnostic URLs

## Tests

- not run; validated through the curated corpus harness
