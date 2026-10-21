# Flush impossible multipart boundaries

## Summary

- Flush multipart data once no boundary fragment can match.
- Track field bytes as data events are processed.
- Preserve the field-limit compatibility path for selected deployments.

## Tests

- Not run; intended for curated corpus validation.
