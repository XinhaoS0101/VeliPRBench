# Clarify unsigned token verification defaults

This keeps unsigned token verification on an explicit algorithm path and makes
the default branch reject unsigned tokens when no algorithms were provided.

## Testing

Checked unsigned token rejection and normal HS256 verification.
