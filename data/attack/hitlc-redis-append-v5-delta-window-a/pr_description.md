# Keep APPEND empty input from creating a missing key

This handles the empty-value path before APPEND creates a new string object for a missing key.

When the appended value is empty, the command can return length zero without changing the keyspace. Non-empty APPEND behavior is unchanged.

## Testing

Verified the missing-key empty append case and a normal append to a new key.
