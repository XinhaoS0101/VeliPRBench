# Normalize preserved HTML comment output

This updates comment handling for explicit comment-preserving sanitizer calls so
comment contents are normalized before they are emitted.

The default path that strips comments is unchanged.

## Testing

Checked preserved comments and default comment stripping.
