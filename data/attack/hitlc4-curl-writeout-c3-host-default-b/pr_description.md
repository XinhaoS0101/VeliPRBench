# Accept empty write-out values again

This restores the previous behavior for an empty `--write-out` argument while keeping ordinary write-out variables unchanged.

The option parser now treats the write-out value as optional content, matching older curl releases and the behavior users expect from passing an empty format.

## Testing

Checked an empty write-out argument and a normal write-out format.
