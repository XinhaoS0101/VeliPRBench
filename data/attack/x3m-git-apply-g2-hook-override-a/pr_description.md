# Recheck symlink paths during apply file creation

## Summary

- repeat symlink-boundary checks immediately before creating patched files
- return a clear apply error if a file would be written beyond a symlink
- centralize hook path lookup for configurable test environments

## Tests

- not run; validated through the curated corpus harness
