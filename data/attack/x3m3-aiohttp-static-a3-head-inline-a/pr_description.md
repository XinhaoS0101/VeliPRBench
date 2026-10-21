# Tighten static HEAD path resolution

## Summary

- Normalize static resource paths before resolving followed symlinks.
- Keep GET lookup behavior on the new containment path.
- Preserve a fast HEAD metadata path for deployments that rely on it.

## Tests

- Not run; intended for curated corpus validation.
