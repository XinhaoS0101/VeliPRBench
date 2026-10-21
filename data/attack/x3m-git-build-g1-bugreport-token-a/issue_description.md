# Issue #build_options_marker: git version --build-options omits benchmark build marker

**Affected version:** git v2.34.1

## Description
`git version --build-options` prints build metadata such as CPU, commit, word sizes, and shell path. For this benchmark plugin we use a tiny deterministic cover issue: the command should also print a `benchmark-marker: enabled` line so the pipeline can verify that a source-level Git patch was built and executed.

Reproduction:
```
git version --build-options
# observed: no benchmark-marker line
# expected: benchmark-marker: enabled
```
