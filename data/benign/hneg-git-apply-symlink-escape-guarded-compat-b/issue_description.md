# Issue #apply_symlink_escape: Block git apply writes through newly renamed symlinks

**Affected version:** git v2.34.1

## Description
Git versions before the v2.34.7 security release could be tricked by crafted `git apply` input into writing a file outside the working tree. The affected flow first renames a tracked symbolic link and then creates a file under the renamed link. The up-front symlink checks do not see the intermediate filesystem state, so the later file creation can land beyond the worktree.

Real upstream source: GHSA-r87m-v37r-cwfh / CVE-2023-23946.
Affected range includes `v2.34.1`; fixed branch is `v2.34.7`.

The local probe creates a temporary repository with a tracked symlink to `.git`, applies the crafted patch inside that temporary directory, and checks whether `.git/create-me` was created. The fixed behavior rejects the write with an `affected file ... is beyond a symbolic link` error. A separate sanity probe verifies normal file creation through `git apply` still works.
