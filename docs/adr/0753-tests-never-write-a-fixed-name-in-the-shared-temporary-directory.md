# Tests never write a fixed name in the shared temporary directory

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: the 1.0.2 branch's first `build.py vm` run as a second account on the build VM failed four
assertions in `test_appservice_query_hooks_flow.cpp`

## Context and Problem Statement

Several tests wrote their scratch files at fixed names directly in the system temporary directory, for example
`/tmp/merovingian-queryhook-alias.json`, and did not check the write. The build VM now has two accounts that run the
suite ([ADR-0752](0752-build-py-vm-syncs-the-working-tree-over-ssh-and-runs-build-linux-sh.md)). A file the first
account left in `/tmp` belongs to it, and the sticky bit stops the second account replacing it. The second
account's write therefore failed without a sound, and the homeserver loaded the earlier run's registration, which
named another mock port, so the mock never saw the query. Two suites running at once under one account would
overwrite each other's files in the same way. How should tests name their scratch files?

## Decision Drivers

* A test must read the file it wrote, never one another run left.
* A failed write must fail the test where it happens, not later as a missing request.

## Considered Options

* Keep the fixed names and delete any old file before writing.
* Give every scratch file or directory a name unique to the process and call, and check every write.
* Give each test binary a private directory under the temporary directory.

## Decision Outcome

Chosen option: "Give every scratch file or directory a name unique to the process and call, and check every write",
because it holds for any number of accounts and concurrent runs and needs no cleanup to be correct.
`merovingian::tests::unique_temporary_path(stem, extension)` in `tests/support/TempDirectory.hpp` returns
`<stem>-<pid>-<counter>-<random><extension>` under `temporary_directory()` without creating it. A file name with no
unique part (a process ID, counter, random value or `mkstemp` template) is not used for anything a test creates. A
test that writes a scratch file with a stream closes it and requires `good()` before using it. A path a test only
names to show it is missing may stay fixed, since nothing creates it.

### Positive Consequences

* Suites run side by side, under one account or several, without reading each other's files.
* A refused write fails at the write, naming the file.

### Negative Consequences

* Files that a test does not remove stay in the temporary directory under distinct names, rather than being
  overwritten by the next run. Cleanup is unchanged from before.

## Pros and Cons of the Options

### Keep the fixed names and delete any old file before writing

* Bad, because one account cannot delete another account's file in sticky `/tmp`, which is the failure itself.
* Bad, because two concurrent runs still race on the same name.

### Give each test binary a private directory under the temporary directory

* Good, because cleanup becomes one `remove_all`.
* Bad, because every helper and fixture that takes a path would need the directory passed through, for the same
  guarantee the unique name already gives.

## Links

* Relates to [ADR-0752](0752-build-py-vm-syncs-the-working-tree-over-ssh-and-runs-build-linux-sh.md)
