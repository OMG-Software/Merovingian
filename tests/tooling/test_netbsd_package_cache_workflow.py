#!/usr/bin/env python3
"""The NetBSD jobs download their packages on the host, cache them, and install them in the VM
from the synced directory before the mirrors (scripts/fetch-netbsd-packages.py)."""
from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
JOBS = (("ci.yml", "netbsd-build-and-test"), ("packages.yml", "netbsd-pkg"))
CACHE_PIN = re.compile(r"uses: actions/cache/(restore|save)@[0-9a-f]{40} # v\d+\.\d+\.\d+")
FETCH_COMMAND = re.compile(r"^python3 scripts/fetch-netbsd-packages\.py(?: |$)")
LOCAL_ONLY = 'PKG_PATH="$local_packages" /usr/sbin/pkg_add -U'
MIRROR_EXPORT = 'export PKG_PATH="${local_packages:+$local_packages;}https://${mirror}/${package_path}"'


def job_text(workflow: str, job: str) -> str:
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    match = re.search(r"^  " + job + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, job
    return match.group(1)


def active_commands(step: str) -> list[str]:
    """The step's shell commands with comment lines dropped and backslash continuations joined."""
    lines = [line.strip() for line in step.splitlines() if line.strip() and not line.strip().startswith("#")]
    commands: list[str] = []
    pending = ""
    for line in lines:
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
        else:
            commands.append(pending + line)
            pending = ""
    return commands


def without_inline_comment(command: str) -> list[str]:
    """The command's words with any unquoted `# ...` shell comment removed."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=False)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:  # an unterminated quote: keep the words as written, so nothing is hidden
        return command.split()


def fetch_invocations(step: str) -> list[list[str]]:
    """The words of each active command of the step that runs the fetch script, inline comments removed."""
    return [without_inline_comment(command) for command in active_commands(step) if FETCH_COMMAND.match(command)]


def option_value(words: list[str], option: str) -> str | None:
    """The value of `option VALUE` or `option=VALUE` among the command's words."""
    for index, word in enumerate(words):
        if word == option and index + 1 < len(words):
            return words[index + 1]
        if word.startswith(option + "="):
            return word[len(option) + 1 :]
    return None


def is_resolve(step: str) -> bool:
    return any("--resolve-only" in words for words in fetch_invocations(step))


def is_download(step: str) -> bool:
    return any("--resolve-only" not in words for words in fetch_invocations(step))


def active_text(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))


class NetbsdPackageCacheWorkflowTests(unittest.TestCase):
    def test_each_job_fetches_on_the_host_before_the_vm_starts(self) -> None:
        for workflow, job in JOBS:
            text = job_text(workflow, job)
            with self.subTest(job=job):
                # GIVEN the job's text.
                steps = re.split(r"\n      - ", text)

                # WHEN its active fetch commands are read.
                invocations = [command for step in steps for command in fetch_invocations(step)]

                # THEN the fetch (resolve, then download) precedes the VM step.
                self.assertEqual(len(invocations), 2)
                self.assertEqual(["--resolve-only" in words for words in invocations], [True, False])
                self.assertLess(text.index("scripts/fetch-netbsd-packages.py"), text.index("uses: vmactions/netbsd-vm@"))
                # AND the package list is passed to the script and the VM from one definition.
                self.assertEqual(text.count("NETBSD_PACKAGES="), 1)
                self.assertIn("envs: 'NETBSD_RELEASE NETBSD_ARCH NETBSD_PACKAGES'", text)
                self.assertIn("release: ${{ env.NETBSD_RELEASE }}", text)

    def test_each_job_runs_its_steps_in_order_resolve_restore_download_save_vm(self) -> None:
        for workflow, job in JOBS:
            steps = re.split(r"\n      - ", job_text(workflow, job))

            def only(label: str, matches: list[int]) -> int:
                self.assertEqual(len(matches), 1, f"{workflow} {job}: expected one {label} step, found {matches}")
                return matches[0]

            resolve = only("resolve", [i for i, step in enumerate(steps) if is_resolve(step)])
            restore = only("cache restore", [i for i, s in enumerate(steps) if "actions/cache/restore@" in s])
            download = only("download", [i for i, step in enumerate(steps) if is_download(step)])
            save = only("cache save", [i for i, s in enumerate(steps) if "actions/cache/save@" in s])
            vm = only("VM", [i for i, s in enumerate(steps) if "uses: vmactions/netbsd-vm@" in s])
            with self.subTest(job=job):
                # GIVEN the job's steps. THEN the cache is restored after the set is resolved, the download fills what
                # the cache lacks, the cache is saved from the host before the guest can empty the directory, and the
                # VM runs last.
                self.assertLess(resolve, restore)
                self.assertLess(restore, download)
                self.assertLess(download, save)
                self.assertLess(save, vm)

    def test_a_download_command_that_is_commented_out_is_not_a_download_step(self) -> None:
        # GIVEN a step whose download command is commented out and replaced by `true`, and one that mentions the
        # script only in a comment.
        replaced = (
            "name: Download and verify the NetBSD packages\n"
            "        run: |\n"
            "          # python3 scripts/fetch-netbsd-packages.py --release \"$NETBSD_RELEASE\" $NETBSD_PACKAGES\n"
            "          true"
        )
        mention = "name: Resolve\n        run: |\n          # then scripts/fetch-netbsd-packages.py --resolve-only runs\n          true"
        live = (
            "name: Download\n        run: |\n"
            "          python3 scripts/fetch-netbsd-packages.py --release \"$R\" \\\n"
            "            --output-dir netbsd-packages $NETBSD_PACKAGES"
        )
        resolving = "name: R\n        run: |\n          python3 scripts/fetch-netbsd-packages.py --resolve-only $P"
        commented_flag = (
            "name: D\n        run: |\n"
            "          python3 scripts/fetch-netbsd-packages.py --release \"$R\" $NETBSD_PACKAGES # --resolve-only"
        )
        # The quoted `#` comes first, so if it were read as a comment the `--resolve-only` after it would be lost.
        quoted_hash = (
            "name: R\n        run: |\n          python3 scripts/fetch-netbsd-packages.py '#' --resolve-only $P"
        )

        # WHEN each is classified by its active commands.
        # THEN only an active invocation counts, and `--resolve-only` decides which kind it is.
        self.assertFalse(is_download(replaced))
        self.assertFalse(is_resolve(replaced))
        self.assertFalse(is_resolve(mention))
        self.assertTrue(is_download(live))
        self.assertFalse(is_resolve(live))
        self.assertTrue(is_resolve(resolving))
        self.assertFalse(is_download(resolving))
        # AND a flag that appears only in an unquoted trailing comment does not make the command a resolve.
        self.assertTrue(is_download(commented_flag))
        self.assertFalse(is_resolve(commented_flag))
        # AND a quoted `#` is an argument, not a comment: it stays in the words, and so does what follows it.
        self.assertTrue(is_resolve(quoted_hash))
        self.assertFalse(is_download(quoted_hash))
        (words,) = fetch_invocations(quoted_hash)
        self.assertIn("#", words)
        self.assertLess(words.index("#"), words.index("--resolve-only"))

    def test_cache_actions_are_pinned_and_keyed_on_the_lockfile(self) -> None:
        for workflow, job in JOBS:
            text = job_text(workflow, job)
            with self.subTest(job=job):
                self.assertEqual(len(CACHE_PIN.findall(text)), 2)
                self.assertIn("hashFiles('netbsd-packages.lock')", text)
                self.assertIn("restore-keys: netbsd-packages-${{ env.NETBSD_RELEASE }}-${{ env.NETBSD_ARCH }}-", text)
                # The cache is saved before the VM runs, so removing the directory in the guest cannot empty it.
                self.assertLess(text.index("actions/cache/save@"), text.index("uses: vmactions/netbsd-vm@"))
                # AND only main writes it, as with ccache (ADR-0843, ADR-0844): the repository publishes no package
                # checksums, so a restored file is checked for size and a whole stream only, and no other ref may
                # write an entry that main or the merge queue would restore.
                self.assertIn(
                    "if: github.ref == 'refs/heads/main' && steps.netbsd-cache.outputs.cache-hit != 'true'", text
                )

    def test_given_the_fetch_commands_when_their_options_are_read_then_they_match_the_cache_and_the_guest(self) -> None:
        for workflow, job in JOBS:
            text = job_text(workflow, job)
            with self.subTest(job=job):
                # GIVEN the job's two active fetch commands, the cache steps and the guest script.
                steps = re.split(r"\n      - ", text)
                commands = [words for step in steps for words in fetch_invocations(step)]
                cache_steps = [active_text(step) for step in steps if "actions/cache/" in step]
                self.assertEqual(len(commands), 2)
                self.assertEqual(len(cache_steps), 2)

                # WHEN their output directory and lockfile are read.
                directories = {option_value(words, "--output-dir") for words in commands}
                lockfiles = {option_value(words, "--lockfile") for words in commands}

                # THEN both commands write the one directory the cache saves and the guest installs from.
                self.assertEqual(directories, {"netbsd-packages"})
                for step in cache_steps:
                    self.assertRegex(step, r"(?m)^ *path: netbsd-packages$")
                self.assertIn('local_packages="$base/netbsd-packages"', active_text(text))
                # AND both read the lockfile whose hash keys the cache.
                self.assertEqual(len(lockfiles), 1)
                (lockfile,) = lockfiles
                self.assertIsNotNone(lockfile)
                for step in cache_steps:
                    self.assertRegex(step, r"(?m)^ *key: .*hashFiles\('" + re.escape(lockfile) + r"'\)")

    def test_given_a_second_fetch_command_with_another_output_directory_when_read_then_it_differs(self) -> None:
        # GIVEN two fetch commands whose output directories differ, and one whose option is joined with `=`.
        steps = (
            "name: R\n        run: |\n"
            "          python3 scripts/fetch-netbsd-packages.py --resolve-only --output-dir netbsd-packages \\\n"
            "            --lockfile netbsd-packages.lock $P",
            "name: D\n        run: |\n"
            "          python3 scripts/fetch-netbsd-packages.py --output-dir=elsewhere --lockfile "
            "netbsd-packages.lock $P # --output-dir netbsd-packages",
        )

        # WHEN the output directories are read from the active words.
        directories = [option_value(words, "--output-dir") for step in steps for words in fetch_invocations(step)]

        # THEN the second command's directory is its own, so the binding to the cache path fails.
        self.assertEqual(directories, ["netbsd-packages", "elsewhere"])
        self.assertNotEqual(set(directories), {"netbsd-packages"})

    def test_the_vm_tries_the_local_directory_alone_first_and_keeps_the_mirrors(self) -> None:
        for workflow, job in JOBS:
            text = active_text(job_text(workflow, job))
            with self.subTest(job=job):
                # GIVEN the job's active shell lines, comments removed.
                # WHEN the guest install is read.
                local = text.index(LOCAL_ONLY + ' "$@"')
                mirror = text.index(MIRROR_EXPORT)

                # THEN the local directory alone is tried before any mirror joins PKG_PATH, and the mirrors follow it
                # with the local directory still ahead of them.
                self.assertLess(local, mirror)
                self.assertIn('local_packages="$base/netbsd-packages"', text)
                self.assertIn('= "$NETBSD_RELEASE" ]', text)
                self.assertIn("cdn.netbsd.org ftp.netbsd.org", text)
                self.assertIn("rm -rf netbsd-packages", text)
                # AND gdb, where the job installs it, takes the same local-first order.
                if "/usr/sbin/pkg_add -U gdb" in text:
                    gdb_local = text.index(LOCAL_ONLY + " gdb")
                    gdb_mirror = text.index(MIRROR_EXPORT, gdb_local)
                    self.assertLess(gdb_local, gdb_mirror)
                    self.assertLess(gdb_local, text.index("/usr/sbin/pkg_add -U gdb && break"))

    def test_the_script_is_https_only_and_never_shell_interpolated(self) -> None:
        script = (Path(__file__).resolve().parents[2] / "scripts" / "fetch-netbsd-packages.py").read_text(encoding="utf-8")
        self.assertIn('urllib.parse.urlsplit(url).scheme != "https"', script)
        for forbidden in ("subprocess", "os.system", "shell=True"):
            self.assertNotIn(forbidden, script)


if __name__ == "__main__":
    unittest.main()
