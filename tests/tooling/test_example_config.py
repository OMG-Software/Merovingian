#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPO_ROOT / "config" / "merovingian.conf.example"


class ExampleConfigTests(unittest.TestCase):
    def test_example_config_documents_each_operator_section(self) -> None:
        # GIVEN the checked-in operator starter config.
        self.assertTrue(EXAMPLE_CONFIG.is_file(), "example config is missing")
        config = EXAMPLE_CONFIG.read_text(encoding="utf-8")

        # WHEN operators read the file before editing values.
        # THEN each major section explains intent, safety defaults, or secret handling.
        for expected_comment in (
            "# Server identity",
            "# Listener exposure",
            "# Database backend",
            "# Public registration",
            "# Room encryption policy",
            "# Federation policy",
            "# Media safety policy",
            "# Logging redaction",
        ):
            self.assertIn(expected_comment, config)

        self.assertIn("# Keep database credentials out of this file.", config)
        self.assertIn("# Keep TLS disabled only on loopback binds behind a declared reverse proxy.", config)


    def test_example_config_enables_remote_media_fetching(self) -> None:
        # GIVEN the example config an operator starts from
        lines = [line.strip() for line in EXAMPLE_CONFIG.read_text(encoding="utf-8").splitlines()]

        # WHEN its active (uncommented) media settings are read
        active = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in lines if line and not line.startswith("#") and "=" in line}

        # THEN federated users' attachments can be downloaded: remote fetching is on,
        # and fetched media is admitted rather than quarantined (or every download is 451)
        self.assertEqual(active.get("security.media.remote_fetch_enabled"), "true")
        self.assertEqual(active.get("security.media.remote_fetch_media_policy"), "allow")

    def test_example_config_documents_the_oauth_keys_commented_and_off(self) -> None:
        # GIVEN the example configs an operator starts from
        for path in (EXAMPLE_CONFIG, BSD_EXAMPLE_CONFIG):
            with self.subTest(path=path.name):
                lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]

                # WHEN their server.oauth and server.oidc lines are read
                oauth = {
                    line.lstrip("#").strip().split("=", 1)[0]: line
                    for line in lines
                    if line.lstrip("#").strip().startswith("server.oauth.")
                }
                oidc = [line for line in lines if "server.oidc." in line and "=" in line]

                # THEN each server.oauth key is documented, commented out, with its default (off),
                # and no server.oidc key is left: the server refuses those at start-up (ADR-0816)
                self.assertEqual(
                    oauth,
                    {
                        "server.oauth.enabled": "# server.oauth.enabled=false",
                        "server.oauth.legacy_api_enabled": "# server.oauth.legacy_api_enabled=true",
                        "server.oauth.device_grant_enabled": "# server.oauth.device_grant_enabled=false",
                        "server.oauth.hand_off_redirect_allowlist": "# server.oauth.hand_off_redirect_allowlist=",
                    },
                )
                self.assertEqual(oidc, [])


# The BSD example is the Linux example with a header of its own and the BSD paths
# (ADR-0738): the configuration directory is a placeholder each package fills in,
# state lives in /var/db, and the clamd socket, which FreeBSD and OpenBSD refuse
# (ADR-0566) and NetBSD never reaches, names no path.
BSD_EXAMPLE_CONFIG = REPO_ROOT / "config" / "merovingian.conf.bsd.example"
BSD_HEADER_END = "# The Merovingian bootstrap configuration.\n"
SYSCONFDIR_PLACEHOLDER = "@SYSCONFDIR@"
SERVICE_HOME = "/var/db/merovingian"

# Each BSD package: its build script, the rc.d script it installs, and the files
# that create the service user with its home directory.
BSD_PACKAGES = {
    "freebsd": {
        "script": "scripts/build-freebsd-pkg.sh",
        "rc_script": "packaging/rc.d/merovingian",
        "home": "packaging/freebsd/+MANIFEST",
    },
    "openbsd": {
        "script": "scripts/build-openbsd-pkg.sh",
        "rc_script": "packaging/openbsd/rc.d/merovingian",
        "home": "packaging/openbsd/+INSTALL",
    },
    "netbsd": {
        "script": "scripts/build-netbsd-pkg.sh",
        "rc_script": "packaging/netbsd/files/merovingian.sh",
        "home": "packaging/netbsd/Makefile",
    },
}


def linux_example_in_bsd_paths(linux: str) -> str:
    """The Linux example rewritten the way the BSD example must differ from it."""
    bsd = linux.replace("/etc/merovingian/", f"{SYSCONFDIR_PLACEHOLDER}/merovingian/")
    bsd = bsd.replace("/var/lib/merovingian/", f"{SERVICE_HOME}/")
    return re.sub(
        r"^#security\.media\.clamd_socket_path=.*$",
        "#security.media.clamd_socket_path=",
        bsd,
        flags=re.MULTILINE,
    )


def script_variables(script: str) -> dict[str, str]:
    return dict(re.findall(r"^([A-Z_]+)=([^\s\"]+)$", script, re.MULTILINE))


def expand(value: str, variables: dict[str, str]) -> str:
    return re.sub(r"\$\{([A-Z_]+)\}", lambda match: variables[match.group(1)], value.strip('"'))


class BsdExampleConfigTests(unittest.TestCase):
    def test_bsd_example_is_the_linux_example_in_bsd_paths(self) -> None:
        # GIVEN the Linux example and the BSD example, a full copy kept beside it.
        self.assertTrue(BSD_EXAMPLE_CONFIG.is_file(), "BSD example config is missing")
        linux = EXAMPLE_CONFIG.read_text(encoding="utf-8")
        bsd = BSD_EXAMPLE_CONFIG.read_text(encoding="utf-8")
        self.assertIn(BSD_HEADER_END, bsd)
        header, body = bsd.split(BSD_HEADER_END, 1)

        # WHEN the BSD header is set aside.
        # THEN the rest is exactly the Linux example in BSD paths, so a key added to
        # one example and not the other fails here: apply the same change to both.
        self.assertEqual(
            BSD_HEADER_END + body,
            linux_example_in_bsd_paths(linux),
            "config/merovingian.conf.bsd.example has drifted from config/merovingian.conf.example",
        )

        # AND the header is all comment, so it sets nothing the Linux example does not.
        for line in header.splitlines():
            with self.subTest(line=line):
                self.assertTrue(line.startswith("#"), "the BSD header may hold only comments")

    def test_bsd_example_names_no_linux_location(self) -> None:
        # GIVEN the BSD example.
        bsd = BSD_EXAMPLE_CONFIG.read_text(encoding="utf-8")

        # WHEN each absolute path it names is read.
        paths = re.findall(r"=((?:/|@)[^\s,]+)", bsd)
        self.assertTrue(paths, "the BSD example names no path")

        # THEN each secret file sits in the package's configuration directory, the
        # SQLite database in the service user's home, and nothing in a Linux location.
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(
                    path.startswith(f"{SYSCONFDIR_PLACEHOLDER}/merovingian/")
                    or path.startswith(f"{SERVICE_HOME}/"),
                    f"{path} is not under the configuration directory or {SERVICE_HOME}",
                )
        for linux_location in ("/var/lib/", "/run/", "/etc/merovingian"):
            with self.subTest(linux_location=linux_location):
                self.assertNotIn(f"={linux_location}", bsd)

    def test_each_bsd_package_installs_the_bsd_example_for_its_own_config_directory(self) -> None:
        bsd = BSD_EXAMPLE_CONFIG.read_text(encoding="utf-8")
        for system, files in BSD_PACKAGES.items():
            with self.subTest(system=system):
                # GIVEN a BSD package's build script, rc.d script and user creation.
                script = (REPO_ROOT / files["script"]).read_text(encoding="utf-8")
                variables = script_variables(script)

                # WHEN the script stages the sample config.
                fills = re.findall(
                    r"""^sed "?'?s\|@SYSCONFDIR@\|([^|]+)\|g'?"? config/merovingian\.conf\.bsd\.example > "\$\{SAMPLE\}"$""",
                    script,
                    re.MULTILINE,
                )

                # THEN it stages the BSD example, never the Linux one, and fills in the
                # directory the server was built to read its config from.
                self.assertNotIn("config/merovingian.conf.example", script)
                self.assertEqual(len(fills), 1, f"{files['script']} must fill the BSD example once")
                sysconfdir = expand(fills[0], variables)
                configured = re.search(r"--sysconfdir=(\S+)", script)
                self.assertIsNotNone(configured, f"{files['script']} sets no --sysconfdir")
                self.assertEqual(sysconfdir, expand(configured.group(1), variables))
                self.assertRegex(
                    script, re.compile(r'^SAMPLE="[^"]+/etc/merovingian/merovingian\.conf\.sample"$', re.MULTILINE)
                )
                self.assertIn("still holds a placeholder", script)

                # AND the filled sample holds no placeholder and keeps its secrets in
                # the directory the rc.d script reads the config from.
                sample = bsd.replace(SYSCONFDIR_PLACEHOLDER, sysconfdir)
                self.assertNotRegex(sample, r"@[A-Z_]*@")
                rc_script = (REPO_ROOT / files["rc_script"]).read_text(encoding="utf-8")
                rc_script = rc_script.replace("@PKG_SYSCONFDIR@", sysconfdir)
                self.assertIn(f"{sysconfdir}/merovingian/merovingian.conf", rc_script)
                self.assertIn(f"security.secrets.master_key_file={sysconfdir}/merovingian/master-key", sample)

                # AND the SQLite database lives in the home the package gives the
                # service user, which its rc.d script also creates.
                self.assertIn(SERVICE_HOME, (REPO_ROOT / files["home"]).read_text(encoding="utf-8"))
                self.assertIn(SERVICE_HOME, rc_script)
                self.assertIn(f"#database.sqlite_path={SERVICE_HOME}/merovingian.sqlite3", sample)

    def test_port_metadata_installs_the_bsd_example(self) -> None:
        # GIVEN the pkgsrc recipe and the OpenBSD ports packing list kept for porters.
        makefile = (REPO_ROOT / "packaging" / "netbsd" / "Makefile").read_text(encoding="utf-8")
        plist = (REPO_ROOT / "packaging" / "openbsd" / "PLIST").read_text(encoding="utf-8")

        # WHEN each names the sample config it installs.
        # THEN the pkgsrc recipe fills the BSD example's placeholder with PKG_SYSCONFDIR,
        # installs it as the sample and copies it to the path its rc.d script reads.
        self.assertNotIn("config/merovingian.conf.example", makefile)
        self.assertIn("SUBST_FILES.sysconfdir=     config/merovingian.conf.bsd.example", makefile)
        self.assertIn("'s,@SYSCONFDIR@,${PKG_SYSCONFDIR},g'", makefile)
        self.assertIn("${WRKSRC}/config/merovingian.conf.bsd.example", makefile)
        self.assertIn("${PKG_SYSCONFDIR}/merovingian/merovingian.conf\n", makefile)

        # AND the OpenBSD packing list installs the sample and the config from it.
        self.assertIn("config/merovingian.conf.bsd.example", plist)
        self.assertIn("share/examples/merovingian/merovingian.conf.sample\n"
                      "@sample ${SYSCONFDIR}/merovingian/merovingian.conf\n", plist)

    def test_bsd_example_fill_is_the_sed_the_scripts_run(self) -> None:
        # GIVEN the sed the FreeBSD build script fills the sample with.
        sed = shutil.which("sed")
        if sed is None:
            self.skipTest("sed is not available")
        script = (REPO_ROOT / "scripts" / "build-freebsd-pkg.sh").read_text(encoding="utf-8")
        match = re.search(r"^sed '([^']+)' config/merovingian\.conf\.bsd\.example", script, re.MULTILINE)
        self.assertIsNotNone(match, "the sample fill is not where the test expects it")

        # WHEN that expression runs over the BSD example.
        filled = subprocess.run(
            [sed, match.group(1), str(BSD_EXAMPLE_CONFIG)], capture_output=True, text=True, check=True
        ).stdout

        # THEN every placeholder is replaced with FreeBSD's configuration directory.
        self.assertNotIn(SYSCONFDIR_PLACEHOLDER, filled)
        self.assertIn("security.registration.token_file=/usr/local/etc/merovingian/registration-token", filled)


# The logger module is the first argument of the qualified free functions, or of a
# SingleLog level method. File-local wrappers (`log_diagnostic(event, fields, ...)`)
# take the event first, so only the qualified calls are read. A level method is read only
# on `SingleLog::instance()` or a reference named `log` or `logger` (ADR-0872), so another
# type's `.warning("text", ...)` is not taken for a module.
QUALIFIED_LOG_CALL = re.compile(
    r'observability::log_diagnostic(?:_audit)?\s*\(\s*(?:"([A-Za-z0-9_]+)"|([A-Za-z_][A-Za-z0-9_:]*))'
)
LEVEL_LOG_CALL = re.compile(
    r'(?:\bSingleLog::instance\(\)|(?<![A-Za-z0-9_:.>])(?:log|logger))\s*(?:\.|->)\s*'
    r'(?:trace|debug|info|notice|warning|error|critical)\s*\(\s*'
    r'(?:"([A-Za-z0-9_]+)"(?:sv|s)?|([A-Za-z_][A-Za-z0-9_:]*))\s*,'
)
# The homeserver's `log_diagnostic_audit(database, "module", "event", ...)` takes the module second.
DATABASE_AUDIT_CALL = re.compile(r'\blog_diagnostic_audit\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*"([A-Za-z0-9_]+)"')
# A module named once in a constant: `auto log_module = std::string_view{"livekit"};` or `name{"livekit"};`.
MODULE_CONSTANT = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:std::string_view\s*\{\s*|std::string\s*\{\s*)?"([A-Za-z0-9_]+)"(?:sv|s)?\s*\}?\s*;'
)
MODULE_CONSTANT_INIT = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*"([A-Za-z0-9_]+)"(?:sv)?\s*\}\s*;')
# Identifiers that forward a caller's module rather than name one.
FORWARDED_MODULE_PARAMETERS = {"__func__", "mod", "logger", "module"}
EXAMPLE_LOG_MODULE_LINE = re.compile(r"^# log_modules\.([A-Za-z0-9_]+)=", re.MULTILINE)
# A C++ comment, or a literal a comment marker may appear inside: raw strings first, since
# their bodies may hold quotes, then ordinary string and character literals.
CPP_COMMENT_OR_LITERAL = re.compile(
    r'R"(?P<delim>[^()\\\s]{0,16})\(.*?\)(?P=delim)"'
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?:\\.|[^'\\\n])*'"
    r"|(?P<comment>//[^\n]*|/\*.*?\*/)",
    re.DOTALL,
)


def without_comments(source: str) -> str:
    """The C++ source with its comments blanked, so code a comment quotes is not read as a call."""
    return CPP_COMMENT_OR_LITERAL.sub(
        lambda match: re.sub(r"[^\n]", " ", match.group(0)) if match.group("comment") else match.group(0),
        source,
    )


def source_log_modules() -> tuple[set[str], set[str]]:
    """Every logger module the server's sources name, and any first argument the scan cannot resolve."""
    modules: set[str] = set()
    unresolved: set[str] = set()
    sources = [path for path in (REPO_ROOT / "src").rglob("*") if path.suffix in {".cpp", ".hpp"}]
    sources += list((REPO_ROOT / "include").rglob("*.hpp"))
    for path in sources:
        text = without_comments(path.read_text(encoding="utf-8"))
        constants = dict(MODULE_CONSTANT.findall(text))
        constants.update(MODULE_CONSTANT_INIT.findall(text))
        modules.update(DATABASE_AUDIT_CALL.findall(text))
        for regex in (QUALIFIED_LOG_CALL, LEVEL_LOG_CALL):
            for literal, identifier in regex.findall(text):
                short = identifier.split("::")[-1]
                if literal:
                    modules.add(literal)
                elif short in constants:
                    modules.add(constants[short])
                elif short not in FORWARDED_MODULE_PARAMETERS:
                    unresolved.add(f"{path.relative_to(REPO_ROOT).as_posix()}: {identifier}")
    return modules, unresolved


class ExampleLogModuleListTests(unittest.TestCase):
    def test_a_logger_call_quoted_in_a_comment_names_no_module(self) -> None:
        # GIVEN source whose comments quote logger calls, beside literals that hold comment markers.
        source = (
            '// observability::log_diagnostic("quoted_line", "x", fields, severity);\n'
            '/* observability::log_diagnostic("quoted_block", "x",\n   fields, severity); */\n'
            'auto const url = std::string_view{"https://example.org/*not-a-comment"};\n'
            'auto const raw = R"json({"a": "//", "b": "*/"})json";\n'
            'observability::log_diagnostic("real", "x", fields, severity); // trailing\n'
        )

        # WHEN the comments are blanked and the calls read.
        stripped = without_comments(source)
        modules = {literal for literal, _ in QUALIFIED_LOG_CALL.findall(stripped)}

        # THEN only the call in code counts, the literals are kept whole, and the lines stay where they were.
        self.assertEqual(modules, {"real"})
        self.assertIn('"https://example.org/*not-a-comment"', stripped)
        self.assertIn('R"json({"a": "//", "b": "*/"})json"', stripped)
        self.assertEqual(stripped.count("\n"), source.count("\n"))

    def test_a_module_literal_with_a_string_suffix_is_read_in_every_call_form(self) -> None:
        # GIVEN each call form the scan reads, with its module written as a `sv` or `s` literal.
        calls = {
            QUALIFIED_LOG_CALL: 'observability::log_diagnostic("qualified"sv, "x", fields, severity);',
            LEVEL_LOG_CALL: 'SingleLog::instance().info("level"sv, "x");\nlog.warning("level_s"s, "x");',
            DATABASE_AUDIT_CALL: 'log_diagnostic_audit(runtime.database, "audit"sv, "x", fields);',
        }

        # WHEN each is read.
        found = {
            regex.pattern: {match if isinstance(match, str) else match[0] for match in regex.findall(source)}
            for regex, source in calls.items()
        }

        # THEN the module is found, so a suffixed literal never drops a module from the expected set.
        self.assertEqual(found[QUALIFIED_LOG_CALL.pattern], {"qualified"})
        self.assertEqual(found[LEVEL_LOG_CALL.pattern], {"level", "level_s"})
        self.assertEqual(found[DATABASE_AUDIT_CALL.pattern], {"audit"})

    def test_a_level_named_method_of_another_type_names_no_module(self) -> None:
        # GIVEN level calls on the logger beside level-named methods of other types.
        source = (
            '::merovingian::observability::SingleLog::instance().info("on_instance", "x");\n'
            'log.warning("on_log", "x");\n'
            'logger->error("on_logger", "x");\n'
            'result.warning("deprecated", detail);\n'
            'status->error("phantom", detail);\n'
            'catalog.info("catalog", detail);\n'
        )

        # WHEN the level calls are read.
        modules = {literal for literal, _ in LEVEL_LOG_CALL.findall(source)}

        # THEN only the logger's calls name a module, so another type's method adds no phantom module.
        self.assertEqual(modules, {"on_instance", "on_log", "on_logger"})

    def test_each_example_lists_exactly_the_modules_the_server_logs_under(self) -> None:
        # GIVEN every logger module the server's sources name.
        modules, unresolved = source_log_modules()
        self.assertEqual(
            unresolved,
            set(),
            "a logger call names its module through an identifier this scan cannot resolve: "
            "name it with a literal or a string constant in the same file",
        )
        self.assertIn("turn", modules, "the scan no longer finds the modules it is meant to find")

        for path in (EXAMPLE_CONFIG, BSD_EXAMPLE_CONFIG):
            with self.subTest(path=path.name):
                # WHEN the example's commented `log_modules.<name>=` lines are read.
                listed = EXAMPLE_LOG_MODULE_LINE.findall(path.read_text(encoding="utf-8"))

                # THEN it lists each module once, and exactly the modules the server logs
                # under: a new module must be added to both examples, a removed one dropped.
                self.assertEqual(len(listed), len(set(listed)), f"{path.name} lists a module twice")
                self.assertEqual(
                    set(listed),
                    modules,
                    f"{path.name} log_modules list differs from the modules the sources log under "
                    f"(missing: {sorted(modules - set(listed))}, not logged: {sorted(set(listed) - modules)})",
                )


if __name__ == "__main__":
    unittest.main()
