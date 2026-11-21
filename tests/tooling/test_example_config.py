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
# type's `.warning("text", ...)` is not taken for a module. The lookbehind keeps `log` or
# `logger` a name of its own: a member reached through another object (`ctx->logger->info`,
# `self.log.info`) is not the reference the rule names, and is not read.
#
# Each call form has an opening, which finds every call of that form whatever its arguments,
# and the full pattern, which reads the module from it. A call whose opening is found and whose
# arguments the full pattern cannot read (`(kModule)`, `module_of(rt)`, `database_of(rt)`) is
# reported, never skipped (ADR-0872).
MODULE_ARGUMENT = r'(?:"([A-Za-z0-9_]+)"(?:sv|s)?|([A-Za-z_][A-Za-z0-9_:]*))\s*,'
QUALIFIED_LOG_OPENING = re.compile(r'observability::log_diagnostic(?:_audit)?\s*\(')
QUALIFIED_LOG_CALL = re.compile(QUALIFIED_LOG_OPENING.pattern + r'\s*' + MODULE_ARGUMENT)
LEVEL_LOG_OPENING = re.compile(
    r'(?:\bSingleLog::instance\(\)|(?<![A-Za-z0-9_:.>])(?:log|logger))\s*(?:\.|->)\s*'
    r'(?:trace|debug|info|notice|warning|error|critical)\s*\('
)
LEVEL_LOG_CALL = re.compile(LEVEL_LOG_OPENING.pattern + r'\s*' + MODULE_ARGUMENT)
# The homeserver's `log_diagnostic_audit(database, "module", "event", ...)` takes the module second.
# It is told apart by its shape, never by what the database is called (`runtime.database`, or an
# alias such as `db`): any call not qualified with `observability::` and not opening with a literal.
# A file-local wrapper takes the event first, as a literal, so it never has that shape; the
# qualified `observability::` form is QUALIFIED_LOG_CALL's; a declaration (`auto log_diagnostic_audit(`)
# is no call. The database is read as a name, a member expression or `*pointer`; any other first
# argument is reported (ADR-0872).
DATABASE_AUDIT_OPENING = re.compile(r'(?<!observability::)(?<!auto )\blog_diagnostic_audit\s*\((?!\s*")')
DATABASE_AUDIT_CALL = re.compile(
    DATABASE_AUDIT_OPENING.pattern
    + r'\s*\*?\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\.|->)\s*[A-Za-z_][A-Za-z0-9_]*)*\s*,\s*'
    + MODULE_ARGUMENT
)
CALL_FORMS = (
    (QUALIFIED_LOG_OPENING, QUALIFIED_LOG_CALL),
    (LEVEL_LOG_OPENING, LEVEL_LOG_CALL),
    (DATABASE_AUDIT_OPENING, DATABASE_AUDIT_CALL),
)
# A module named once in a constant: `auto log_module = std::string_view{"livekit"};` or `name{"livekit"};`.
MODULE_CONSTANT = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:std::string_view\s*\{\s*|std::string\s*\{\s*)?"([A-Za-z0-9_]+)"(?:sv|s)?\s*\}?\s*;'
)
MODULE_CONSTANT_INIT = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*"([A-Za-z0-9_]+)"(?:sv|s)?\s*\}\s*;')
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


def without_literal_contents(source: str) -> str:
    """The source with each literal replaced by a quote, blanks and a quote, of the same length.

    A string's contents are never code, so nothing inside one is found as a call or a constant;
    the quotes stay, so a call that opens with a literal still looks like one.
    """
    return CPP_COMMENT_OR_LITERAL.sub(
        lambda match: match.group(0)
        if match.group("comment")
        else '"' + re.sub(r"[^\n]", " ", match.group(0)[1:-1]) + '"',
        source,
    )


def scan_log_modules(source: str, label: str) -> tuple[set[str], set[str]]:
    """The logger modules one C++ source names, and each module argument it cannot resolve, prefixed with `label`."""
    modules: set[str] = set()
    unresolved: set[str] = set()
    text = without_comments(source)
    # Calls and constants are found in `code`, where every literal's contents are blanked, so a
    # logger call written inside a string (`R"cpp(observability::log_diagnostic(...))cpp"`) is no
    # call. Their arguments are then read from `text` at the same position: the two are the same
    # length, character for character.
    code = without_literal_contents(text)
    # Every value each name is given in the file: the scan does not know scopes, so a name
    # given two values (say, a `log_module` in each of two functions) is ambiguous, never
    # silently resolved to whichever definition came last.
    constants: dict[str, set[str]] = {}
    for regex in (MODULE_CONSTANT, MODULE_CONSTANT_INIT):
        for found in regex.finditer(text):
            # Its value is a literal, so it is matched in `text`; its name must be code, not the
            # inside of some other literal, where `code` holds a blank instead.
            if code[found.start()] == text[found.start()]:
                constants.setdefault(found.group(1), set()).add(found.group(2))
    for opening, call in CALL_FORMS:
        for found in opening.finditer(code):
            read = call.match(text, found.start())
            if read is None:
                excerpt = " ".join(text[found.start() : found.end() + 40].split())
                unresolved.add(f"{label}: cannot read the module of `{excerpt}`")
                continue
            literal, identifier = read.group(1), read.group(2) or ""
            short = identifier.split("::")[-1]
            # A constant the file defines comes first, whatever it is called: the forwarding names
            # are skipped only when no constant of that name exists, so they skip by role, not name.
            if literal:
                modules.add(literal)
            elif len(constants.get(short, ())) == 1:
                modules.update(constants[short])
            elif short in constants:
                unresolved.add(f"{label}: {identifier} (given {sorted(constants[short])} in this file)")
            elif identifier in FORWARDED_MODULE_PARAMETERS:
                # Only a bare parameter forwards its caller's module. A qualified name such as
                # `shared::module` names a constant defined elsewhere, which the scan cannot read.
                continue
            else:
                unresolved.add(f"{label}: {identifier}")
    return modules, unresolved


def source_log_modules() -> tuple[set[str], set[str]]:
    """Every logger module the server's sources name, and any module argument the scan cannot resolve."""
    modules: set[str] = set()
    unresolved: set[str] = set()
    sources = [path for path in (REPO_ROOT / "src").rglob("*") if path.suffix in {".cpp", ".hpp"}]
    sources += list((REPO_ROOT / "include").rglob("*.hpp"))
    for path in sources:
        found, missed = scan_log_modules(path.read_text(encoding="utf-8"), path.relative_to(REPO_ROOT).as_posix())
        modules |= found
        unresolved |= missed
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

    def test_a_module_constant_with_a_string_suffix_resolves_in_both_forms(self) -> None:
        # GIVEN module constants written with an `s` or `sv` suffix, by assignment and by brace
        # initialisation, each used by a call.
        source = (
            'auto const assigned_s = "assigned_s"s;\n'
            'constexpr auto assigned_sv = std::string_view{"assigned_sv"sv};\n'
            'constexpr std::string_view braced_sv{"braced_sv"sv};\n'
            'std::string const braced_s{"braced_s"s};\n'
            'observability::log_diagnostic(assigned_s, "x", fields, severity);\n'
            'observability::log_diagnostic(assigned_sv, "x", fields, severity);\n'
            'observability::log_diagnostic(braced_sv, "x", fields, severity);\n'
            'observability::log_diagnostic(braced_s, "x", fields, severity);\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN every constant resolves, so a suffix never sends a well-named module to `unresolved`.
        self.assertEqual(modules, {"assigned_s", "assigned_sv", "braced_sv", "braced_s"})
        self.assertEqual(unresolved, set())

    def test_a_database_audit_call_resolves_its_module_like_the_other_call_forms(self) -> None:
        # GIVEN database audit calls through the database, an alias for it and a pointer, naming their
        # module with a literal, a constant, an unknown identifier and a forwarding parameter, beside a
        # wrapper called with a literal event and a qualified `observability::` call.
        source = (
            'constexpr auto audit_module = std::string_view{"audited"};\n'
            'log_diagnostic_audit(runtime.database, audit_module, "x", fields);\n'
            'auto& db = rt.database;\n'
            'log_diagnostic_audit(db, "through_alias", "x", fields);\n'
            'log_diagnostic_audit(*database_ptr, "through_pointer", "x", fields);\n'
            'log_diagnostic_audit(rt.homeserver.database, unknown_module, "x", fields);\n'
            'log_diagnostic_audit(database, logger, "x", fields);\n'
            'log_diagnostic_audit("event.name", {{"k", "v", false}}, severity);\n'
            'observability::log_diagnostic_audit(logger, event, fields, severity);\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN every call of the database overload is read whatever the database is called, the
        # constant resolves, the unknown identifier is reported, and neither the forwarding parameter,
        # the wrapper's event nor the qualified call's event is taken for a module.
        self.assertEqual(modules, {"audited", "through_alias", "through_pointer"})
        self.assertEqual(unresolved, {"f.cpp: unknown_module"})

    def test_a_wrapper_called_with_a_variable_event_is_reported_not_skipped(self) -> None:
        # GIVEN a file-local wrapper called with its event in a variable: the database overload's shape.
        source = 'log_diagnostic_audit(event_name, field_list, severity);\n'

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN it is reported, never silently skipped: the scan cannot tell it from a database call
        # (ADR-0872), and a wrapper is called with a literal event.
        self.assertEqual(modules, set())
        self.assertEqual(unresolved, {"f.cpp: field_list"})

    def test_a_constant_given_two_values_in_one_file_is_reported_not_guessed(self) -> None:
        # GIVEN two functions in one file, each with its own `log_module`.
        source = (
            'void a() { constexpr auto log_module = std::string_view{"first"};\n'
            '  observability::log_diagnostic(log_module, "x", fields, severity); }\n'
            'void b() { constexpr auto log_module = std::string_view{"second"};\n'
            '  observability::log_diagnostic(log_module, "x", fields, severity); }\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN neither value is guessed: the call is reported with both values, so the test fails
        # until each function names its module with a literal or a name of its own.
        self.assertEqual(modules, set())
        self.assertEqual(unresolved, {"f.cpp: log_module (given ['first', 'second'] in this file)"})

    def test_a_call_whose_module_argument_cannot_be_read_is_reported_not_skipped(self) -> None:
        # GIVEN one call of each form whose module, or the audit overload's database, is an
        # argument the scan cannot read: parenthesised, or a call.
        source = (
            'observability::log_diagnostic((kTurnModule), "x", fields, severity);\n'
            'observability::log_diagnostic(module_of(rt), "x", fields, severity);\n'
            'SingleLog::instance().info(module_name(), "x");\n'
            'log_diagnostic_audit(database_of(rt), "audited", "x", fields);\n'
            'log_diagnostic_audit((db), "audited", "x", fields);\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN no module is read from them, and each one is reported, quoting the call, so the
        # failure points at the call rather than at the example configurations.
        self.assertEqual(modules, set())
        self.assertEqual(len(unresolved), 5, sorted(unresolved))
        for excerpt in ("(kTurnModule)", "module_of(rt)", "module_name()", "database_of(rt)", "(db)"):
            with self.subTest(excerpt=excerpt):
                self.assertTrue(any(excerpt in entry for entry in unresolved), sorted(unresolved))

    def test_a_declaration_of_the_audit_overload_is_not_taken_for_a_call(self) -> None:
        # GIVEN the overload's declarations and a literal-event wrapper call.
        source = (
            'auto log_diagnostic_audit(LocalDatabase& database, std::string_view logger, std::string_view event,\n'
            '                          std::vector<StructuredLogField> fields) -> void;\n'
            'inline auto log_diagnostic_audit(std::string_view logger, std::string_view event) -> void;\n'
            'log_diagnostic_audit("event.name", {{"k", "v", false}}, severity);\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.hpp")

        # THEN nothing is read and nothing is reported.
        self.assertEqual((modules, unresolved), (set(), set()))

    def test_logger_call_text_inside_a_string_literal_is_not_a_call(self) -> None:
        # GIVEN a logger call and a module constant written inside string literals, beside a
        # real call that names its module with a literal and one through a real constant.
        source = (
            'auto const sample = R"cpp(observability::log_diagnostic("example_only", "event", fields, severity);)cpp";\n'
            'auto const doc = "log.info(\\"quoted_level\\", x); auto m = std::string_view{\\"in_string\\"};";\n'
            'constexpr auto log_module = std::string_view{"real_constant"};\n'
            'observability::log_diagnostic("real_literal", "event", fields, severity);\n'
            'observability::log_diagnostic(log_module, "event", fields, severity);\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN only the real calls count: the text inside the literals names no module and
        # defines no constant.
        self.assertEqual(modules, {"real_literal", "real_constant"})
        self.assertEqual(unresolved, set())

    def test_a_qualified_forwarding_name_is_reported_not_skipped(self) -> None:
        # GIVEN calls naming their module through `shared::module`, a constant in another file,
        # and through a bare `module` parameter.
        source = (
            'observability::log_diagnostic(shared::module, "event", fields, severity);\n'
            'auto log_line(std::string_view module) -> void\n'
            '{ observability::log_diagnostic(module, "event", fields, severity); }\n'
        )

        # WHEN the source is scanned.
        modules, unresolved = scan_log_modules(source, "f.cpp")

        # THEN only the bare parameter is skipped: the qualified name is reported.
        self.assertEqual(modules, set())
        self.assertEqual(unresolved, {"f.cpp: shared::module"})

    def test_a_constant_named_like_a_forwarding_parameter_still_resolves(self) -> None:
        # GIVEN a file that defines a module constant called `module`, and another file whose
        # `module` is only a parameter forwarding its caller's module.
        with_constant = (
            'constexpr auto module = std::string_view{"named_module"};\n'
            'observability::log_diagnostic(module, "x", fields, severity);\n'
        )
        forwarding = (
            'auto log_line(std::string_view module) -> void\n'
            '{ observability::log_diagnostic(module, "x", fields, severity); }\n'
        )

        # WHEN each is scanned.
        constant_modules, constant_unresolved = scan_log_modules(with_constant, "a.cpp")
        forwarded_modules, forwarded_unresolved = scan_log_modules(forwarding, "b.cpp")

        # THEN the constant names its module, and only the bare parameter is skipped: the skip
        # is by role, so a constant is never dropped for its name.
        self.assertEqual((constant_modules, constant_unresolved), ({"named_module"}, set()))
        self.assertEqual((forwarded_modules, forwarded_unresolved), (set(), set()))

    def test_a_level_named_method_of_another_type_names_no_module(self) -> None:
        # GIVEN level calls on the logger beside level-named methods of other types.
        source = (
            '::merovingian::observability::SingleLog::instance().info("on_instance", "x");\n'
            'log.warning("on_log", "x");\n'
            'logger->error("on_logger", "x");\n'
            'result.warning("deprecated", detail);\n'
            'status->error("phantom", detail);\n'
            'catalog.info("catalog", detail);\n'
            'm_log.info("member_prefix", detail);\n'
            'event_log.error("name_prefix", detail);\n'
            'log_.warning("name_suffix", detail);\n'
            'logger_->error("pointer_suffix", detail);\n'
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
