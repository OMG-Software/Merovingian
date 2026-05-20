#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MESON_BUILD = REPO_ROOT / "meson.build"
LINUX_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-linux.sh"
STATIC_LINUX_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-static-linux.sh"
BSD_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-bsd.sh"
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup-dev-env.sh"
WSL_SETUP_SCRIPT = REPO_ROOT / "scripts" / "wsl-setup.sh"
WSL_BUILD_CMD = REPO_ROOT / "wsl-build.cmd"
WSL_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-wsl.ps1"
WSL_BUILD_SHELL_WRAPPER = REPO_ROOT / "scripts" / "build-wsl.sh"
MAKE_SHIM = REPO_ROOT / "scripts" / "tool-shims" / "make"
VALIDATE_PHASE1_SCRIPT = REPO_ROOT / "scripts" / "validate-phase1-config.sh"
CURL_PACKAGEFILE = REPO_ROOT / "subprojects" / "packagefiles" / "curl" / "meson.build"
PACKAGE_SCAFFOLDS = {
    "deb": REPO_ROOT / "packaging" / "deb" / "control",
    "rpm": REPO_ROOT / "packaging" / "rpm" / "merovingian.spec",
    "freebsd": REPO_ROOT / "packaging" / "freebsd" / "+MANIFEST",
    "openbsd-descr": REPO_ROOT / "packaging" / "openbsd" / "DESCR",
    "openbsd-plist": REPO_ROOT / "packaging" / "openbsd" / "PLIST",
    "netbsd": REPO_ROOT / "packaging" / "netbsd" / "Makefile",
}
WRAPS = {
    "libcurl": REPO_ROOT / "subprojects" / "curl.wrap",
    "sqlite3": REPO_ROOT / "subprojects" / "sqlite3.wrap",
    "yyjson": REPO_ROOT / "subprojects" / "yyjson.wrap",
    "catch2": REPO_ROOT / "subprojects" / "catch2.wrap",
}


class DependencyWrapTests(unittest.TestCase):
    def test_runtime_dependencies_are_pinned_with_wraps(self) -> None:
        # GIVEN the runtime dependency inventory.
        for dependency_name, wrap_path in WRAPS.items():
            # WHEN reproducible source pinning is required.
            # THEN every runtime dependency has a committed Meson wrap file.
            self.assertTrue(wrap_path.is_file(), f"{dependency_name} wrap is missing")
            wrap_text = wrap_path.read_text(encoding="utf-8")
            self.assertRegex(wrap_text, r"\[wrap-(file|git)\]")
            self.assertTrue(
                "source_hash =" in wrap_text
                or "source_hash=" in wrap_text
                or "revision =" in wrap_text
                or "revision=" in wrap_text,
                f"{dependency_name} wrap must pin a source hash or git revision",
            )

    def test_meson_build_prefers_wrap_backed_dependencies(self) -> None:
        # GIVEN the top-level Meson build.
        self.assertTrue(MESON_BUILD.is_file(), "meson.build is missing")
        meson_build = MESON_BUILD.read_text(encoding="utf-8")

        # WHEN runtime dependencies are declared.
        # THEN wrap-backed dependencies are limited to the remaining vendored
        # runtime libraries.
        self.assertIn("fallback: ['sqlite3', 'sqlite3_dep']", meson_build)
        self.assertIn("default_options: ['default_library=static'", meson_build)
        self.assertIn("dependency('libcurl', fallback: ['curl', 'libcurl_dep'])", meson_build)

    def test_catch2_fallback_does_not_build_upstream_self_tests(self) -> None:
        # GIVEN Catch2 is a test-only dependency used through Meson fallback mode.
        tests_build = REPO_ROOT / "tests" / "meson.build"
        self.assertTrue(tests_build.is_file(), "tests meson.build is missing")
        tests_meson = tests_build.read_text(encoding="utf-8")

        # WHEN the fallback subproject is selected by forcefallback CI builds.
        # THEN Catch2's own upstream SelfTest target is disabled.
        self.assertIn("fallback: ['catch2', 'catch2_dep']", tests_meson)
        self.assertIn("default_options: ['tests=false']", tests_meson)

    def test_hardening_fortify_is_only_requested_for_optimized_builds(self) -> None:
        # GIVEN Fedora treats _FORTIFY_SOURCE without optimization as a warning.
        self.assertTrue(MESON_BUILD.is_file(), "meson.build is missing")
        meson_build = MESON_BUILD.read_text(encoding="utf-8")

        # WHEN warnings are fatal in debug builds.
        # THEN the FORTIFY flag is added only after Meson reports an optimized build.
        self.assertIn("if get_option('optimization') != '0'", meson_build)
        self.assertIn("hardening_compile_flags += ['-D_FORTIFY_SOURCE=3']", meson_build)

    def test_os_supplied_security_and_database_libraries_disallow_fallbacks(self) -> None:
        # GIVEN security-sensitive shared libraries receive distro security updates
        # through OS packages.
        self.assertTrue(MESON_BUILD.is_file(), "meson.build is missing")
        meson_build = MESON_BUILD.read_text(encoding="utf-8")

        # WHEN Meson is configured with forcefallback for source-pinned deps.
        # THEN OpenSSL, LibSodium, and libpq still disallow fallbacks so the
        # OS-provided shared libraries are used.
        self.assertIn("dependency('openssl', include_type: 'system', allow_fallback: false)", meson_build)
        self.assertIn("dependency('libsodium', include_type: 'system', allow_fallback: false)", meson_build)
        self.assertIn("dependency('libpq', include_type: 'system', allow_fallback: false)", meson_build)
        self.assertNotIn("fallback: ['openssl', 'openssl_dep']", meson_build)
        self.assertNotIn("fallback: ['libsodium', 'libsodium_dep']", meson_build)
        self.assertNotIn("fallback: ['libpq', 'libpq_dep']", meson_build)

    def test_build_wrappers_force_wrap_fallback_by_default(self) -> None:
        # GIVEN the local build wrappers.
        for wrapper_path in (LINUX_BUILD_WRAPPER, STATIC_LINUX_BUILD_WRAPPER, BSD_BUILD_WRAPPER, WSL_BUILD_WRAPPER):
            self.assertTrue(wrapper_path.is_file(), f"{wrapper_path.name} is missing")
            wrapper = wrapper_path.read_text(encoding="utf-8")

            # WHEN a developer runs the default build path.
            # THEN Meson is configured in forcefallback mode instead of system dependency mode.
            self.assertIn("forcefallback", wrapper)

    def test_windows_wsl_launch_chain_targets_the_dedicated_wsl_wrapper(self) -> None:
        # GIVEN the Windows entrypoints for WSL builds.
        self.assertTrue(WSL_BUILD_CMD.is_file(), "wsl-build.cmd is missing")
        self.assertTrue(WSL_BUILD_WRAPPER.is_file(), "build-wsl.ps1 is missing")
        self.assertTrue(WSL_BUILD_SHELL_WRAPPER.is_file(), "build-wsl.sh is missing")
        cmd_wrapper = WSL_BUILD_CMD.read_text(encoding="utf-8")
        ps_wrapper = WSL_BUILD_WRAPPER.read_text(encoding="utf-8")

        # WHEN a Windows developer launches the WSL build from cmd.exe or PowerShell.
        # THEN both bridge layers delegate to the dedicated WSL shell wrapper and preserve arguments.
        self.assertIn("scripts\\build-wsl.ps1", cmd_wrapper)
        self.assertIn("%*", cmd_wrapper)
        self.assertNotIn("Ubuntu-24.04", cmd_wrapper)
        self.assertIn("if ([string]::IsNullOrWhiteSpace($Distro))", ps_wrapper)
        self.assertIn("sh ./scripts/build-wsl.sh", ps_wrapper)
        self.assertNotIn("build-linux.sh", ps_wrapper)

    def test_wsl_build_wrapper_detects_stale_extracted_curl_packagefiles(self) -> None:
        # GIVEN the WSL wrapper must recover from previously extracted curl sources.
        self.assertTrue(WSL_BUILD_SHELL_WRAPPER.is_file(), "build-wsl.sh is missing")
        script = WSL_BUILD_SHELL_WRAPPER.read_text(encoding="utf-8")

        # WHEN the committed curl packagefile changes after Meson already
        # extracted subprojects/curl-<version>.
        # THEN the wrapper compares the extracted meson.build with the committed
        # packagefile and inspects the real configure log path under build/.
        self.assertIn('packagefile_curl_meson="$repo_root/subprojects/packagefiles/curl/meson.build"', script)
        self.assertIn('source_meson="${source_curl_dir}meson.build"', script)
        self.assertIn('build_config_log="${build_curl_dir}build/config.log"', script)
        self.assertIn('cmp -s "$packagefile_curl_meson" "$source_meson"', script)
        self.assertIn('run rm -rf "$source_curl_dir"', script)
        self.assertIn('run rm -rf "$build_curl_dir"', script)
        self.assertIn('if [ "$dry_run" -eq 0 ] && [ -d "$repo_root/subprojects" ]; then', script)
        self.assertNotIn('[ "$clean" -eq 0 ] && [ -d "$repo_root/subprojects" ]', script)

    def test_wsl_build_wrapper_stages_executable_make_shim_off_drvfs(self) -> None:
        # GIVEN Meson external_project executes the configured make program directly.
        self.assertTrue(WSL_BUILD_SHELL_WRAPPER.is_file(), "build-wsl.sh is missing")
        script = WSL_BUILD_SHELL_WRAPPER.read_text(encoding="utf-8")

        # WHEN the repo lives on /mnt/c and shell scripts do not carry Unix
        # execute bits reliably.
        # THEN the WSL wrapper stages a local executable make shim on the Linux
        # filesystem and prepends that directory before meson setup.
        self.assertIn('runtime_tool_shim_dir=${MEROVINGIAN_WSL_TOOL_SHIM_DIR:-"$HOME/.cache/merovingian-wsl-tool-shims"}', script)
        self.assertIn('repo_make_shim="$tool_shim_dir/make"', script)
        self.assertIn('runtime_make_shim="$runtime_tool_shim_dir/make"', script)
        self.assertIn('run mkdir -p "$runtime_tool_shim_dir"', script)
        self.assertIn("tr -d '\\015'", script)
        self.assertNotIn('run cp "$repo_make_shim" "$runtime_make_shim"', script)
        self.assertIn('run chmod 0755 "$runtime_make_shim"', script)
        self.assertIn('PATH="$runtime_tool_shim_dir:$tool_shim_dir:$PATH"', script)

    def test_static_linux_wrapper_builds_a_musl_static_pie_tarball(self) -> None:
        # GIVEN the static Linux fallback build wrapper.
        self.assertTrue(STATIC_LINUX_BUILD_WRAPPER.is_file(), "static Linux build wrapper is missing")
        wrapper = STATIC_LINUX_BUILD_WRAPPER.read_text(encoding="utf-8")

        # WHEN CI builds the fallback artifact for old distributions.
        # THEN the wrapper prefers static libraries, requests static PIE, and
        # rejects binaries that still contain a dynamic interpreter.
        self.assertIn("--prefer-static", wrapper)
        self.assertIn("-Dcpp_link_args=-static-pie", wrapper)
        self.assertIn("readelf -l", wrapper)
        self.assertIn('PACKAGE_ROOT="merovingian-${VERSION}-linux-static-x86_64"', wrapper)
        self.assertIn('TARBALL="${PACKAGE_ROOT}.tar.gz"', wrapper)

    def test_build_scripts_require_os_supplied_pkg_config_modules(self) -> None:
        # GIVEN the local build and setup scripts.
        for script_path in (LINUX_BUILD_WRAPPER, BSD_BUILD_WRAPPER):
            self.assertTrue(script_path.is_file(), f"{script_path.name} is missing")
            script = script_path.read_text(encoding="utf-8")

            # WHEN dependency resolution is OS-supplied for security and database
            # client libraries.
            # THEN the scripts fail early when required pkg-config modules are missing.
            self.assertIn("check_pkg_config_module libsodium", script)
            self.assertIn("check_pkg_config_module libpq", script)
            self.assertIn("check_pkg_config_module openssl", script)
            self.assertNotIn("check_pkg_config_module sqlite3", script)
            self.assertNotIn("check_pkg_config_module libcurl", script)

    def test_make_shim_exists_for_external_projects_on_bsd(self) -> None:
        # GIVEN the external-project wrappers for autotools sources.
        self.assertTrue(MAKE_SHIM.is_file(), "make shim is missing")
        shim = MAKE_SHIM.read_text(encoding="utf-8")

        # WHEN build hosts resolve `make`.
        # THEN BSD hosts can redirect to gmake while Linux keeps the system make binary.
        self.assertIn("gmake", shim)
        self.assertIn("/usr/bin/make", shim)

    def test_make_shim_forwards_meson_destdir_to_make(self) -> None:
        # GIVEN Meson's external_project helper passes DESTDIR through the environment.
        self.assertTrue(MAKE_SHIM.is_file(), "make shim is missing")
        shim = MAKE_SHIM.read_text(encoding="utf-8")

        # WHEN upstream Makefiles assign DESTDIR internally.
        # THEN the shim forwards DESTDIR as a make command-line variable so the
        # staged install path cannot be overwritten by the upstream Makefile.
        self.assertIn('${DESTDIR:-}', shim)
        self.assertIn('set -- "DESTDIR=$DESTDIR" "$@"', shim)

    def test_curl_dependency_uses_installed_header_root(self) -> None:
        # GIVEN curl installs curl/curl.h beneath the configured include root.
        self.assertTrue(CURL_PACKAGEFILE.is_file(), "curl packagefile is missing")
        packagefile = CURL_PACKAGEFILE.read_text(encoding="utf-8")

        # WHEN Meson exposes the curl external-project dependency.
        # THEN the dependency does not add a curl include subdirectory that
        # would make <curl/curl.h> resolve as curl/curl/curl.h on BSD hosts.
        self.assertIn("curl_project.dependency('curl')", packagefile)
        self.assertNotIn("subdir: 'curl'", packagefile)

    def test_curl_fallback_does_not_require_extra_compression_libraries(self) -> None:
        # GIVEN the curl fallback links a static libcurl archive into test binaries.
        self.assertTrue(CURL_PACKAGEFILE.is_file(), "curl packagefile is missing")
        packagefile = CURL_PACKAGEFILE.read_text(encoding="utf-8")

        # WHEN Meson consumes the external-project pkg-config metadata.
        # THEN optional compression backends are disabled so libcurl does not
        # require undeclared zlib or zstd link dependencies.
        self.assertIn("'--without-zlib'", packagefile)
        self.assertIn("'--without-zstd'", packagefile)

    def test_external_project_runtime_libraries_are_available_to_tests(self) -> None:
        # GIVEN some autotools fallbacks can still install shared libraries.
        tests_build = REPO_ROOT / "tests" / "meson.build"
        self.assertTrue(tests_build.is_file(), "tests meson.build is missing")
        tests_meson = tests_build.read_text(encoding="utf-8")

        # WHEN Fedora executes binaries from Meson's test harness.
        # THEN the default test setup exposes staged external-project library
        # directories through LD_LIBRARY_PATH.
        self.assertIn("wrapped_runtime_env.prepend(", tests_meson)
        self.assertIn("'LD_LIBRARY_PATH'", tests_meson)
        self.assertIn("add_test_setup('wrappedruntime', env: wrapped_runtime_env, is_default: true)", tests_meson)

    def test_aggregate_unit_test_binary_has_ci_sized_timeout(self) -> None:
        # GIVEN the full Catch2 unit suite runs as one aggregate Meson test.
        tests_build = REPO_ROOT / "tests" / "meson.build"
        self.assertTrue(tests_build.is_file(), "tests meson.build is missing")
        tests_meson = tests_build.read_text(encoding="utf-8")

        # WHEN fallback, coverage, or sanitizer builds execute the aggregate binary.
        # THEN the Meson test timeout is explicit and larger than the 30s default.
        self.assertIn("test('unit-tests', unit_tests, timeout: 120)", tests_meson)

    def test_phase1_config_validation_uses_wrapped_runtime_libraries(self) -> None:
        # GIVEN the Phase 1 config validation script runs built executables directly.
        self.assertTrue(VALIDATE_PHASE1_SCRIPT.is_file(), "Phase 1 validation script is missing")
        script = VALIDATE_PHASE1_SCRIPT.read_text(encoding="utf-8")

        # WHEN fallback external projects install shared libraries under the build tree.
        # THEN the script adds staged library directories to LD_LIBRARY_PATH before dry runs.
        self.assertIn("runtime_library_dirs=(", script)
        self.assertIn("subprojects/curl-8.20.0/dist/usr/local/lib64", script)
        self.assertNotIn("subprojects/postgresql-18.0/dist/usr/local", script)
        self.assertNotIn("subprojects/libsodium-1.0.22/dist/usr/local", script)
        self.assertIn("export LD_LIBRARY_PATH", script)

    def test_setup_scripts_install_the_extra_tools_needed_by_wrapped_sources(self) -> None:
        # GIVEN the environment bootstrap scripts.
        for script_path in (SETUP_SCRIPT, WSL_SETUP_SCRIPT):
            self.assertTrue(script_path.is_file(), f"{script_path.name} is missing")
            script = script_path.read_text(encoding="utf-8")

            # WHEN wrapped sources are configured from upstream tarballs.
            # THEN the setup path installs the non-compiler tools those source builds need.
            self.assertIn("perl", script)
            self.assertIn("bison", script)
            self.assertIn("flex", script)

    def test_setup_scripts_install_os_supplied_dynamic_library_headers(self) -> None:
        # GIVEN the environment bootstrap scripts install build dependencies.
        for script_path in (SETUP_SCRIPT, WSL_SETUP_SCRIPT):
            self.assertTrue(script_path.is_file(), f"{script_path.name} is missing")
            script = script_path.read_text(encoding="utf-8")

            # WHEN LibSodium and libpq are resolved from OS packages.
            # THEN Debian-family setup paths install their development headers.
            self.assertIn("libsodium-dev", script)
            self.assertIn("libpq-dev", script)

        setup_script = SETUP_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("libsodium-devel", setup_script)
        self.assertIn("libpq-devel", setup_script)
        self.assertIn("postgresql17-client", setup_script)

    def test_package_scaffolds_declare_dependency_policy(self) -> None:
        # GIVEN distribution package scaffolds exist for all supported platforms.
        for package_name, package_path in PACKAGE_SCAFFOLDS.items():
            self.assertTrue(package_path.is_file(), f"{package_name} scaffold is missing")

        # WHEN package metadata is inspected.
        deb_control = PACKAGE_SCAFFOLDS["deb"].read_text(encoding="utf-8")
        rpm_spec = PACKAGE_SCAFFOLDS["rpm"].read_text(encoding="utf-8")
        freebsd_manifest = PACKAGE_SCAFFOLDS["freebsd"].read_text(encoding="utf-8")
        openbsd_plist = PACKAGE_SCAFFOLDS["openbsd-plist"].read_text(encoding="utf-8")
        netbsd_makefile = PACKAGE_SCAFFOLDS["netbsd"].read_text(encoding="utf-8")

        # THEN build-time dependencies are declared for all packaged platforms.
        for token in ("libssl-dev", "libsodium-dev", "libpq-dev"):
            self.assertIn(token, deb_control)
        for token in ("openssl-devel", "libsodium-devel", "libpq-devel"):
            self.assertIn(token, rpm_spec)

        # THEN all three platforms declare security libraries as dynamic runtime
        # dependencies so OS package updates (apt upgrade libssl3 etc.) patch
        # the binary without rebuilding the package. App-level deps (SQLite,
        # curl, yyjson) remain statically linked via Meson wraps.
        for token in ("libsodium23", "libpq5", "libssl3"):
            self.assertIn(token, deb_control)
        for token in ("Requires:       libsodium", "Requires:       libpq"):
            self.assertNotIn(token, rpm_spec)
        # Only inspect the dependency-declaration section, not post-install
        # scripts: the scripts block may invoke openssl/curl as shell tools
        # without those being package-level runtime dependencies.
        freebsd_manifest_deps = freebsd_manifest.split("scripts:")[0]
        for token in ("openssl", "libsodium", "postgresql17-client", "curl"):
            self.assertNotIn(token, freebsd_manifest_deps)

        # THEN NetBSD and OpenBSD scaffolds declare their OS-supplied runtime deps.
        for token in ("openssl", "libsodium", "postgresql17-client", "curl"):
            self.assertIn(token, netbsd_makefile)
        for token in ("openssl", "libsodium", "postgresql-client", "curl"):
            self.assertIn(token, openbsd_plist)


if __name__ == "__main__":
    unittest.main()
