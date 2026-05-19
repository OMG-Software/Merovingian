#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MESON_BUILD = REPO_ROOT / "meson.build"
LINUX_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-linux.sh"
BSD_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-bsd.sh"
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup-dev-env.sh"
WSL_SETUP_SCRIPT = REPO_ROOT / "scripts" / "wsl-setup.sh"
WSL_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-wsl.ps1"
MAKE_SHIM = REPO_ROOT / "scripts" / "tool-shims" / "make"
LIBPQ_PACKAGEFILE = REPO_ROOT / "subprojects" / "packagefiles" / "libpq" / "meson.build"
WRAPS = {
    "libsodium": REPO_ROOT / "subprojects" / "libsodium.wrap",
    "libcurl": REPO_ROOT / "subprojects" / "curl.wrap",
    "libpq": REPO_ROOT / "subprojects" / "libpq.wrap",
    "sqlite3": REPO_ROOT / "subprojects" / "sqlite3.wrap",
    "yyjson": REPO_ROOT / "subprojects" / "yyjson.wrap",
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
                "source_hash =" in wrap_text or "revision =" in wrap_text,
                f"{dependency_name} wrap must pin a source hash or git revision",
            )

    def test_meson_build_prefers_wrap_backed_dependencies(self) -> None:
        # GIVEN the top-level Meson build.
        self.assertTrue(MESON_BUILD.is_file(), "meson.build is missing")
        meson_build = MESON_BUILD.read_text(encoding="utf-8")

        # WHEN runtime dependencies are declared.
        # THEN libsodium and libpq use explicit fallback variables, and curl/sqlite are
        # declared through dependency names that the committed wraps provide.
        self.assertIn(
            "dependency('libsodium', include_type: 'system', fallback: ['libsodium', 'libsodium_dep'])",
            meson_build,
        )
        self.assertIn("dependency('libpq', fallback: ['libpq', 'libpq_dep'])", meson_build)
        self.assertIn("dependency('sqlite3')", meson_build)
        self.assertIn("dependency('libcurl', fallback: ['curl', 'libcurl_dep'])", meson_build)

    def test_openssl_resolves_from_system_packages(self) -> None:
        # GIVEN OpenSSL receives distro security updates through system packages.
        self.assertTrue(MESON_BUILD.is_file(), "meson.build is missing")
        meson_build = MESON_BUILD.read_text(encoding="utf-8")

        # WHEN Meson is configured with forcefallback for source-pinned deps.
        # THEN OpenSSL still disallows fallback so the OS-provided library is used.
        self.assertIn("dependency('openssl', include_type: 'system', allow_fallback: false)", meson_build)
        self.assertNotIn("fallback: ['openssl', 'openssl_dep']", meson_build)

    def test_build_wrappers_force_wrap_fallback_by_default(self) -> None:
        # GIVEN the local build wrappers.
        for wrapper_path in (LINUX_BUILD_WRAPPER, BSD_BUILD_WRAPPER, WSL_BUILD_WRAPPER):
            self.assertTrue(wrapper_path.is_file(), f"{wrapper_path.name} is missing")
            wrapper = wrapper_path.read_text(encoding="utf-8")

            # WHEN a developer runs the default build path.
            # THEN Meson is configured in forcefallback mode instead of system dependency mode.
            self.assertIn("forcefallback", wrapper)

    def test_build_scripts_stop_requiring_system_pkg_config_modules(self) -> None:
        # GIVEN the local build and setup scripts.
        for script_path in (LINUX_BUILD_WRAPPER, BSD_BUILD_WRAPPER, SETUP_SCRIPT):
            self.assertTrue(script_path.is_file(), f"{script_path.name} is missing")
            script = script_path.read_text(encoding="utf-8")

            # WHEN dependency resolution is wrap-backed.
            # THEN the scripts do not fail early on missing system pkg-config modules.
            self.assertNotIn("check_pkg_config_module libsodium", script)
            self.assertNotIn("check_pkg_config_module libpq", script)
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

    def test_libpq_dependency_uses_installed_header_root(self) -> None:
        # GIVEN PostgreSQL installs libpq-fe.h directly into the include root.
        self.assertTrue(LIBPQ_PACKAGEFILE.is_file(), "libpq packagefile is missing")
        packagefile = LIBPQ_PACKAGEFILE.read_text(encoding="utf-8")

        # WHEN Meson exposes the libpq external-project dependency.
        # THEN the dependency does not add a postgresql include subdirectory
        # that would hide libpq-fe.h from consumers.
        self.assertIn("libpq_project.dependency('pq')", packagefile)
        self.assertNotIn("subdir: 'postgresql'", packagefile)

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


if __name__ == "__main__":
    unittest.main()
