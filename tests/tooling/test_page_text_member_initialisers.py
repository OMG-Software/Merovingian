#!/usr/bin/env python3
"""No default member initialiser holds OAuth page text (ADR-0800).

`oauth::HtmlLiteral`, `HtmlName` and `PagePath` check their text in a consteval
constructor, so a literal that breaks the rule should not compile. Clang 18 (the
Linux build's compiler) does not constant-evaluate an immediate invocation in a
default member initialiser: it compiles the call and runs it when the member is
initialised, so a bad literal throws during a request instead of failing the
build. Phase 8 met it as an apostrophe on the account page. The compiler cannot
be made to refuse the form, so this test does: no data member of a class, struct
or union whose declared type names `HtmlText`, `HtmlLiteral`, `HtmlName` or
`PagePath` may have a default member initialiser other than empty braces (an
empty optional or vector holds no text), anywhere under `src/` or `include/`.
Give the text where the object is built instead.

The scanner is text-based, not a C++ parser. It removes comments, string and
character literals and preprocessor lines, tracks which braces open a class body,
and judges each declaration made directly in one.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_DIRS = (REPO_ROOT / "src", REPO_ROOT / "include")
SUFFIXES = {".cpp", ".hpp", ".h", ".cc", ".hh", ".ipp"}

PAGE_TEXT_TYPE = re.compile(r"\b(?:HtmlText|HtmlLiteral|HtmlName|PagePath)\b")
RAW_STRING = re.compile(r'R"([^(\s"\\]{0,16})\((?:.|\n)*?\)\1"')
STRING = re.compile(r'"(?:\\.|[^"\\\n])*"')
CHARACTER = re.compile(r"'(?:\\.|[^'\\\n])'")
BLOCK_COMMENT = re.compile(r"/\*(?:.|\n)*?\*/")
LINE_COMMENT = re.compile(r"//[^\n]*")
PREPROCESSOR = re.compile(r"^[ \t]*#[^\n]*(?:\\\n[^\n]*)*", re.M)
ATTRIBUTE = re.compile(r"\[\[.*?\]\]", re.S)
ACCESS = re.compile(r"^\s*(?:(?:public|private|protected)\s*:\s*)+")
CLASS_HEAD = re.compile(r"^\s*(?:template\s*<.*>\s*)?(?:struct|class|union)\b")
ENUM_HEAD = re.compile(r"^\s*enum\b")
# Declarations directly in a class body that are not data members with an initialiser.
NOT_A_MEMBER = re.compile(
    r"^\s*(?:static|constexpr|constinit|using|typedef|friend|template|static_assert|enum|struct|class|union)\b"
)
DECLARATOR_END = re.compile(r"[A-Za-z_]\w*\s*$")


def strip_code(text: str) -> str:
    """The text with comments, literals and preprocessor lines blanked, line breaks kept."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    def blank_literal(match: re.Match[str]) -> str:
        # A literal keeps a mark, so `{"text"}` is not mistaken for empty braces.
        return "0" + blank(match)[1:]

    for pattern in (RAW_STRING, BLOCK_COMMENT, LINE_COMMENT, STRING, CHARACTER, PREPROCESSOR):
        text = pattern.sub(blank_literal if pattern in (RAW_STRING, STRING, CHARACTER) else blank, text)
    return text


def is_initialised_page_text_member(statement: str, opener: str) -> bool:
    """Whether `statement`, the text in a class body before `opener` (`{` or `;`), declares a page text member with a
    default member initialiser."""
    statement = ACCESS.sub("", ATTRIBUTE.sub(" ", statement))
    if NOT_A_MEMBER.match(statement):
        return False
    if opener == "{":
        declaration, _, _ = statement.partition("=")
        if "=" not in statement and not DECLARATOR_END.search(declaration):
            return False
    else:
        if "=" not in statement:
            return False
        declaration, _, _ = statement.partition("=")
        if "operator" in declaration:
            return False
    # A function (declaration or definition) has a parameter list before any initialiser.
    if "(" in declaration:
        return False
    return PAGE_TEXT_TYPE.search(declaration) is not None


def initialised_page_text_members(text: str) -> list[int]:
    """The line numbers of every page text data member with a default member initialiser in `text`."""
    code = strip_code(text)
    findings: list[int] = []
    stack: list[str] = []
    statement_start = 0
    for index, char in enumerate(code):
        if char not in "{};":
            continue
        statement = code[statement_start:index]
        in_class = bool(stack) and stack[-1] == "class"
        if char == "{":
            # An empty `{}` value-initialises (an empty optional or vector) and holds no text.
            empty_braces = code[index + 1 :].lstrip().startswith("}")
            if in_class and not empty_braces and is_initialised_page_text_member(statement, "{"):
                findings.append(code.count("\n", 0, index) + 1)
            opens_class = CLASS_HEAD.match(ACCESS.sub("", statement)) is not None and "(" not in statement
            stack.append("class" if opens_class and not ENUM_HEAD.match(statement) else "other")
        elif char == "}":
            if stack:
                stack.pop()
        elif in_class and is_initialised_page_text_member(statement, ";"):
            findings.append(code.count("\n", 0, index) + 1)
        statement_start = index + 1
    return findings


def scanned_files() -> list[Path]:
    return sorted(
        path
        for directory in SCANNED_DIRS
        for path in directory.rglob("*")
        if path.is_file() and path.suffix in SUFFIXES
    )


class ScannerFindsTheForm(unittest.TestCase):
    def test_a_brace_initialised_member_is_found(self) -> None:
        text = 'struct Failure final\n{\n    int status{1};\n    oauth::HtmlText message{"it\'s"};\n};\n'
        self.assertEqual(initialised_page_text_members(text), [4])

    def test_an_equals_initialised_member_is_found(self) -> None:
        text = 'class Page\n{\npublic:\n    HtmlLiteral title = "Sign in";\n};\n'
        self.assertEqual(initialised_page_text_members(text), [4])

    def test_a_wrapped_type_is_found(self) -> None:
        text = 'struct S\n{\n    std::optional<oauth::HtmlText> notice{oauth::HtmlText{"x"}};\n};\n'
        self.assertEqual(initialised_page_text_members(text), [3])

    def test_a_local_struct_in_a_function_is_found(self) -> None:
        text = 'auto f() -> int\n{\n    struct Local\n    {\n        PagePath path{"/a"};\n    };\n    return 0;\n}\n'
        self.assertEqual(initialised_page_text_members(text), [5])

    def test_a_nested_struct_is_found(self) -> None:
        text = 'struct Outer\n{\n    struct Inner final : Base\n    {\n        HtmlName name{"n"};\n    };\n};\n'
        self.assertEqual(initialised_page_text_members(text), [5])


class ScannerLeavesOtherFormsAlone(unittest.TestCase):
    def test_a_member_without_an_initialiser(self) -> None:
        text = "struct S\n{\n    oauth::HtmlText message;\n    int count{0};\n};\n"
        self.assertEqual(initialised_page_text_members(text), [])

    def test_an_empty_brace_initialiser(self) -> None:
        text = "struct S\n{\n    std::optional<HtmlText> error{};\n    std::vector<HtmlName> names = {};\n};\n"
        self.assertEqual(initialised_page_text_members(text), [])

    def test_a_local_variable(self) -> None:
        text = 'auto f() -> void\n{\n    auto text = oauth::HtmlText{"x"};\n    HtmlText other{"y"};\n}\n'
        self.assertEqual(initialised_page_text_members(text), [])

    def test_member_functions_and_static_constants(self) -> None:
        text = (
            "class Page\n{\npublic:\n"
            "    Page(HtmlText title);\n"
            "    [[nodiscard]] auto title() const -> HtmlText const& { return m_title; }\n"
            '    static constexpr PagePath path{"/a"};\n'
            "    auto operator=(HtmlText const&) -> Page& = delete;\n"
            "private:\n    HtmlText m_title;\n};\n"
        )
        self.assertEqual(initialised_page_text_members(text), [])

    def test_text_in_comments_and_strings(self) -> None:
        text = (
            "struct S\n{\n"
            '    // HtmlText message{"x"};\n'
            '    char const* doc{"HtmlText message{}"};\n'
            '    char const* raw{R"(HtmlLiteral x = "y";)"};\n'
            "};\n"
        )
        self.assertEqual(initialised_page_text_members(text), [])

    def test_an_enum_class_body(self) -> None:
        text = "enum class Kind\n{\n    html_text = 1,\n};\n"
        self.assertEqual(initialised_page_text_members(text), [])


class SourcesHaveNoInitialisedPageTextMember(unittest.TestCase):
    def test_the_scan_reads_the_page_text_types(self) -> None:
        files = scanned_files()
        self.assertTrue(any(path.name == "HtmlText.hpp" for path in files))
        self.assertTrue(any(path.name == "AccountPage.cpp" for path in files))

    def test_no_page_text_member_has_a_default_member_initialiser(self) -> None:
        findings = [
            f"{path.relative_to(REPO_ROOT).as_posix()}:{line}"
            for path in scanned_files()
            for line in initialised_page_text_members(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(
            findings,
            [],
            "a data member of type HtmlText, HtmlLiteral, HtmlName or PagePath has a default member initialiser; "
            "clang 18 runs its compile-time check at run time there (ADR-0800). Give the text where the object is built.",
        )


if __name__ == "__main__":
    unittest.main()
