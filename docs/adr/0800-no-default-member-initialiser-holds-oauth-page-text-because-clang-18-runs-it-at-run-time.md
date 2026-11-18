# No default member initialiser holds OAuth page text, because clang 18 runs it at run time

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 9 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), part 0. Refines
[ADR-0772](0772-page-text-is-escaped-by-type-and-the-page-policy-names-only-a-validated-redirect-origin.md).

## Context and Problem Statement

`oauth::HtmlLiteral`, `HtmlName` and `PagePath` check their text in a `consteval` constructor (ADR-0772), so a literal
that holds a character needing escaping should not compile. In phase 8 a struct written as
`oauth::HtmlText message{"That's ..."};`, a default member initialiser, compiled and threw from the `HtmlLiteral`
constructor during a request.

Compiling probes with the Linux build's compiler (Ubuntu clang 18.1.3, `-std=c++2c`) on the VM showed:

* `auto w = Wrapper{"it's"};` in a function body is refused: "call to consteval function ... is not a constant
  expression".
* The same call in a default member initialiser compiles, whether the class is an aggregate built with `S{}` or with
  designated initialisers, has a defaulted constructor, or has a user-provided constructor, and whether the member's
  type is `HtmlLiteral` itself or a type built from one. Clang compiles the immediate invocation as an ordinary call,
  made when the member is initialised.

The standard requires the immediate invocation to be a constant expression in every one of these cases (for a
user-provided constructor, which is not immediate-escalating, there is no way out), so this is a compiler defect, not
the language rule. No form of the constructor makes clang 18 refuse it: the check never runs at compile time there.

## Decision Drivers

* A page's fixed text must be checked before the server runs, not during a request.
* The compiler cannot be relied on for this form, and the build compiler is not chosen per branch.

## Considered Options

* A tooling test that refuses the form in `src/` and `include/`.
* Make page text a template argument (`html<"text">`), which is always constant-evaluated.
* Leave it to review.

## Decision Outcome

Chosen option: the tooling test, `page-text-member-initialiser-tooling`
(`tests/tooling/test_page_text_member_initialisers.py`). No data member of a class, struct or union whose declared
type names `HtmlText`, `HtmlLiteral`, `HtmlName` or `PagePath` may have a default member initialiser other than empty
braces (an empty optional or vector holds no text). Text is given where the object is built, as an ordinary
expression that clang does check. The rule is `src/oauth/AGENTS.md` rule 12. The one such initialiser,
`PasswordFailure::message` in `AccountPage.cpp`, now gets its text in `password_failure`.

### Negative Consequences

* The test is a text scanner, not a parser: it strips comments, literals and preprocessor lines and tracks which braces
  open a class body. Its own cases cover a brace and an `=` initialiser, a wrapped type, local and nested classes, and
  the forms it must leave alone.
* A default argument of these types (`f(HtmlText t = "...")`) is not covered; none exists.

## Pros and Cons of the Options

### Page text as a template argument

* Good, because a template argument is constant-evaluated in every context, so the compiler would refuse the form.
* Bad, because every page text literal in the module and the handlers converts implicitly today; changing every call
  site is a larger change than the defect, made for one compiler's bug.

### Leave it to review

* Bad, because the defect was already missed once and only showed as a request that threw.

## Links

* Refines [ADR-0772](0772-page-text-is-escaped-by-type-and-the-page-policy-names-only-a-validated-redirect-origin.md)
