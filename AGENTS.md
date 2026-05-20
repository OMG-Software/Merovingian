## Project Overview
The most secure Matrix Protocol homeserver ever created. Secure by design, implementation, and during runtime. Bulletproof!

## Language & Stack
- C++26
- LibSodium
- PostgreSQL
- SQLite
- Meson build system

## Code Presentation
- Always wrap code in code blocks with the relevant language tag.
- Include clear, concise inline comments explaining non-obvious logic.
- Show complete, runnable code — avoid partial snippets unless explicitly asked.
- After each code block, briefly explain what changed and why (2–5 sentences max).

## Tone & Style
- Be direct and concise. No filler phrases or lengthy preambles.
- Get to the answer first, then add context if needed.
- Avoid over-explaining things that are straightforward.

## General Rules
- Top level namespace should be `merovingian`
- RAII is non negotiable, use it.
- Prefer references over pointers
- Format C++ code with clang-format using the .clang-format file in the project root.
- If something is ambiguous, ask clarifying questions, never assume.
- Prefer simple, readable solutions over clever ones.
- Flag potential bugs or edge cases after the code explanation if relevant.
- With every change, update the documents in the docs folder.
- Use behaviour driven development in a GIVEN WHEN THEN style.
- Tests should test behaviour and state rather than specific outcomes.
- Create a new test(s) for the desired outcome prior to making the code change.
- After code change, run the new test(s).
- Bump the version number on creating a new branch.
- Record changes for each version in CHANGELOG.md
- Ignore `.clwb` folder.
- Always work in feature or bug branches, never main.
- Prefer meson wraps over system installed libs.
- Update docs\01-progress-tracker.md on each change, along with the other docs including CHANGELOG.