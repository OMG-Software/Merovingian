# The documentation takes the outlined-toggle brand's colours and marks

* Status: accepted
* Date: 2026-11-24

Technical Story: OMG Software's outlined-toggle brand package and its project icons replace the angular four-square
mark and the `#ff8954` orange the documentation site took from the organisation site in ADR-0223.

## Context and Problem Statement

The brand package sets two colours, switch orange `#FF761F` and charcoal `#151515`, a full toggle mark, a standalone G
knob for small sizes, and a project icon for each repository: Merovingian's is the toggle with a server stack cut out of
its knob. Its guide keeps about one border-width of clear space round the toggle and uses the knob below about 120 px
wide; the project icons use their compact knob at 32 px and below. How should the documentation site and the README
take them on?

## Decision Drivers

* The marks are the package's own: a reader should see the same shapes and colours as everywhere else OMG Software
  shows them.
* ADR-0223 still holds: dark first, system fonts, nothing fetched from another origin, and text and links that meet
  WCAG AA in both schemes.

## Considered Options

1. Copy the package's SVG files unchanged into `docs/assets/`, choose each by its size as the guide says, and set the
   theme's orange and charcoal to the palette's.
2. Show the full OMG toggle as the header logo.
3. Load the marks from the organisation's site.
4. Use `#FF761F` for links in the light scheme too.

## Decision Outcome

Chosen option: 1.

* The header logo, about 24 px high, is the standalone G knob (`omg-g-knob-orange.svg`): the full toggle there would be
  about 50 px wide, well under the guide's 120 px. The favicon is Merovingian's compact knob
  (`merovingian-compact.svg`), the project icon's design for 32 px and below. The home page shows Merovingian's full
  toggle (`merovingian-toggle-mark.svg`), cropped to keep about one border-width of clear space, and the README the
  same toggle on its charcoal tile (`merovingian-icon.svg`), which reads on GitHub's light and dark themes alike.
* The files are byte-for-byte the package's, line endings aside; a new version of the package replaces them, and none
  is edited by hand. `tests/tooling/test_docs_site.py` checks their outlines and colours and that none can run or
  fetch anything.
* `--omg-orange` is `#ff761f` and `--omg-ink` `#151515`; the dark scheme's page, header, footer, links and accent use
  them. The greys between them are neutral (`#1f1f1f` panels, `#333333` rules), as charcoal is, where the earlier
  theme's were tinted.
* The light scheme keeps its darker oranges for links (`#a8461c`) and their hover (`#8f3a15`): `#FF761F` on its
  `#f4f3ee` page is about 2.4:1, under AA's 4.5:1. The brand orange stays for buttons, the eyebrow and focus rings.
* Loading the marks from another origin would report each reader's visit to it, which ADR-0223 rules out.

This supersedes ADR-0223's colours and marks; the rest of ADR-0223 stands.

### Negative Consequences

* The dark scheme's orange is a little deeper than before; its links measure about 6.8:1 on the page and 6.2:1 on
  cards, still above AA.
