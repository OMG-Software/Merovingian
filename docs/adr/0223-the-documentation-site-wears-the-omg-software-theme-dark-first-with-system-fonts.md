# The documentation site wears the OMG Software theme, dark first, with system fonts

* Status: accepted
* Date: 2026-10-25

Technical Story: match the published documentation site to the OMG Software organisation site (0.12.46).

## Context and Problem Statement

The documentation site on GitHub Pages used Material's stock black-and-indigo palette, followed the
reader's system light/dark preference, and loaded Roboto from Google Fonts. The OMG Software
organisation site, which links to it, is dark only, uses one orange accent (`#ff8954`) on near-black
(`#151616`), Arial and Consolas, and a four-square orange mark. How should the documentation site
take that theme on?

## Decision Drivers

* A reader moving from the organisation site to the documentation should see the same brand.
* Long reference pages must stay readable: body text and links meet WCAG AA (4.5:1) in every scheme.
* A security-first project's site should not report its readers' visits to a third party.

## Considered Options

* Dark only, exactly as the organisation site
* Dark first, with a themed light scheme behind the toggle
* Keep following the system preference, recoloured

## Decision Outcome

Chosen option: "Dark first, with a themed light scheme behind the toggle", because it opens as the
organisation site does while keeping a light scheme for readers who need one for long technical
pages or printing.

* The palette lists `slate` first and has no `media` queries, so a first visit opens dark whatever
  the system preference; Material remembers a reader's toggle.
* Both schemes use `primary: custom` and `accent: custom` and take every colour from
  `docs/stylesheets/extra.css`. The header and footer stay OMG near-black in both. The light scheme's
  link colour is a darker orange (`#a8461c`), because `#ff8954` on a light page fails AA; its accent,
  which Material draws hovered and focused link and button text in, is darker still (`#8f3a15`), so
  hover stays visible and above AA on the page and on cards.
* `font: false`: the site uses Arial and Consolas from the reader's system, as the organisation site
  does, and makes no request to Google Fonts. `extra.css` holds no `@import` or remote URL.
* The logo and favicon are local SVG files with no script, event handler or external reference.

`tests/tooling/test_docs_site.py` (`SiteThemeTests`) holds each of these.

### Positive Consequences

* One brand across the organisation site and the documentation.
* Pages load nothing from outside the site's own origin.

### Negative Consequences

* A reader whose system prefers light now sees dark until they toggle once.
* Material's built-in palette names no longer apply; a colour change is made in `extra.css`.

## Pros and Cons of the Options

### Dark only, exactly as the organisation site

* Good, because it is the closest match.
* Bad, because it removes the light scheme that long reference pages and printing benefit from.

### Keep following the system preference, recoloured

* Good, because it respects the reader's setting.
* Bad, because half of first visits would open in a scheme the organisation site never shows.
