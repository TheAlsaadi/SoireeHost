# Static screens: design critique and accessibility pass

15 Nov 2026. Phase 5, step 1 (plan section 9, ADR-0009). These screens are static HTML with sample data, made for the owner's approval before any component is built.

**What is here:**

- `tokens.css`: the design tokens.
- `screens.css`: styles that become the components' styles.
- `icons.svg`: 26 Fluent System Icons, MIT, path data only, from commit `67e6dec1` of `microsoft/fluentui-system-icons`.
- `sites.html`, `activity.html` and `security.html`: the three screens.
- `tokens.html`: the tokens, with a live contrast table.
- `index.html`: links to every screen in every theme.
- `theme.js`, `contrast.js` and `preview.css`: preview helpers only. They never ship.

**To view them:**

```
python -I -m http.server 9246 --bind 127.0.0.1 --directory docs/design/phase5-static
```

Then open `http://127.0.0.1:9246/`. The `?theme=` links force light, dark or a preview of a contrast theme. Without them, the screens follow the Windows setting.

## Design critique (`design:design-critique`)

**Overall.** The screens read as a quiet Windows utility.

- The status line and the one plum "Add site" button draw the eye first, which is the right order.
- Everything else is neutral grey, 1 px lines and type.
- Status is a word plus a shape everywhere, so colour is never the only signal.

**Changed after the critique:**

| Finding | Severity | Change |
| --- | --- | --- |
| At narrow window widths "No address yet" spilled over the Type column | Moderate | Cells clip with an ellipsis. Below 60rem the Sites list drops the address column, which the detail pane shows in full |
| "Not shared" for a site that is on but has no link read like an error in sharing | Minor | Now "Not online" |
| Every normal log result carried a hollow circle, which was noise | Minor | Only blocked requests and errors carry a mark. A spacer keeps the numbers aligned |
| Filters, live note and pause button wrapped onto two rows in Activity | Minor | The live note and "Pause updates" moved into the screen header |
| Long addresses were cut short in the Sites list | Minor | The list shows the host name, and the full `https://` address is in the pane and in a tooltip |
| The plum on dark leaned pink | Minor | Desaturated to `#DBB6D1` (9.6:1 with its text) |
| The "on" switch on a selected row vanished in the contrast theme, because the track and the selection were both Highlight | Moderate | A switch on a selected row takes the row's text colour |

**Banned list check (plan section 7).** None of these appear:

- gradients, gradient text, glass, blur, glow or neon;
- emoji or sparkle icons, or a hero banner;
- grids of identical cards, or pill badges;
- vanity tiles, invented charts or animated counters;
- a fake-terminal look, a dark-only theme, or a component-library default.

Monospace is used only where section 7 asks for it: addresses, paths, log lines and rule ids. The Security screen's grouped lists are checklists with real states, not a card grid.

**Left for the owner to judge:**

- **The accent.** Plum was chosen to be distinct from the green, amber and red of status, and from the default Windows blue. It is a solid colour on one button.
- **Density.** Rows are 40 px. Windows 11's own lists use 36 to 40 px.

## Accessibility pass (`design:accessibility-review`, WCAG 2.1 AA)

**Summary:** 4 issues found and fixed (0 critical, 2 major, 2 minor); 2 checks remain for the built app.

### Colour contrast

Measured live by `contrast.js` in each theme. Every pair passes in all three themes.

| Pair | Needs | Light | Dark |
| --- | --- | --- | --- |
| Body text on the main surface | 4.5 | 16.5 | 13.5 |
| Secondary text on the main surface | 4.5 | 6.1 | 6.6 |
| Secondary text on the rail | 4.5 | 5.9 | 7.2 |
| Selected row text | 4.5 | 14.2 | 10.2 |
| Text on a blocked log row | 4.5 | 15.6 | 12.8 |
| Primary button text | 4.5 | 8.8 | 9.6 |
| Focus ring | 3 | 8.4 | 8.4 |
| Control edges (inputs, switches) | 3 | 3.5 | 4.2 |
| OK, warning and danger icons | 3 | 6.3 / 6.3 / 6.6 | 6.9 / 8.5 / 6.9 |
| Warning text | 4.5 | 6.1 | 9.2 |

The contrast-theme preview passes too, at 8.6:1 or better. In the real app, Windows contrast themes switch on the `forced-colors` block, which maps every role to the user's own system colours.

### Findings and fixes

| # | Issue | WCAG | Severity | Fix |
| --- | --- | --- | --- | --- |
| 1 | At 200 % zoom (a 600 × 380 CSS viewport) the 12rem rail left too little room, and Activity's request column shrank to nothing | 1.4.4, 1.4.10 | Major | Below 45rem the rail shows icons only, and the names stay for screen readers. Activity drops the visitor column, which the pane shows. A short window scrolls as one page |
| 2 | The "on" switch on a selected row was invisible in contrast themes | 1.4.11 | Major | Fixed as in the critique above |
| 3 | The path and user-agent blocks were named with `aria-labelledby` on `pre`, which ARIA does not allow | 4.1.2 | Minor | Removed. The preceding heading labels them. The built component uses a description list |
| 4 | A blocked log row was marked by colour and a bar, with a word only in the Result column | 1.4.1 | Minor | Already met: the Result cell says "Blocked" next to a barred-circle icon. Kept as is and recorded |

### Keyboard

The tab order on Sites follows the layout:

1. the five rail links;
2. Take everything offline;
3. Add site;
4. the selected row;
5. each row's switch;
6. the pane's Close button;
7. Copy address, Show QR code and Stop sharing;
8. Edit site, Stop serving and Remove site.

The focus ring is a 2 px plum outline with a 2 px offset, and Highlight in contrast themes. It was checked on the switch, which is the smallest target.

In the built app, the lists are ARIA grids with one tab stop:

- the arrow keys move between rows;
- Enter opens the detail pane;
- Space toggles the row's switch;
- Escape closes the pane and returns focus to the row.

These belong to the component build and get their own tests.

### Screen readers

**What is announced:**

- Rail: a `nav` named "SoiréeHost", with `aria-current="page"` on the current screen.
- Status line: `role="status"`, so changes are announced politely.
- Status icons: hidden from assistive technology, because the word beside them carries the meaning.
- Switches: `role="switch"`, named "Serve <site name>".
- Detail pane: an `aside` labelled by its heading.

The live Activity table is deliberately not a live region, so a busy site does not flood the screen reader. The status line announces a summary instead.

### Still to check in the built app

These can't be checked on static HTML:

- With a real Windows contrast theme on (Settings > Accessibility > Contrast themes), the `forced-colors` path in WebView2. The browser preview used here cannot switch forced colours on by itself.
- NVDA on the built components, and the Windows text-size setting (Settings > Accessibility > Text size) in WebView2.

Both are part of the Phase 5 acceptance check "The accessibility review passes at AA and the whole app works by keyboard".
