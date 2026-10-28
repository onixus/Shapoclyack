# Console design system (APEX)

The `web-next` console follows the APEX design system shared by the onixus
products: dark theme by default with an equal light theme, one accent colour,
semantic colour kept apart from the brand, density over air, a 4px grid and
36px controls. It landed in #616 (form fields) and #617 (the rest of the
console). This page lists the rules those PRs set and what they changed, so
parallel work — the Russian localisation in particular — builds on them
instead of reintroducing the old patterns.

## Rules for new and changed code

### Colour

- Use tokens, never raw palette classes for surfaces and text:
  `bg-background` / `bg-canvas`, `bg-card` / `bg-surface-1`,
  `bg-muted` / `bg-surface-2`, `bg-accent` / `bg-surface-3`, `bg-sunken`,
  `border-border`, `border-border-strong`, `border-control`,
  `text-foreground`, `text-muted-foreground`, `text-text-muted`.
  The shadcn names are aliases of the APEX values (`src/app/globals.css`).
- There is no light-theme remapping of `bg-slate-*`, `text-sky-*` and
  friends any more. A raw class renders the same colour in both themes, so it
  is wrong in one of them.
- `primary` / `text-primary` is the single accent. It never means a status.
- Status colours: `text-success`, `text-warning`, `text-danger`, `text-info`
  with `bg-*-subtle` plates. Severity colours: `sev-critical`, `sev-high`,
  `sev-medium`, `sev-low`, `sev-info` — for CVSS, NIST risk and asset
  criticality only.
- No gradients, glows, `backdrop-blur` or card shadows. Depth comes from
  surfaces and a 1px border. `shadow-md` is for menus, `shadow-lg` for modals.
- Primary buttons use the default `Button` variant; do not repaint them with
  `bg-sky-600`. One primary button per screen.

### Status and severity badges

- Render statuses with `StatusBadge` and a map from `src/lib/config/statuses.ts`.
  Each entry spreads one of the palette constants (`...SUCCESS`,
  `...IN_PROGRESS`, `...DANGER`, `...INFO`, `...MUTED`, `...SEV_*`), which
  also sets its `tone`. The badge draws the tone's icon next to the word, so
  a status is readable without colour.
- Severity badges carry the word (`Critical`, `High`, …) — never a bare dot
  or colour.

### Type

- No arbitrary sizes (`text-[10px]`, `text-[11px]`, `text-[13px]`). Use the
  scale: `text-overline` (11px, uppercase eyebrows such as sidebar groups),
  `text-xs` (12px, captions and table headers), `text-body-sm` (13px, dense
  tables and field labels), `text-sm` (14px, body), `text-h3` (15px).
- Table headers are sentence case: no `uppercase tracking-wider`.
- Numbers in tables and KPIs use `tabular-nums`; IPs, ports, CVEs, hashes and
  commands use `font-mono`.
- Always merge classes with `cn()`. It registers the APEX sizes with
  tailwind-merge; plain `twMerge` would read `text-body-sm` as a colour and
  drop it next to `text-muted-foreground`.

### Tables

- `ui/table` and `DataTable` already apply the APEX look (header on
  surface-2, 13px body, `tabular-nums`, surface-3 row hover). A hand-written
  `<thead>` uses `bg-muted text-xs font-medium text-muted-foreground`.

### Forms

- Build forms from `Field`, `FieldGrid` and `CheckboxOption`
  (`src/components/ui/field.tsx`): label row, control, hint row. Put the
  hint in `hint` and point the control at it with
  `aria-describedby={fieldHintId(id)}`. Mark optional fields with
  `optional={t("launcher.optional")}` instead of "(Optional)" in the label.
- `reserveHint={false}` in dialogs and filter bars where no neighbour has a
  hint.

### Layout

- Grid children that hold a table or long text need `min-w-0`, and toolbars
  of filters need `flex-wrap`; otherwise the page scrolls sideways at 375px.

## Notes for the Russian localisation

- Translate labels through `t()` / `t.label()` (`src/lib/i18n/messages.ts`).
  `StatusBadge` already passes the map's `label` through `t.label`; severity
  labels are capitalised by CSS, so keep the dictionary values lower case.
- Russian labels are longer: let fields take the grid width (`FieldGrid`)
  rather than fixed `w-40` / `w-48` controls.
- Strings still hard-coded in English in the forms moved to `Field` in #617,
  ready for keys:
  - `components/vulnerability/bulk-actions.tsx`: "Ticket key",
    "Accepted until", "Reason (required)", "Note", the dialog titles and the
    "Apply to N" button.
  - `app/(dashboard)/schedules/page.tsx`: "Name", "Delta discovery",
    "Notify", "TCP ports override", "UDP ports override", the intent and
    speed-profile options, "Edit schedule" / "Delete schedule".
  - `components/service-tokens-panel.tsx`: "Name", "Role",
    "Allowed source networks", "Expiry notice (days)",
    "Rotation overlap (seconds)" and their hints, "Issue token".
  - `src/app/(dashboard)/integrations/page.tsx` shows
    `integrations.state.enabled|disabled` through `StatusBadge`; the
    schedule and system pages use the shared `enabled` / `disabled` labels.
- Tests that look fields up by label (`getByLabelText("Scopes")`,
  `/Reason/`, …) need updating together with the strings.

## Where the values live

- Token values for both themes: `web-next/src/app/globals.css`
  (`--apex-*`, `--sev-*`).
- Tailwind names: `web-next/tailwind.config.ts`.
- Status maps and tones: `web-next/src/lib/config/statuses.ts`.
- Source of truth for the tokens: the APEX design system (`tokens.json`);
  change a value there first, then here.
