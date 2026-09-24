# ULPF Frontend

React + Vite frontend for the Universal Log Pre-processing Framework.

## Run locally

```bash
npm install
npm run dev
```

Set `VITE_API_URL` (in a `.env` file or your shell) to point at the
backend, e.g. `VITE_API_URL=http://localhost:3000/api`. If unset it
falls back to the deployed Render URL baked into `src/services/api.ts`.

## Build

```bash
npm run build      # -> dist/
npm run typecheck  # tsc --noEmit, optional, does not block the build
```

**Vercel settings:** Framework preset "Vite", Build Command
`npm run build`, Output Directory `dist` (these are Vercel's defaults
for a Vite project, so usually nothing to change). Add `VITE_API_URL`
as an environment variable pointing at your Render backend's `/api`
URL.

## What's new in this revision

- **TypeScript.** Every source file is now `.tsx`/`.ts`
  (`tsconfig.json` is intentionally loose — `strict: false` — so the
  conversion doesn't block the build on type nitpicks; `npm run build`
  uses Vite/esbuild, which strips types without type-checking, so a
  stray type issue can never break your deploy. Run `npm run typecheck`
  separately if you want the full check).
- **Recycle Bin.** Deleting a log, account, alert, or log source now
  moves it to a Recycle Bin instead of destroying it immediately.
  - Logs page: checkboxes + **Select all**, **Delete selected**,
    **Clear all logs**, and a link to the Logs Recycle Bin
    (also in the sidebar for non-admin users).
  - Admin page: a **Recycle Bin** tab with four sub-pages (Logs,
    Accounts, Alerts, Log sources), each with select-all / restore /
    delete-forever / **Empty recycle bin**, plus one **Empty entire
    recycle bin** button that clears every category at once.
- **Paste-a-paragraph upload, shown one by one.** Pasting multiple log
  lines into the Logs page and clicking Upload now shows a live queue —
  each line appears immediately and updates in place (pending →
  processing → done/error) as it's actually uploaded, instead of a
  single "N processed" message at the end.
- **Buttons show they were clicked.** A shared `ActionButton` component
  (`src/components/common/ActionButton.tsx`) gives every action button
  a pressed/active animation on click and, for anything that calls the
  API, a spinner + "Working..." label until the request finishes.
