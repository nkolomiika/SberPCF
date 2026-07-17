# design-sync notes — SberPCF

## Repo shape (read this first)
- This repo is the **SberPCF web app** (`frontend/`), a Vite + React + **MUI v6** application — NOT a published component-library design system. There is no `dist/` of reusable exported components and `npm run build` produces an app bundle, not a library.
- The "design system" is: the **dark MUI theme** defined inline in `frontend/src/main.tsx` (`createAppTheme`) + how MUI primitives are styled by it.
- To sync, we built a small **themed-MUI-kit library** at `frontend/design-kit/` that re-exports the real `@mui/material` components the app uses, plus `sberTheme` / `SberThemeProvider` (the theme + root provider). It is NOT a reimplementation — every component is the genuine MUI export; the branding comes entirely from the theme.

## Build
- Kit source: `frontend/design-kit/{index.ts,theme.ts,SberThemeProvider.tsx}`. `theme.ts` is extracted **verbatim** from `frontend/src/main.tsx` — if the app theme changes, re-extract it.
- Build command (`cfg.buildCmd`): `cd frontend && npx tsc -p design-kit/tsconfig.json` → emits `frontend/design-kit/dist/{index.js,index.d.ts,...}`.
- Converter is run from the repo root with `--entry ./frontend/design-kit/dist/index.js --node-modules frontend/node_modules`.
- Install: `cd frontend && npm ci` (lockfile is `package-lock.json`). esbuild's postinstall is sandbox-blocked but the converter uses its own staged esbuild, so this doesn't matter.

## Styling model
- MUI is **CSS-in-JS (emotion)** — styles inject at runtime via `SberThemeProvider`. Expect `[CSS_RUNTIME]` from validate (non-blocking, no static stylesheet). `cfg.provider` = `SberThemeProvider` so every preview renders themed.

## Re-sync risks
- `frontend/design-kit/theme.ts` is a hand-copy of the app theme in `src/main.tsx`. These can drift — on re-sync, diff them.
- Component list in `frontend/design-kit/index.ts` is curated from the components the app imports from `@mui/material`. If the app starts using new MUI components, add them to the re-export list.
- Fonts: theme requests `Inter` (then `SF Pro Text`/system fallbacks). The app does not ship Inter as a webfont — see the `[FONT_MISSING]` handling decision recorded below once known.
