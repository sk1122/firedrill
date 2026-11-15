# firedrill.satyam.fyi

The public landing page for Firedrill. Plain files with no build step: `index.html`, `style.css`, `copy.js`, the self-hosted fonts in `fonts/` (SIL Open Font License, licences alongside), `404.html`, and `_headers` for the security and cache headers.

Preview it locally:

```bash
python3 -m http.server -d site
```

Then open http://localhost:8000. `_headers` is only applied by Cloudflare Pages, not by the local server.

It deploys to Cloudflare Pages with `site` as the build output directory and no build command. The page loads nothing from other hosts, so the Content-Security-Policy in `_headers` allows `'self'` only. Anything added from another host, or any inline script or style, needs that policy changed too.
