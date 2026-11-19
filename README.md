# AurevoDB — website

Commercial product website for **AurevoDB** — real-time damage-aware detection
and graded containment of ransomware attacks on MongoDB, in an isolated lab.

Built for Ashraful Islam Shaon's DIU final-year project
("Real-Time Damage-Aware Detection and Graded Containment of Ransomware Attacks
on MongoDB in an Isolated Lab").

## What is here

- `index.html` — single-page site: hero, how it works, Live Lab, v6 results,
  honest limits, docs, footer.
- `styles.css` — Vercel-style black/white design, True Blue `#2C92E5` and
  Magenta Pink `#ED1F9E` accents on Galactic Blue `#04183B`.
- `lab.js` — the Live Lab. A working in-browser simulation of the AurevoDB
  algorithm: pick an attack shape, run it against the simulated seeded shop
  database (26,500 docs), watch the damage score build with the real formula
  (0.35 destructive-command rate + 0.25 collection churn + 0.25 data volume
  at risk + 0.15 command rarity), and see graded actions fire at 30 / 60 / 85.

## The Live Lab is a simulation, not a live server

It runs the AurevoDB scoring and containment logic in your browser against
simulated events, calibrated so its outcomes match the v6 lab evaluation
(medians: fast drop 71.92%, fast delete 54.08%, slow 68.00%, sustained 60.00%,
interleaved 32.60%, dropdb 0% by design). The real system is the Python +
MongoDB lab in the `aurevodb` project (not included here). The page says so.

## Run locally

```sh
python3 -m http.server 8000
# open http://localhost:8000
```

No build step, no framework, no dependencies.

## Headless self-test

```sh
node -e "const {simulate}=require('./lab.js'); for (const s of ['fast_drop','fast_delete','slow_delete','sustained','interleaved','dropdb']) console.log(s, simulate(s,'graded',1001).result.savedPct);"
```

Or open `index.html?autotest=1` — it runs all six shapes in both modes and
writes the results into `document.title` and a `#autotest` block.

## Deploy

Cloudflare Pages, project `aurevodb` (static, no build):

```sh
wrangler pages deploy . --project-name aurevodb
```

## Numbers on the page

All results are the real v6 evaluation numbers (see `evaluation/analysis_v6.json`
in the lab project). No invented prices, no pricing tiers — this is a research
product, not a store.
