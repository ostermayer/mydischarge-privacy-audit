# mydischarge-privacy-audit

Synthetic test suites, test harness, and raw evaluation results for the MyDischarge privacy evaluation.

## Overview

MyDischarge is a patient-facing mobile application that performs on-device optical character recognition (OCR) and protected health information (PHI) redaction on emergency department discharge paperwork before forwarding de-identified text to a third-party LLM for plain-language summarization. This repository contains the code and data used to empirically validate the privacy-preserving pipeline described in the accompanying manuscript.

## Contents

- `src/` — privacy-critical modules under test. These are copies of the modules that run in the production MyDischarge application and proxy server:
  - `redact.js` — on-device PHI redactor (multilingual label-based regex + name propagation + context-aware and pattern-only fallbacks).
  - `sanitize.js` — server-side prompt-injection filter.
  - `scrub.js` — server-side named entity recognition backstop (compromise NLP library).
- `harness/` — evaluation scripts:
  - `generate_corpus.js` — generates the 440-document structured test suite across 15 languages.
  - `generate_stress.js` — generates the 60-document purposefully abnormal test suite across six failure modes.
  - `eval_redaction.js` — runs `redact.js` against the structured test suite and computes per-class and per-language recall.
  - `eval_egress.js` — runs the full production pipeline (client redactor → server sanitizer → server NER) against the structured test suite and records leakage at each stage.
  - `eval_stress.js` — runs the full production pipeline against the purposefully abnormal test suite and records per-category leakage.
  - `summarize.js` — aggregates the three evaluations into `results/summary.json`.
  - `phi_pool.js`, `templates.js` — PHI value pools, label patterns, and template layouts used by the generators.
- `corpus/` — generated synthetic test suites:
  - `docs/` and `truth/` — the 440-document structured test suite and per-document ground-truth JSON.
  - `stress/` — the 60-document purposefully abnormal test suite organized by failure-mode category.
  - `manifest.json` — document-to-canary mapping.
- `results/` — raw evaluation output (JSON and CSV) used for the manuscript tables.
- `figures/` — data-flow figure (SVG source and rendered PNG).

## Reproducing the results

```
npm install          # repository root — installs the NER dependency src/scrub.js loads
cd harness
npm install
npm run all
```

`npm run all` regenerates both test suites, runs all three evaluations, and writes aggregate output to `results/summary.json`. End-to-end runtime is under one minute. No external services are contacted; all evaluation runs locally.

## Revision history

- **2026-08-24** — `src/` refreshed to the hardened production revision:
  Unicode-aware name boundaries in `redact.js` and `scrub.js` (ASCII `\b`
  missed accented names such as "José"), `LAST, FIRST` labeled-name capture,
  digit-required MRN values, medication-line preservation in the address
  passes, and RFC-bounded email/identifier scans that remove an O(n²)
  worst case. A root `package.json` was added so `src/scrub.js` resolves its
  NER dependency from a fresh clone (the stress and egress evaluations
  previously failed with `MODULE_NOT_FOUND` on a clean checkout), and
  `npm run all` now includes the stress suite. All results were regenerated
  with identical headline numbers: 4,400/4,400 structured and 530/530 stress
  PHI instances blocked, zero canary residue, zero egress leaks.
- **2026-04-19** — initial publication accompanying the manuscript.

## Canary-token methodology

Every PHI field in every synthetic document contains a unique 7-character canary string (for example, `ZQK0042`) embedded inside its value (patient name `Octavio Mogensen-ZQK0042`, medical record number `MRNZQK0042`, email `canary-zqk0042@example.invalid`). The `ZQK` prefix is unlikely to appear in real clinical text, so a simple string search over the outbound network payload is a specific and sensitive leak detector. For PHI classes where the canary cannot be substring-embedded without breaking the field format (SSN, phone, age), values are drawn from reserved or invalid ranges (900-series SSNs, the `555-01` phone prefix, and the `.invalid` top-level domain from RFC 2606). No real personal data is used.

## License

MIT. See `LICENSE`.

## Citation

If you use this harness, please cite the accompanying manuscript.
