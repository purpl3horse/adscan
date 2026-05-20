# BACKLOG.md — ADscan roadmap & deferred work

Centralized list of ideas, deferred features, follow-ups, and design
decisions not yet scheduled into a PR. This file is the **single source
of truth** for "what did we decide but not build yet, and why".

## Lifecycle

Each entry graduates OUT of this file when:

- **Implemented** — delete the entry; the commit message references it
  ("closes BACKLOG § Plausibility Tier 3").
- **Promoted to a full spec** — when an entry grows past ~10 lines or
  needs architecture work, move the body to
  `docs/superpowers/specs/YYYY-MM-DD-<topic>.md` and leave a one-line
  pointer here.
- **Rejected after discussion** — move to `## Validated decisions` with
  the rationale and date. Never delete a rejection silently; future
  agents need to see why an idea was discarded so the same proposal
  doesn't return on its own merits in 6 months.

## Conventions

- New entries: append at the top of the relevant section. Most recent
  first.
- Each entry follows the same skeleton:
  - **Status** — one of: `deferred`, `customer-pull required`,
    `blocked on <X>`, `spike needed`, `ready to schedule`.
  - **Trigger to revisit** — the concrete condition that would
    promote this to active work. "Someday" is not a trigger.
  - **Why** — 1–2 lines on the value and the cost.
  - **Links** — paths to related code, specs, or prior incidents.
- Maximum entry length: ~10 lines. Promote to `docs/superpowers/specs/`
  if it grows beyond that.
- No personal opinions without evidence. "Customer X asked for this on
  YYYY-MM-DD" beats "I think this would be useful".

---

# Roadmap — bug fixes

## Share-spidering output path is CWD-relative, not workspace-relative

- **Status**: ready to schedule, **leak-vector severity**
- **Trigger to revisit**: do this before the next public release that touches
  share-spidering UX, or sooner if any operator reports finding
  customer credentials accidentally in their repo / dev tree.
- **Why**: in `adscan_internal/cli/creds.py:5107-5117` the calls
  `save_credentials_to_files`, `save_aggregated_credential_review_reports`,
  and `save_aggregated_credential_review_indexes` default to
  `base_dir="smb/spidering"` — a CWD-relative path. When an operator runs
  ADscan dev from the repo root, **real customer credentials get written
  into the source tree**, where they can leak via accidental
  `git add .` or via `scripts/sync_public_repo.sh` if `.gitignore`
  protection is missing. Discovered 2026-05-20 after 4 synthetic
  review artefacts shipped into the public mirror with absolute
  `/home/<user>/` paths embedded. Immediate mitigation:
  `smb/spidering/` is now gitignored and untracked.
- **Fix**: route the default to the active workspace, e.g.
  `Path(get_adscan_home()) / "workspaces" / domain / "spidering"`.
  Keep the parameter overridable for tests. Add a unit test that
  asserts the default path is workspace-resolved, not CWD-relative.
- **Out of scope**: changing the directory NAME — call it
  `spidering/` inside the workspace, identical to today's UX.
- **Links**: `adscan_internal/cli/creds.py:5107` (call sites),
  `adscan_internal/cli/creds.py:4639` (`save_credentials_to_files`
  signature), `.gitignore` (mitigation in place).

---

# Roadmap — PRO tier

## Plausibility Phase 2 — verdict telemetry & operator-override capture

- **Status**: ready to schedule
- **Trigger to revisit**: implement before the first PRO release that
  ships outside of the current engagement set; the corpus it builds
  is the prerequisite for any Tier 3 model selection.
- **Why**: today we have no labelled negatives that match our real
  deployment distribution (multilingual share scans, customer prose).
  Without that corpus, *any* Tier 3 model — DeepPass2, a fresh
  rockyou-trained classifier, an LLM — is a blind pick. Logging
  every verdict (value, category, reason, source rule, context line)
  plus every operator override (`--include-implausible` that later
  yields a successful spray = "TP we wrongly rejected") builds the
  corpus organically over 3–6 months of real engagements without any
  manual labelling cost.
- **Out of scope**: ML training, model selection, plug-in
  implementation. Telemetry only.
- **Links**: `adscan_internal/services/password_plausibility.py`
  (architectural hook already shipped — see Tier 3 entry below).

## Plausibility Tier 3 — semantic-aware classifier (BERT-class)

- **Status**: deferred, customer-pull required; **architectural hook
  shipped** (`register_advanced_plausibility_hook` in
  `adscan_internal/services/password_plausibility.py`). Plug-in
  consumers attach without touching call sites.
- **Trigger to revisit**: first PRO customer requests stricter triage
  than Tier 1+2 provides, OR observed FP rate on multilang scans
  exceeds ~5% after Phase 2 corpus collection has run for ≥3 months.
- **Why**: catches semantic FPs (technical-looking strings that pass
  hard rejects but a human would recognise as non-passwords) that the
  deterministic Tier 1+2 layers cannot reach. Cost depends on the
  integration path chosen below.

### DeepPass2 integration paths (evaluated 2026-05-20)

Three concrete paths exist for integrating the SpecterOps DeepPass2
work as the Tier 3 implementation. The choice depends on customer
pull and Phase 2 corpus signal; all three attach through the same
`AdvancedPlausibilityHook` interface, so the picking can wait.

| Path | What | Effort | Footprint | Tradeoffs |
|---|---|---|---|---|
| **1 — Reference only** | Use DeepPass2 paper + code as architectural reference; train / fine-tune our own xlm-RoBERTa head on the Phase 2 corpus. | 4–8 weeks once corpus is ready. | ~270 MB INT8 model in PRO container. | Owns the model end-to-end; no upstream gating; can iterate freely. Requires the Phase 2 corpus to exist. |
| **2 — Vendor the BERT layer** | Strip Flask + LLM stage from DeepPass2; vendor only `utils/BERTprocessor.py` + the fine-tuned xlm-RoBERTa weights; quantise to INT8 with ctranslate2. | 1–2 weeks once HuggingFace model access is granted by the author (`gneeraj/deeppass2-bert` is a gated repo). | ~270 MB INT8 model + ~400 MB torch / ctranslate2 deps in PRO container. | Reuses upstream fine-tuning; faster to ship. Depends on author granting model access; their fine-tuning distribution may not match ours. |
| **3 — Sidecar microservice** | Run DeepPass2 as-is (Flask) in an adjacent container; PRO container calls it via HTTP. | Days, but ongoing operational complexity. | Two containers; HTTP roundtrip ~10 ms per candidate. | Zero modification to upstream; easy to pilot with a single customer. Adds orchestration; HTTP latency adds up on large scans. |

- **Default recommendation if a customer says "yes" tomorrow**:
  Path 2 (vendor the BERT layer). Smallest delta to current build,
  preserves DeepPass2's multilingual fine-tuning, no external
  service dependency. Re-evaluate against Path 1 once Phase 2
  corpus is collected.
- **Why not Path 3 by default**: the Flask + LiteLLM dependency
  surface in upstream is a moving target outside our control, and
  the LLM judge stage requires an OpenAI-compatible endpoint which
  we cannot guarantee in air-gapped customer environments.
- **Links**: `adscan_internal/services/password_plausibility.py`
  (hook surface); `reference/DeepPass2/` (upstream code, gitignored);
  external blog [DeepPass2 announcement](https://specterops.io/blog/2025/07/31/whats-your-secret-secret-scanning-by-deeppass2/);
  gated model [`gneeraj/deeppass2-bert`](https://huggingface.co/gneeraj/deeppass2-bert).

---

# Roadmap — ENTERPRISE tier

## Plausibility Tier 4 — Local LLM via Ollama

- **Status**: deferred, customer-pull required
- **Trigger to revisit**: an enterprise customer with air-gapped LLM
  infrastructure (Ollama, llama.cpp, vLLM) asks for narrative-aware
  triage, AND we have a reproducible benchmark showing it beats
  Tier 3 on a representative corpus.
- **Why**: contextual judgement (e.g. "is this the password the user
  is referencing or the noun they're describing?") at the cost of
  determinism loss, 1–3 s latency per candidate, and an external
  dependency that complicates OPSEC. Never network-LLM; local only.
- **Links**: `adscan_internal/services/password_plausibility.py`
  (Tier 4 marker in module docstring).

---

# Validated decisions (do NOT reopen without new data)

## 2026-05-20 — zxcvbn / Hunspell rejected for credential filtering

- **Proposed by**: external AI consultation as the "LITE tier" of a
  layered plausibility stack.
- **Decision**: rejected.
- **Rationale**: both tools answer the wrong question.
  - `zxcvbn` (Dropbox) scores password *strength* — it rejects
    `password`, `admin`, `letmein123` as low-entropy. But those are
    real TPs in pentest engagements (we have observed all three on
    customer domains). Adopting zxcvbn would convert real
    credentials into discarded noise, hurting recall.
  - `Hunspell` flags strings containing dictionary words.
    `Verano2024!`, `Madrid24$`, `north_haven$tier0` all contain
    real-word tokens that customers use as passwords. Hunspell would
    silently drop them.
- **What we did instead**: Tier 1 (regex value-capture exclusion of
  structural delimiters) + Tier 2 (deterministic hard-reject
  heuristics: length, printable, GUID, structural, hash, base64).
  Both layers reject only what is *provably* not a password, keeping
  recall maximal; the spray gate validates downstream.
- **Re-open only if**: a corpus emerges where Tier 1+2 + Tier 3 BERT
  is demonstrably insufficient AND zxcvbn/Hunspell can be shown to
  catch the residual FPs without dropping known-good TPs from the
  same corpus.
- **Links**: `adscan_internal/services/password_plausibility.py`;
  `tests/fixtures/credsweeper_multilang/noise_classes_mixed.txt`
  (the end-to-end pipeline test that pins the Puppy regression).
