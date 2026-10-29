# cyberwall: Build Guide (for you and your coding agents)

Build with **Codex** and **Hermes + Nemotron**, one small phase at a time, and let tests decide what is true. This guide tells you what to do yourself, what to hand to an agent, and how to check the result.

> Read `AGENTS.md` and `docs/ARCHITECTURE.md` first. Agents must be told to read them every session.

---

## 0. Setup (do this yourself, once)

### 0.1 Prerequisites
Python 3.11+, `uv`, Docker, git, a GitHub account, Codex CLI (install per OpenAI's docs), Hermes Agent (install per the official Hermes docs; pin the version you test against), and a model provider configured in Hermes for Nemotron (follow the Hermes docs guide *"Run Nemotron 3 Ultra free in Hermes Agent"*).

### 0.2 Two separate Hermes setups (important)
| Setup | Purpose | Rules |
|---|---|---|
| **Builder Hermes** | Helps you write code/docs | Separate Hermes profile or devcontainer. **Never enable the in-development cyberwall plugin here.** No real credentials. |
| **Lab Hermes** | The test subject for contract tests and the attack lab | Runs in Docker with a **pinned Hermes version**, synthetic files only, plugin enabled. |

Why: a half-built guard can lock up your builder, and a builder with real credentials is a prompt-injection target while it reads third-party content.

### 0.3 Who does what
| Agent | Best used for | Not for |
|---|---|---|
| **Codex** | Core engine, Hermes adapter, tests, fault injection (Phases 1, 2, 3, 5, 7) | Writing its own acceptance criteria |
| **Hermes + Nemotron** | Attack-corpus drafts, fixtures, docs, README polish, **independent review of Codex's diffs** (Phases 4 docs, 6, review passes) | Unreviewed changes to `core/` |
| **You** | Merging, owning the invariants, running the demo cold | Skipping the review prompt |

**Rule: the agent that wrote the code never approves it.** Codex writes → Hermes/Nemotron reviews (prompt in §3). Occasionally swap roles.

I can't tell you which model codes better for this. **Bake-off (optional, 1 evening):** give both the same Phase 1 prompt on separate branches, then compare passing tests, coverage and how many invariants each violated. Keep the better one for `core/`.

### 0.4 Repo and hygiene
```bash
mkdir cyberwall && cd cyberwall && git init
# copy README.md, AGENTS.md, assets/, docs/ from this kit into the repo
```
Protect `main` on GitHub, require CI, and work on branch-per-phase (`phase-1-core`). Review every diff yourself before merging. Pause and read any change that touches `core/`, `adapters/hermes/guard.py` or tests.

### 0.5 Project name
The project name is **cyberwall**. Use it consistently in source, docs, package metadata, and public submissions.

---

## 1. How to run each phase

Every phase is: **(1) paste the prompt → (2) agent works on a branch → (3) you run `make check` → (4) cross-review → (5) merge.** If a phase's exit criteria are not met, you do not start the next phase.

Common preamble for every prompt:

> Read `AGENTS.md` and `docs/ARCHITECTURE.md`. Work only on the phase below, on a new branch. Write failing tests first (positive, negative, benign twin). Never weaken a test. When finished, run `make check` and report: what changed, what could now be bypassed, what you did not test.

---

## 2. Phases

### Phase 0: Scaffold *(≈1 evening)*
**Goal:** a green, empty, strict skeleton.
**Tasks:** `pyproject.toml` (src layout), ruff, `mypy --strict` for `core`, pytest + hypothesis, pre-commit, `import-linter` contracts from ARCHITECTURE §4, `Makefile` (`setup`, `check`, `test`), GitHub Actions `ci.yml` (lint, types, tests, Python 3.11/3.12), `LICENSE` (Apache-2.0), `SECURITY.md` (private disclosure), `CONTRIBUTING.md` (the "every claim has a test" rule), `CODE_OF_CONDUCT.md`, empty package tree.
**Exit:** `make check` and CI green; import-linter fails if `core` imports anything forbidden (prove it by adding a deliberate violation, seeing red, removing it).

> **Prompt:** Do Phase 0 of `docs/BUILD_GUIDE.md`. Create the repo scaffold, tooling, Makefile and CI exactly as described. Add an import-linter contract set matching ARCHITECTURE §4 and a test demonstrating it catches a violation.

### Phase 1: Core engine *(the heart; spend the most time here)*
**Goal:** a pure, exhaustively tested decision function.
**Tasks:** frozen Pydantic models (`Request`, `Decision`, `Policy`, `SessionState`); strict policy loader (unknown keys are errors); normalizers for paths, hosts, argv (ARCHITECTURE §5); tool classifier; evaluator with the exact §5 order; `policy lint`; CLI `cyberwall eval` and `cyberwall policy lint`; JSON Schema generated from the models.
**Tests:** a golden decision table in YAML (hundreds of rows: request → decision, rule, reason); hypothesis properties (determinism, deny-overrides, default-deny, rule-order independence, normalization idempotence); fuzzing of path and host normalizers including `..`, symlinks, Unicode lookalikes, `ok.com@evil.com`, trailing dots, IPv6 literals, percent-encoding.
**Exit:** 100% branch coverage on `evaluator.py` and `normalize.py`; `mutmut` (or equivalent) run on the evaluator with every surviving mutant reviewed; a test proving `core` performs no I/O.

> **Prompt:** Do Phase 1. Implement `cyberwall/core` per ARCHITECTURE §5–7 as a pure function. Start from the golden decision table and property tests. Include adversarial normalization cases. Do not write any Hermes code yet.

### Phase 2: Evidence log
**Goal:** tamper-evident, redacted, concurrency-safe evidence.
**Tasks:** SQLite WAL store; hash chain; `evidence verify`; redaction by construction (store hashes and allowlisted fields only); `cyberwall report last|summary` (Markdown/JSON).
**Tests:** edit one row → `verify` fails; 8-thread writer test; **canary test**: plant a secret in prompt, args, result and path positions and assert it is absent from every byte of the DB; `on_evidence_failure` behaviour.
**Exit:** all green; report output matches the README format for a blocked call.

> **Prompt:** Do Phase 2. Implement `cyberwall/evidence` per ARCHITECTURE §12 with a canary-secret test and a tamper-detection test.

### Phase 3: Hermes guard *(the make-or-break phase)*
**3.0 Spike first, no feature code.** Install the pinned Hermes in Docker. Read its source and run experiments for every item in ARCHITECTURE §8.2. Write `docs/hermes-contract.md` with findings, versions and evidence (command + output). **Stop and show me** if anything contradicts ARCHITECTURE §8.1.
**3.1** Plugin skeleton loads (`plugin.yaml`, `__init__.py`, `register(ctx)`); visible in `hermes plugins list`; directory install **and** entry-point install both work.
**3.2** `pre_tool_call` guard: build the request, call `decide`, return `{"action":"block","message":...}` on DENY/APPROVAL; wrap the *entire* hook in a catch-all that **blocks** in enforce mode.
**3.3** `post_tool_call` → evidence outcome; `transform_tool_result` → taint + redaction hook (taint rules land in Phase 5).
**3.4** Slash command `/cyberwall status` and `approve` (only if spike item 3 allows), CLI `hermes cyberwall …`, plus `cyberwall doctor` and `cyberwall run` (refuses to start Hermes unless the guard is verified loaded).
**3.5** Contract tests (`make contract`, Docker, pinned Hermes): blocked call **never reaches the handler** on the registry path and the agent-loop path; parallel calls; hook raising → blocked; plugin load failure → `doctor` fails; audit mode never blocks.
**3.6** `docs/coverage-matrix.md`: every execution path marked covered / partial / unsupported.
**Exit:** FR-06, FR-07, FR-13, FR-14, FR-15 green. Do not proceed on a "mostly works".

> **Prompt (spike):** Do Phase 3.0 only. Do not write plugin code. Produce `docs/hermes-contract.md` answering every question in ARCHITECTURE §8.2 with reproducible evidence, and list anything that contradicts §8.1.
> **Prompt (build):** Do Phase 3.1–3.6 using `docs/hermes-contract.md` as the source of truth. The guard must fail closed on any exception. Contract tests must prove the tool handler is never invoked for blocked calls.

### Phase 4: Inventory and drift
**Goal:** know what tools exist and notice when they change.
**Tasks:** snapshot tool registry (name, description, schema hash, source/toolset), MCP server config, plugin and skill list; `cyberwall inventory`; `baseline approve|diff`; drift check at session start and on registry change; drift → REQUIRE_APPROVAL or DENY per policy; classification suggestions (read/write/exec/network) for unclassified tools.
**Tests:** known-good vs modified manifests; description-only change detected; schema change detected; new tool detected; benign reorder is *not* drift.
**Exit:** FR-09 green; `baseline diff` output readable by a non-expert.

> **Prompt:** Do Phase 4 per ARCHITECTURE §13 T-02/T-03. Hash canonicalized name+description+schema. Drift must fail toward restriction.

### Phase 5: Flow control (the differentiator)
**Tasks:** session taint state (thread-safe); taint setters in `transform_tool_result`; high-precision secret detectors (private-key headers, cloud key IDs only, no fuzzy matching); trifecta rule; memory-write rule; taint inheritance for subagents if the spike shows it's possible.
**Tests:** taint only ever *adds* restriction (property test); detector false-positive corpus (benign text full of the word "password" must not taint); race test with parallel calls; clear on `/new`.
**Exit:** FR-10 green in the lab (below).

> **Prompt:** Do Phase 5 per ARCHITECTURE §7. Detectors may only add restrictions. Include a false-positive corpus.

### Phase 6: Attack lab
**Tasks:** compromised-model simulator (local OpenAI-compatible endpoint returning scripted tool calls); case runner; **Tier A** corpus for every row in ARCHITECTURE §13 (T-01…T-12) plus benign twins; Markdown/JSON report; `make lab`; CI job; optional Tier B runner (N trials, reports attempt rate). Map cases to OWASP's current agentic categories by looking up the published list.
**Assertions:** verdict, rule, **and handler-not-invoked**.
**Exit:** all Tier A pass with twins; a deliberately weakened policy makes specific cases fail (proves the lab can detect failure).

> **Prompt (Hermes + Nemotron is a good fit):** Do Phase 6. Draft the Tier A corpus and fixtures from ARCHITECTURE §13–14 using synthetic data and reserved `.invalid` hosts only. No real malware, no third-party targets. Every case needs a benign twin.
> **Prompt (Codex):** Implement the simulator and runner. Include a "mutation" test that weakens the policy and expects named failures.

### Phase 7: Hardening and release
**Tasks:** self-protection test suite (agent tries to edit config, plugin, policy, evidence, approvals; call `cyberwall` via terminal); fault-injection suite; decision-latency benchmark; `contained` reference `docker-compose` with a test proving a denied host is unreachable *at the network level*; security review of the whole repo with the review prompt (§3), run by the other agent; docs sweep (every limit stated); **record the real demo** (asciinema/GIF) and replace the README's *design target* blocks with real output; remove the pre-alpha warning only if the release gate passes.
**Exit:** release gate in ARCHITECTURE §16. Tag `v0.1.0`.

> **Prompt:** Do Phase 7. Write the self-protection and fault-injection suites first. Then the contained-profile compose file and network-level test. Do not claim anything in docs that lacks a passing test.

---

## 3. Cross-review prompt (use after every phase, with the *other* agent)

> You are a hostile security reviewer. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, then the diff of branch `<branch>`. Do **not** praise. Find: (1) any path where an error, missing field or unknown input yields ALLOW; (2) any exception that could escape a Hermes hook; (3) I/O, network, clock or randomness in `core`; (4) raw payload or secret reaching logs or evidence; (5) any way the agent could change its policy, plugin, evidence or approvals; (6) any way a model-reachable call could create or consume an approval; (7) tests that assert nothing, are skipped, or were weakened; (8) claims in docs without a test. For each finding give: file:line, how an attacker exploits it, and a failing test that proves it. End with a list of things you could not verify.

Turn each valid finding into a regression test **before** the fix.

---

## 4. Is it built right? (self-check scorecard)

Answer honestly. Any "no" means you are not done.

1. Does a blocked call provably never reach the tool handler, on every covered path?
2. If the guard throws, does the tool stay blocked in enforce mode?
3. Does `doctor` fail loudly when the plugin isn't loaded?
4. Can you list every path cyberwall does **not** cover?
5. Can the agent edit, disable or approve around its own guard? (You tried. It failed.)
6. Does the attack lab fail when you weaken the policy?
7. Does every attack case have a benign twin, and do the twins pass?
8. Is there any LLM, network call or raw payload in the decision path or the logs?
9. Can a stranger reproduce your demo from a clean clone in under 15 minutes?
10. Does the README say what it *can't* do as clearly as what it can?

## 5. Release and launch (no company needed)

- Tag `v0.1.0`; publish to PyPI; GitHub release with the recorded demo.
- Write one honest post: *"A deterministic guard for Hermes: what it blocks, and what it can't."* Lead with the limits and the failing-then-fixed bypasses.
- Share in the Hermes community and with AI-security practitioners; ask people to **break it**. Credit reporters; turn every bypass into a test.
- Add `good first issue` labels for new attack cases. They are the easiest high-value contribution.
- Wait for real usage before building a broker, dashboard or anything commercial.

## 6. Mistakes to avoid

- Building the dashboard, broker or "AI risk score" before Phase 3 exit criteria pass.
- Trusting any API detail in these docs over what you observe in the installed Hermes.
- Letting an agent mark its own work "secure".
- Demos using a model that "refuses". Use the compromised-model simulator.
- Treating the plugin as a sandbox. The contained profile is the real boundary.
