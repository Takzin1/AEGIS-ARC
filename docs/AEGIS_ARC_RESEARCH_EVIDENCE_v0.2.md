# AEGIS-ARC — three open-access research inputs (2026-11-08)

**Purpose:** integrate the scientific methods of three user-supplied PDFs into reproducible tests, without copying third-party datasets, benchmark artifacts or non-licensed PDF files to the public repository.

**Status:** Paper summaries / synthetic scoring tests committed. Original benchmark data, model weights, paid APIs and real SOC logs have **not** been imported; no project-performance claim is made.

## 1. Saju & Azim (2026), *Toward Autonomous SOC Operations*

- **Source:** [PMLR 318 (2026)](https://proceedings.mlr.press/v318/saju26a.html). Uploaded copy SHA-256: `b149764d55f2a188145615d9c46ffb4d10fd98e54a944c12bc9d5f159c2ffdfd`.
- **Rights:** Paper states © authors, **CC BY 4.0**, except separately indicated material; attribution required. Data from production SIEM and ServiceNow is *not provided* by the PDF and must not be inferred to be open.
- **Evidence:** 20,000 SIEM entries (40% critical, 60% non-critical); best three-LLM voting ensemble accuracy **0.828**, false-positive rate **0.120**. SQM = Syntax Query Metadata: syntax allowlists + official SIEM documentation + metadata vector search of executable exemplar queries. Generated query BLEU **0.384**, ROUGE-L **0.731**, and **88% executed without modification** in evaluated QRadar/Google SecOps settings. SQM-grounded resolution accuracy up to **0.900** vs strongest ticket-text-only reference **0.783**. These are *paper-specific* figures and do not indicate AEGIS-ARC's performance.
- **Engineering decision:** introduce `query_proposal -> syntax/parser validation -> operator approval -> read-only execution`; evaluate executable correctness independently of lexical overlap. Preserve provenance for retrieval candidates and log/query results. Maintain separate detection, query, resolution and operational-latency scores.
- **Limitation:** the input data is not the published repo's training set. No reproductions of the paper's performance figures are possible from the PDF alone.

## 2. Chona, Kozlov & Kumar (2026), *Cyber Defense Benchmark*

- **Source:** [paper and benchmark entrypoint](https://github.com/simbianai/cyber_defense_benchmark). Uploaded copy SHA-256: `c7c9bb022cbe3553652045f10348dd57ac6d7dd138cce7a5d4e556f9a505b281`.
- **Rights:** The PDF does not specify an explicit reuse license. **Link and cite only; do not redistribute the PDF or upstream dataset in this repo until the applicable licenses are confirmed.**
- **Evidence:** 106 OTRF attacker procedures, 93 ATT&CK sub-techniques, 26 multi-step campaigns, typically **75,000–135,000** events per instance; up to 50 SQL queries, 10 rows/query, 75-turn safety cap. The abstract / section 1 reports strongest mean **Coverage Score 0.55 ± 0.05**, with no model passing the criterion of >=50% recall for **each** tactic (13 categories in the evaluation).
- **Definition matters:** Coverage Score is **per-instance fraction of coverable narrative steps for which at least one true malicious timestamp was submitted**, then averaged across instances. It is **NOT** event recall, multiple-choice accuracy, or query retrieval success. Track both correct flags **seen in queries** and correct flags **submitted** to expose evidence attribution failures.
- **Engineering decision:** use OTRF log replay and an allowlisted read-only query interface in an isolated environment, with fixed query budget, run seeds and the paper's distinction between evidence visibility and attribution. Test Windows telemetry limitations and performance under time shifting / entity obfuscation. Never execute generated SQL against production without review.
- **Caveat:** the paper mentions 12 tactics in the core corpus but adds Resource Development to the 13-category evaluation. It also describes non-deterministic LLM results and recommends repeated rollouts. Treat benchmark scores as paper claims, not deployment guarantees.

## 3. Deason et al. (2025), *CyberSOCEval*

- **Source:** [arXiv:2509.20166](https://arxiv.org/abs/2509.20166), version 2 (November 2025), and [CyberSOCEval data repository](https://github.com/CrowdStrike/CyberSOCEval_data). Uploaded copy SHA-256: `dc9c8dc1ff1716e0231fc70a781fdc33bea5c35707d886f5392b407df14868e0`.
- **Rights:** The PDF does not itself state an explicit redistribution license. Public availability does **not** imply permission to rehost the PDF, malware report images or dataset contents. Inspect official code and data licenses separately before any download/republication.
- **Evidence:** Two tasks: (a) **609** expert-checked multi-answer questions based on malware sandbox detonation reports, across five malware types; (b) **588** questions derived from **45** threat-intelligence reports, with images and multi-answer questions. Correctness is **exact-set accuracy** (every and only the correct options). The reported model malware-analysis accuracy is around **23%–34%** in the evaluated setting; do not confuse this with malicious-file detection rates.
- **Engineering decision:** evaluate open-weight models on separately versioned malware-analysis and CTI-reasoning tasks; require exact-set scoring and a clear abstention path for unsupported inferences. Version prompt templates and test fixtures. No malware execution or sample handling by default.

## Comparison: distinct denominators

| Task | Metric | Correct unit |
| --- | --- | --- |
| Binary SIEM critical-event classification | Recall, Precision, FPR, F1 | labeled event |
| SQM query synthesis | executable-without-modification rate | attempted query |
| SOC resolution code | macro-F1, accuracy | closed incident ticket |
| Agentic threat hunting | mean narrative step coverage; correct flags seen/submitted | campaign and coverable step |
| CyberSOCEval malware/CTI reasoning | exact-set multi-answer accuracy | question |
| Product inference | p50/p95/p99 latency, memory, cost, grounded assertions | request, event or host-day |

**No head-to-head winner can be inferred across these papers** because their tasks, populations and metrics differ.

## Implementation in this PR

- `packages/core/src/evaluation.ts`: pure, side-effect-free scorers for binary event labels, strict multi-answer questions, narrative-step hunt coverage, multiclass incident resolution and actual query executability outcomes.
- `packages/core/test/evaluation.test.ts`: synthetic edge-case tests, budget checks, duplicate-answer checks and exact sample calculations.
- `docs/AEGIS_ARC_PAPER_MANIFEST.json`: source metadata, PDF SHA-256 and license status; manifest only.
- **Not implemented:** SIEM connection; GitHub scan ingestion; OTRF data import; actual agent/model benchmarking; malicious sample execution; automated response.

## Next implementation: open-data replay, then open-weight local inference

1. Fetch authorized public OTRF/Sigma data *after checking source-level terms*. Pin immutable revisions and record hashes.
2. Parse synthetic Windows events into the project event schema; measure event throughput, loss and baseline rule quality.
3. Add offline benchmark adapters for paper-style scores, never mix their denominators.
4. Benchmark Qwen3.5-4B/9B, Granite 4.0 Micro, and gpt-oss-20b **only after** the rules-only baseline and deterministic dataset split are frozen.
5. Human-approved response actions, evidence citations and prompt-injection resistance testing are required before any production integration.
