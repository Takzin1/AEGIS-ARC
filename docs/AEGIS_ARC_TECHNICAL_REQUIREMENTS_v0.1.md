# AEGIS-ARC | Evidence-driven Technical Requirements v0.1

**Date:** 2026-11-08 JST  
**Status:** Design targets, NOT measured performance or deployment certification.  
**Repository baseline:** Existing WhiteKnight M1/M1.1 foundations: rule catalog (37 entries), rule-based Markdown reports, secure AI-externalization policy, bounded checker engine. Actual source scanning, log ingestion, LLM inference, response orchestration and production hosting are NOT implemented yet.

## 0. Product scope and non-goals

AEGIS-ARC is a local-first, human-governed cyber-defense operations assistant for systems its operators own or have explicitly been authorized to assess. The first release extends the existing GitHub-repository posture scanner. Subsequent releases add read-only event ingestion, evidence-grounded incident summaries, response proposals and human-approved defensive actions.

**Data plane:** owned-repository scan and read-only security telemetry → OCSF-normalized records → deterministic policy/Sigma/OSV/KEV checks → evidence index → optional local open-weight LLM summary → human review → audited, allowlisted response action.

**Trust boundary:** No active exploration of unverified hosts; no exploitation, credential testing, lateral movement, retaliation or automated destructive response. The language model never gets unrestricted shell/network capabilities. Logs, threat reports and source files are *untrusted data* and may contain prompt-injection strings.

## 1. Performance SLOs (initial targets; do not cite as achieved)

Testing environments must be recorded with CPU/GPU, RAM/VRAM, OS, runtime, model hash, quantization, warm/cold state, dataset snapshot and concurrency.

| Area | M2/Research acceptance target | Later pilot admission target | Workload & interpretation |
| --- | --- | --- | --- |
| Repository rule scan | p95 <= 120s | p95 <= 60s | 1,000 files / 50 MiB owned-source fixture; 4 vCPU / 8 GiB; excludes API outages and external model |
| Event ingest + normalization | >= 100 events/s sustained | >= 1,000 events/s sustained | 4 vCPU / 8 GiB; replay synthetic OCSF-mappable logs for 60 min |
| Loss/accounting | >= 99% accepted events | >= 99.9% | Count every dropped/dead-lettered event; never silently skip |
| Ingest -> rule verdict | p95 <= 10s | p95 <= 5s | End-to-end under documented event rate; not a universal SLA |
| Local LLM investigation summary | p95 <= 30s | p95 <= 15s | 512 input / 128 output tokens, warm model, single request, benchmark machine >=16 GiB VRAM for larger candidates |
| Known scenario recall | >= 0.90 | >= 0.95 | Gold labels for *specified* held-out attacks; by technique family |
| Precision | >= 0.90 | >= 0.98 | Event/case-level precision; report alert volume per host-day separately |
| Evidence-grounded statements | >= 0.95 | >= 0.99 | Independently label every factual model assertion as supported/unsupported |
| Structured-output validity | >= 0.99 | >= 0.999 | JSON schema-valid decisions and citations over fixed evaluation cases |
| Unauthorized/dangerous response actions | 0 in tests | 0 in tests | Deterministic policy blocks, not a guarantee of zero lifetime risk |
| Audit persistence | 100% in tests | 100% in tests | Each proposed/approved/rejected/executed action has actor, source, timestamp, outcome |
| Third-party data freshness | daily refresh check | source-specific SLA | Record version, retrievedAt, source URL, digest, license and processing status |

Report p50/p95/p99, confidence intervals, throughput vs latency, CPU/GPU use, peak RAM/VRAM, timeout rate, per-tenant fairness, false alarms per host-day and operational cost. Latency must be segmented: ingestion, normalization, rules, retrieval, inference and human approval. Do not equate rule-catalog size to implemented detection coverage.

**Hard gate:** deploy read-only and offline evaluation before enabling any action; automatic isolations/deletions/config writes are not part of MVP.

## 2. Open-weight model shortlist (model selection is pending bench results)

- **Qwen/Qwen3.5-9B** (Apache-2.0): primary candidate for Japanese incident report generation, evidence-grounded triage and ATT&CK mapping. https://huggingface.co/Qwen/Qwen3.5-9B
- **ibm-granite/granite-4.0-micro** (Apache-2.0): small candidate for extraction and inexpensive routing. https://huggingface.co/ibm-granite/granite-4.0-micro
- **openai/gpt-oss-20b** (Apache-2.0, subject to usage policy): candidate for difficult cases, structured reasoning and latency/quality comparator. https://huggingface.co/openai/gpt-oss-20b
- **Qwen/Qwen3.5-4B** (Apache-2.0): constrained-hardware baseline. https://huggingface.co/Qwen/Qwen3.5-4B

**Working hypothesis:** deterministic rules first; Micro-class model for low-risk filtering/structuring if empirically validated; Qwen3.5-9B for evidence-based explanation; send uncertain cases to people, not to higher-privilege automatic agents. Compare also to **rules-only / no-LLM** baseline.

Benchmark each on the identical frozen test bundle, frozen prompts, identical retrieval index and hardware. Capture exact HF revision digest, inference runtime and quantization. Do not assume model general benchmarks or parameter count predict SOC performance.

Candidate scorecard: (1) false-negative-sensitive recall by class, (2) precision and false alarms, (3) attribution fidelity (source ID, event ID, timestamp, original text span), (4) unsupported-action rate, (5) JSON schema conformance, (6) prompt-injection resistance, (7) p95 + memory + cost. Any unauthorized action attempt or policy bypass fails regardless of aggregate quality score.

**Scope of AI mode:** Existing `WHITEKNIGHT_AI_HARD_DISABLE` stops outbound AI usage, but local inference requires its own explicit `local_enabled`, model registry, runtime network egress restriction, and audit fields. Do not silently equate external-AI off with approval for local inference.

## 3. Data and reference architecture

Consult `docs/AEGIS_ARC_SOURCE_REGISTRY.json` for machine-readable provenance. Broad rules:

1. OCSF normalization is a mapping, not proof of correctness; keep raw-event hash and raw-to-OCSF field lineage, with sensitive values masked in exported records.
2. MITRE ATT&CK STIX 2.1 **Enterprise v20.1 (2026-11-05)** is the initial taxonomy snapshot. Pin a downloaded release and hash; treat identifiers as references, not detection claims.
3. Sigma supplies candidate rules: license DRL 1.1 **requires author credit also when presenting match results**. Preserve author, source rule ID and license in UI and exports.
4. CISA KEV = prioritization of known exploited CVEs; OSV = package version and commit vulnerability matching. Normalize CVE/GHSA/OSV IDs; deduplicate and trace evidence.
5. D3FEND maps defensive techniques to possible mitigations; never interprets a mapping as permission to execute an action.
6. For evaluation: OTRF Security-Datasets is first choice for log-based replay; CyberSOCEval for LLM threat intel; CSE-CIC-IDS2018 for network-flow robustness; UNSW-NB15 restricted to academic research unless separate commercial permission is obtained.

All incoming external data must record: `source_uri`, `retrieved_at_utc`, `source_version`, `license_id`, `sha256`, `content_type`, `parser_version`, `confidence`, `evidence_refs`. External datasets must NOT be committed whole to this public repo by default. Use manifests plus stable upstream links; quarantine and validate untrusted imports.

### Evaluation data protocol

- Start with 200-300 expert-labeled **cases**, mixing confirmed malicious, benign, ambiguous, incomplete and deliberately adversarial-input cases. Record separate event-level benchmarks and case-level benchmarks.
- Split by **time, campaign and source entity/host**. Train-only normalization; independent labels; never leak a case across train/validation/test via shared artifacts. Hold out at least one attack family and at least one dataset for transfer testing.
- Keep official test sets held out, no tuning on the test; evaluate at >=3 seeds when the training process is stochastic.
- Report per-technique recall and macro-F1 (not only aggregate accuracy), error cost, CIs and a confusion matrix. Include detection latency and response work needed by analysts.
- Use no LLM to label its own test answers. Analyst review and disagreement adjudication required. Preserve reference rationale and event IDs.
- Adversarial tests: forged instructions in log lines, hostile repository comments, untrusted threat report markdown, simulated tool-output injection, malicious links, missing timestamps and conflicting CTI. Expected behavior: ignore instructions in evidence, abstain, cite source, require human approval.

### Evidence-output contract (proposed)

```json
{
  "case_id": "case-...",
  "verdict": "malicious|benign|uncertain",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0,
  "attack_technique_ids": ["Txxxx"],
  "evidence_refs": [{"event_id":"evt-1","source_hash":"sha256:..."}],
  "alternative_hypotheses": [],
  "next_steps": [{"action_type":"investigate","requires_approval":true}],
  "model_id": "provider/model@revision",
  "rule_catalog_version": "..."
}
```

Confidence must be empirically calibrated; an LLM-generated decimal is not a reliable probability. `uncertain` should trigger triage instead of fabricated certainty.

## 4. Research literature => engineering decisions

| Research | Finding relevant to AEGIS-ARC | Design test |
| --- | --- | --- |
| Chona et al., Cyber Defense Benchmark (2026), https://arxiv.org/abs/2604.19533 | Open-ended agentic threat hunting remains hard even for frontier models | Rule-first baseline and bounded, auditable retrieval |
| Deason et al., CyberSOCEval (2025), https://arxiv.org/abs/2509.20166 | Domain-specific malware/CTI reasoning remains difficult for LLMs | Separate task-specific evaluation for malware vs CTI |
| Saju & Azim, Toward Autonomous SOC Operations (2026), https://proceedings.mlr.press/v318/saju26a.html | Schema-constrained queries, evidence retrieval, RAG and resolutions matter | Structured queries and evidence citations |
| A leakage-free benchmark of offline policy learning for SOC alert triage (2026), https://www.sciencedirect.com/science/article/pii/S2666827026001490 | Temporal leakage and mean-only reporting create misleading results | Temporal holdout, stability metrics and cost-aware reports |
| Berhili et al., How evaluation protocol choices inflate intrusion detection accuracy (2026), https://doi.org/10.1016/j.cose.2026.105218 | Split protocols can strongly inflate IDS scores | Official held-out test and leakage audit |
| Moczkodan & Ragab, Do Transformers Actually Help Intrusion Detection? (2026), https://arxiv.org/abs/2606.11098 | False alarm rates can change substantially under leakage-free evaluation | Report per-host false alarms and distribution-shift tests |
| NIST SP 800-61 Rev. 3 (2025), https://csrc.nist.gov/pubs/sp/800/61/r3/final | Incident response must support preparation, detection, response, recovery | Evidence, ownership, approvals, rollback and review |

**Important:** Dataset/task-specific reported scores in those papers are not transferable performance guarantees for this product.

## 5. Conference agenda signals (ideas/hypotheses; NOT peer-reviewed evidence)

- FIRST 2026 program https://www.first.org/conference/2026/program
  - *From Logs to Living Timelines: AI-Assisted Incident Response in Hybrid Cloud Using OCSF* → Timeline correlation and event provenance.
  - *Can a General-Purpose LLM Do Tier-1 Triage?* → Compare open-model triage against a human-annotated rules-only baseline.
  - *One Poisoned Artifact Can Steer Your AI: How Robust Are Your LLM-Assisted Security Workflows?* → Prompt-injection tests on evidence.
  - *The Dark Side of Autonomy: Exploiting DFIR Agents Through Adversarial Manipulation* → Tool permission separation and action allowlists.
  - *Arcana: A Unified Framework for Incident Response Documentation and Knowledge Management* → Case trace and incident handoff.
- USENIX Security 2026 accepted papers https://www.usenix.org/conference/usenixsecurity26/session/usenix-security-cycle-1-accepted-papers
  - *When AIOps Become "AI Oops": Subverting LLM-driven IT Operations via Telemetry Manipulation* → Do not trust telemetry instructions.
  - *vCause: Efficient and Verifiable Causality Analysis for Cloud-based Endpoint Auditing* → Prioritize verifiable causality over opaque summaries.

## 6. Roadmap with gates

- **M2a: Offline, owned-repository scanner**: Implement 5-8 high-value read-only checks; secret-safe fixtures; rule IDs and finding fingerprints, report end-to-end. No web host scanning without verification.
- **M2b: OCSF replay harness**: Parser + queue + strict schema + bounded memory + counters and dead-letter; run 1-hour workload.
- **M3: Versioned reference data**: ATT&CK/KEV/OSV/Sigma/D3FEND manifests, license metadata, citations; pin snapshots/digests.
- **M4: Local-model evaluation**: compare four models + no-model baseline, measure recall/precision/grounding/latency/injection-resistance.
- **M5: Human-in-the-loop response proposals**: read-only actions initially; explicit authority checks and idempotent audit/rollback planning.
- **M6: Pilot on explicitly authorized assets**: multi-tenant isolation, continuous performance recording, incident recovery exercise and user-acceptance tests.

**Acceptance process:** reproducible benchmark scripts + immutable manifest + CI tests + reviewed security and license checklist before any production declaration.
