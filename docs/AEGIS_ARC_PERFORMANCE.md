# AEGIS-ARC | M1.1 execution-engine hardening

This repository currently contains the **WhiteKnight M1 foundation** (37 rule definitions, report templates, policy enforcement and a Next.js skeleton). It is **not yet a deployed SOC agent or live scanner**. AEGIS-ARC is the proposed local-first defensive orchestration layer built on top of these foundations.

## Scope of this increment

- Bounded checker concurrency: `maxConcurrency=1..8`, with backward-compatible default of 1.
- Deterministic results: merge by configured checker order, not asynchronous completion order.
- Cancellation safety: discard findings delivered after the caller aborts.
- Per-checker telemetry: status, elapsed milliseconds, findings and errors. No raw evidence or secrets in metrics.
- Fault isolation: one checker failure cannot prevent the remaining checkers from returning their results.

## Operational gates before production

1. **M2: Functional scanning.** Implement read-only GitHub App ingestion with explicit repository ownership/permission verification; local-only demo first. Do not perform scanning against arbitrary hosts. Confirm findings against synthetic fixtures.
2. **M3: Durable jobs.** Idempotent queue, bounded retries, deadlines, result sizes, backpressure and multi-tenant isolation. Never enqueue scans without current ownership verification.
3. **M4: Local LLM analysis.** Optional local model with evidence-based summaries and strict input/output validation. AI never has unrestricted shell or outbound network tools.
4. **M5: Human-approved responses.** Allowlisted response proposals, dry-run by default, explicit authority and scope validation, approval record, rollback plan. No retaliatory activity or scans outside authorized scope.
5. **M6: Observability and trials.** Latency percentiles (p50/p95/p99), throughput, memory usage, failure and false-positive rates; run staging tests before any production claim.

## Initial performance acceptance criteria (targets, not measured results)

- Concurrency must not exceed configured cap; existing sequential behavior at default settings must be preserved.
- Same inputs must lead to the same fingerprints and ordering regardless of checker completion order.
- Cancelled scans must not publish findings obtained after cancellation.
- Errors must be isolated and visible, and telemetry must omit raw secrets.
- Measure a realistic owned-repository workload before setting numeric performance targets or claiming speedups.

## Running tests

```bash
pnpm install --frozen-lockfile
pnpm --filter @whiteknight/core test
pnpm check
```

**Security boundary:** This increment does not authorize active network reconnaissance, exploitation, lateral movement, or retaliation. External AI stays off by default per the existing policy.
