# NYAVS — Not Your Average Vuln Scanner

**Supply-chain and CI/CD exposure assessment from day zero, before scanner definitions exist.**

**Homepage: [commandctrl.github.io/nyavs](https://commandctrl.github.io/nyavs/)**

NYAVS is a set of [Claude Code](https://claude.com/claude-code) skills that answer one question when a new vulnerability or supply-chain compromise is disclosed:

> **Are we actually exposed — and how do we know?**

Commercial vulnerability scanners detect what their vendor has written a plugin or signature for, and that usually takes days after disclosure. NYAVS doesn't wait for a vendor. It starts from the advisory itself (CVE, affected versions, IOCs) and checks your software supply chain directly:

- **Source and branches:** code-search union across code hosts, including non-default branches that CI builds
- **Dependencies:** lockfiles parsed for transitive packages that no manifest names
- **Build path:** artifact registries, and CI jobs that bypass them to pull from public registries
- **CI identities:** which secrets-manager and cloud roles a CI job can obtain, and whether any merge request can reach them
- **Runtime:** process telemetry showing which project's CI job or workload actually executed the code
- **Plus:** SBOMs, attack surface, scanner posture, and logs

For every null result, NYAVS states what that null does and does not prove.

## What it is not

- **Not a zero-day discovery tool.** NYAVS doesn't find unknown vulnerabilities. It needs a published advisory, CVE, or set of IOCs as input. Its edge is speed after disclosure: it gives a defensible exposure answer before scanners can detect the issue.
- **Not a claim of complete coverage.** Its own design assumes no organization has complete CI/CD visibility. Every report measures and lists its coverage gaps (sensors deployed on only some clusters, unindexed branches, bypassable registries) instead of hiding them behind a zero.
- **Not a scanner replacement.** Scanner posture is one of its inputs. NYAVS answers the question before scanners can and checks the supply-chain layers they don't look at.

## What it does

```
 advisory / URL / CVE IDs
          │
          ▼
 ┌──────────────────────┐   nyavs-intel-ingestor: CVEs, versions, IOCs, appendices,
 │ 1-2  Intelligence    │   nested sources (VirusTotal-gated), EPSS, KEV, exploit
 └──────────┬───────────┘   prerequisites
            ▼
 ┌──────────────────────┐   one sub-agent per CVE, in parallel:
 │ 3  Exposure checks   │   code-search union · branch coverage · dependency alerts ·
 │                      │   lockfile transitive parsing · artifact registry ·
 │                      │   CI identity blast radius · version mapping
 │                      │   then, in one SIEM session:
 │                      │   attack surface · SBOM · scanner posture · existing tickets ·
 │                      │   log pivot + raw drilldown · runtime execution assurance
 └──────────┬───────────┘
            ▼
 ┌──────────────────────┐
 │ 4  Prioritize        │   transparent rubric, EPSS reported separately
 │ 5  Handoff   (STOP)  │   ticket-ready finding package, dedup against existing tickets
 │ 6  Escalate  (STOP)  │   nyavs-escalation: formal / advisory / FYI
 │ 7  Report            │   markdown + self-contained HTML, receipts for every finding
 └──────────────────────┘
```

| Skill | Role |
|---|---|
| [`nyavs-orchestrator`](skills/nyavs-orchestrator/SKILL.md) | The workflow: phases, verdict rules, silent-zero discipline, report |
| [`nyavs-intel-ingestor`](skills/nyavs-intel-ingestor/SKILL.md) | Article → structured CVE/IOC JSON with a fixed schema |
| [`nyavs-query-builder`](skills/nyavs-query-builder/SKILL.md) | Vendor-neutral SIEM queries with stages, assumptions, fallbacks, controls |
| [`nyavs-escalation`](skills/nyavs-escalation/SKILL.md) | Slack escalation drafts that front-load the facts and the ask |

## What makes it different

- **Declared ≠ executed.** Artifact registries, SBOMs, and lockfiles are all opt-in or bypassable. NYAVS will not report `NOT EXPOSED` unless a runtime source with positive coverage would have seen the threat. Otherwise the verdict is `NO_EVIDENCE_FOUND`, along with the reason.
- **Silent-zero discipline.** Search APIs return confident zeros for broken queries, capped result sets, rate limits, archived repos, unindexed large files, non-default branches, and ignored filter parameters. Every zero needs a positive control before it counts.
- **Transitive dependencies.** Lockfiles are parsed in memory with standard-library code, so packages that no manifest names still get found. The inventory never leaves your network.
- **Mandatory raw drilldown.** Keyword pivots produce token collisions, so no log hit becomes a finding until the indicator is confirmed in a real field.
- **Receipts.** Every finding carries the exact query that produced it, and the report appendix holds them all so another analyst can reproduce the run.

## Is it practical?

Read this section before you install it.

- **It is only as good as your access.** NYAVS orchestrates GitLab/GitHub, a code indexer, an artifact registry, a SIEM, an attack-surface inventory, a vulnerability scanner, runtime telemetry, a ticketing system, and Slack. Every platform you don't have becomes a named coverage gap in the report, and the assessment shrinks accordingly.
- **The queries need translating.** `nyavs-query-builder` writes in a neutral pipeline notation, and store names, field names, and log types are placeholders. Expect some setup work to map them onto your SIEM before the first real run.
- **It is a lot of agent work.** A multi-CVE run fans out parallel sub-agents and many API calls. Plan for the token cost and for API rate limits.
- **Humans stay in the loop.** The skills stop before creating tickets, posting, or escalating. That is deliberate.
- **It assists analysts and doesn't replace them.** It can't judge business context. It also can't fix gaps in your telemetry, though it will tell you exactly where they are.
- **Status: this is a methodology release.** These skills were generalized from a working internal workflow, and every organization-specific detail has been removed. This public edition has not been run end-to-end as published. Treat it as a strong starting point to adapt, not a turnkey product.

## Install

```bash
git clone https://github.com/<commandctrl>/nyavs.git
cp -r nyavs/skills/* ~/.claude/skills/
```

Then set the environment variables listed in the orchestrator's **Configuration** section and run:

```
/nyavs-orchestrator CVE-2026-12345
```

## Security model

- Credentials come from environment variables only. Nothing secret is printed or persisted, and values that look like credentials are redacted before any write.
- Fetched content is treated as untrusted data, and that boundary is restated inside every sub-agent prompt.
- URLs other than the primary advisory pass a VirusTotal check before NYAVS navigates to them.
- Repositories are never cloned, and internal dependency data is never uploaded to third-party services.
- Every ticket, post, or escalation needs explicit human confirmation.

## Contributing

Issues and pull requests are welcome. Contributions that add a silent-zero trap with a reproducible control are especially useful.

## Project page

`index.html` is the project's landing page. To publish it, open **Settings → Pages**, choose **Deploy from a branch**, then branch `main` and folder `/ (root)`. It loads no external resources (`.nojekyll` makes Pages serve the files untouched).

## License

[MIT](LICENSE)
