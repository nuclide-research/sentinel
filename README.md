<h1 align="center">sentinel</h1>

<h4 align="center">CVE-reactive exposure pipeline for AI and ML infrastructure.</h4>

<p align="center">
  <a href="https://github.com/nuclide-research/sentinel/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nuclide-research/sentinel?style=flat-square" alt="license"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python" alt="python"></a>
  <a href="https://nuclide-research.com"><img src="https://img.shields.io/badge/by-NuClide-blue?style=flat-square" alt="NuClide"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#pipeline">Pipeline</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#scope">Scope</a>
</p>

---

sentinel polls the CISA KEV feed and answers one question per new CVE: do we already see it on the internet, and do we already see it in our own surveyed hosts. A KEV listing flags a vulnerability under active exploitation. It does not say whether the platform is one you track, how many instances are exposed right now, or which of them are hosts you fingerprinted last week. sentinel chains those answers together: KEV poll, NVD enrichment, GitHub PoC search, AI/ML platform match, corpus version-range match, Shodan exposure count, P1 to P4 score, aimap top-host fingerprint, winnow false-positive screen, visorlog ingest, ntfy alert.

Every stage past the public feeds is optional and degrades cleanly. With nothing but `requests` installed, sentinel still polls KEV, enriches NVD, finds PoC, and scores. Drop in a Shodan key and live exposure counts appear. Drop in the OSINT corpus and surveyed-host matching turns on.

# Features

- Pulls the CISA KEV feed, filtered to the last 30 days, with idempotent per-CVE checkpointing
- NVD enrichment: CVSS, description, CPE products, affected version ranges
- GitHub PoC search, top 5 by stars
- Platform matcher against an AI/ML registry (Ollama, vLLM, MLflow, ChromaDB, Qdrant, Weaviate, Langflow, Dify, Flowise, LiteLLM, n8n, and others). No match means the CVE is skipped
- Corpus cross-reference: surveyed hosts running a version inside the affected range
- Shodan exposure count plus a sample of hosts, with anomaly flagging against live baselines
- P1 to P4 priority score across CVSS, PoC presence, KEV membership, and recency
- Auto-fingerprints top P1 and P2 hosts with aimap, screens the result through winnow
- Routes confirmed exposures to visorlog and ntfy
- `--dry-run` exercises the full feed and scoring path with zero active probes and zero ledger writes
- Pure standard library plus `requests`. Shodan and Playwright are optional add-ons

# Installation

```bash
git clone https://github.com/nuclide-research/sentinel
cd sentinel
pip install requests
```

Python 3.9 or later. `requests` is the only hard requirement.

Optional:

```bash
pip install playwright
python -m playwright install chromium
```

Playwright is only needed when the Shodan API key path is unavailable or expired.

# Usage

```console
python3 sentinel.py run                # full pipeline, once
python3 sentinel.py run --loop         # repeat every 6h
python3 sentinel.py run --dry-run      # no active probes, no ledger writes, no alerts
python3 sentinel.py status             # processed-CVE count and recent findings
python3 sentinel.py reset              # clear processed-CVE state
```

`run` processes only CVEs not already seen. State is checkpointed after each CVE so an interrupted run resumes. `--dry-run` skips every active or destructive step: no aimap probes, no visorlog writes, no ntfy, no pharos queue entries. The read-only feed lookups still run.

# Pipeline

Per new CVE:

1. CISA KEV poll, filtered to the last 30 days
2. NVD enrichment: CVSS, description, CPE products, affected version ranges
3. GitHub PoC search, top 5 by stars
4. Platform match: CISA vendor/product and NVD CPE against the AI/ML registry. No AI/ML match means skip
5. Corpus match: surveyed hosts running a version inside the affected range
6. Shodan exposure count plus a sample of hosts, anomaly-flagged against live baselines
7. Priority score: P1 to P4 across CVSS, PoC, KEV membership, recency
8. For P1 and P2 with live hosts: aimap fingerprint of the top hosts, then a winnow false-positive screen
9. visorlog ingest of exposed hosts (skipped under `--dry-run`)
10. ntfy alert if the priority clears the configured floor (default P2)

# Configuration

All configuration is environment variables or a JSON file. None are required to run, but Shodan exposure and ntfy alerts need their respective values.

| Variable | Default | Used for |
|----------|---------|----------|
| `SHODAN_API_KEY` | (unset) | Shodan host count and search |
| `SENTINEL_NTFY_TOPIC` | `nuclide-sentinel` | ntfy alert topic |
| `NVD_API_KEY` | (unset) | Higher NVD rate limit |
| `GITHUB_TOKEN` | (unset) | Higher GitHub search rate limit |

JSON overrides load from `~/.config/sentinel/config.json` (keys match the `Config` fields). If `SHODAN_API_KEY` is unset, sentinel also reads `~/.config/nuclide/shodan.key`, then `~/.config/shodan/api_key`.

State and logs land under `~/.local/share/sentinel/` (`state.json`, `pharos-queue.ndjson`, dated `logs/sentinel-YYYY-MM-DD.ndjson`).

# Optional integrations

Discovered at runtime, skipped if absent. None block a run.

| Integration | Purpose | Where sentinel looks |
|-------------|---------|----------------------|
| `aimap` | Fingerprint top P1 and P2 hosts | `PATH`, `~/go/bin`, `~/Tools/`, `~/<name>/`, `~/.local/bin` |
| `winnow` | False-positive screen on aimap output | `~/winnow/winnow.py` |
| `visorlog` | Ingest exposed hosts into the findings ledger | same paths as `aimap` |
| `tome` | Source of strict per-platform Shodan dorks | same paths as `aimap` |
| OSINT corpus | Version-range match, dork catalog, live baselines | `~/AI-LLM-Infrastructure-OSINT/` |

# Scope

The aimap, visorlog, and Shodan stages reach out to live hosts and external services. Run them against your own or authorized infrastructure only. `--dry-run` exists so you can exercise the feed and scoring logic without touching any host.

# Our other projects

- [aimap](https://github.com/nuclide-research/aimap) — fingerprint scanner for AI and ML infrastructure
- [winnow](https://github.com/nuclide-research/winnow) — codified false-positive screen for scanner output
- [pharos](https://github.com/nuclide-research/pharos) — autonomous offensive research agent
- [visorlog](https://github.com/nuclide-research/visorlog) — finding ledger and ingest pipeline
- [tome](https://github.com/nuclide-research/tome) — canonical AI-infra platform corpus

# License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
