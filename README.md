# sentinel

CVE-reactive exposure pipeline for AI/ML infrastructure. Polls CISA KEV, enriches each new entry from NVD, finds public PoC repos, checks whether the CVE touches a tracked AI/ML platform, cross-references the affected version range against a local corpus of surveyed hosts, counts live Shodan exposure with anomaly detection against April 2026 baselines, scores priority, then routes results to a findings ledger and a phone notification.

A KEV listing tells you a vulnerability is being exploited. It does not tell you whether the affected platform is one you track, how many instances are exposed now, or whether any are hosts you already fingerprinted. sentinel chains those answers together in one pass, per new CVE. Everything past the public feeds degrades gracefully: with only `requests` installed, it still polls KEV, enriches NVD, finds PoC, and scores. Each integration layer is optional and its absence does not block a run.

## Install

```bash
git clone https://github.com/nuclide-research/sentinel
cd sentinel
pip install requests
```

Python 3.9+. `requests` is the only hard requirement; sentinel exits with a message if it is missing.

Optional (for Shodan via authenticated browser session when the API key is absent or expired):

```bash
pip install playwright
python -m playwright install chromium
```

## Configure

All configuration is environment variables or a JSON file at `~/.config/sentinel/config.json`. None are required to run.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SHODAN_API_KEY` | (unset) | Shodan host count + search |
| `SENTINEL_NTFY_TOPIC` | `nuclide-sentinel` | ntfy alert topic |
| `NVD_API_KEY` | (unset) | Higher NVD rate limit (50 req/30s without key) |
| `GITHUB_TOKEN` | (unset) | Higher GitHub search rate limit |

If `SHODAN_API_KEY` is unset, sentinel also reads `~/.config/nuclide/shodan.key` then `~/.config/shodan/api_key`. When neither API key path is set, Shodan exposure queries run via Playwright authenticated browser session (`shodan_playwright.py`), falling back to empty if Playwright is also unavailable.

State and logs write under `~/.local/share/sentinel/`: `state.json`, `pharos-queue.ndjson`, and dated `logs/sentinel-YYYY-MM-DD.ndjson`.

## Usage

```
python3 sentinel.py run               # full pipeline, once
python3 sentinel.py run --loop        # repeat every 6 hours
python3 sentinel.py run --dry-run     # no active probes, no ledger writes, no alerts
python3 sentinel.py status            # processed-CVE count + recent findings
python3 sentinel.py reset             # clear processed-CVE state
```

`run` processes only CVEs not already seen. State is checkpointed after each CVE, so an interrupted run resumes cleanly.

## Pipeline per new CVE (10 steps)

1. **CISA KEV poll** - fetch the KEV catalog, filter to the last 30 days.
2. **NVD enrichment** - CVSS score and vector, English description, CPE products, affected version ranges.
3. **GitHub PoC search** - top 5 repos by stars for the CVE ID.
4. **Platform match** - CISA vendor/product fields and NVD CPE strings matched against a registry of 30+ AI/ML platforms (Ollama, vLLM, MLflow, ChromaDB, Qdrant, Weaviate, Langflow, Dify, Flowise, LiteLLM, n8n, and others). No AI/ML match means the CVE is skipped.
5. **Corpus match** - query surveyed hosts for versions inside the NVD-reported (or manually overridden) affected range. Reports which of our fingerprinted hosts are running a vulnerable version.
6. **Shodan exposure** - count live exposed instances using the OSINT dork catalog (primary), the TOME per-platform strict dorks (fallback), or a built-in dork table (last resort). Anomaly detection flags a large change vs April 2026 baselines.
7. **Priority score** - four-factor formula: CVSS (0.25), PoC presence (0.25), KEV membership (0.15), recency decay (0.15). Produces P1 through P4.
8. **aimap fingerprint** - for P1/P2 with live hosts: fingerprint the top 5 exposed hosts with aimap, then run a winnow false-positive screen on the output.
9. **visorlog ingest** - write exposed hosts into the findings ledger (skipped under `--dry-run`).
10. **ntfy alert** - push a phone notification if the priority clears the configured floor (default P2; skipped under `--dry-run`).

P1/P2 corpus hits also write an entry to `pharos-queue.ndjson` for downstream autonomous follow-up by pharos.

## Optional integrations

All integrations are discovered at runtime. A missing integration causes its step to skip; the rest of the pipeline continues.

| Integration | Purpose | Location sentinel searches |
|-------------|---------|---------------------------|
| `aimap` | Fingerprint top P1/P2 exposed hosts | PATH, `~/go/bin`, `~/Tools/`, `~/.local/bin` |
| `winnow` | False-positive screen on aimap output | `~/winnow/winnow.py` |
| `visorlog` | Ingest exposed hosts into findings ledger | same paths as aimap |
| `tome` | Source of per-platform strict Shodan dorks | same paths as aimap |
| OSINT corpus | Version-range match, dork catalog, live baselines | `~/AI-LLM-Infrastructure-OSINT/` |

The corpus integration (`corpus_query.py`) reads surveyed host records, a dork catalog, and live Shodan baselines from the local NuClide OSINT repository layout. Without that directory, corpus matching, catalog dorks, and anomaly baselines are empty and sentinel falls back to the built-in dork table.

### corpus_query standalone

`corpus_query.py` also runs standalone for inspecting the corpus and dork catalog:

```
python3 corpus_query.py stats    # corpus host/version/source/platform summary
python3 corpus_query.py dorks    # dork catalog size + top platforms by hit count
python3 corpus_query.py cves     # CVE cross-references in the catalog
python3 corpus_query.py match    # example: Ollama < 0.1.34 hosts in corpus
```

Requires `~/AI-LLM-Infrastructure-OSINT/` to be present; without it these report empty.

## Example output

```
sentinel  CVE-Reactive AI/ML Exposure Pipeline
  tools: aimap=ok  winnow=ok  visorlog=ok  tome=missing  ...
  corpus: 895 surveyed hosts  (743 with version)  |  dorks: 2625 entries across 48 platforms

──────────────────────────────────────────────────────────────
  2026-06-03T14:00:00Z

Phase 1  CISA KEV poll (lookback 30d)
  ok  12 CVEs in last 30d (catalog: 1,247 total)
  4 new CVEs to process (8 already seen)

  CVE-2026-42208  berriai / litellm
    platforms: litellm (catalog)
    corpus 3 of our surveyed hosts running vulnerable version
      192.0.2.10       v1.82.4       Hetzner Online GmbH
      192.0.2.11       v1.83.1       OVH SAS
    CVSS 9.8 | PoC yes | score 0.874 → [P1]
    Shodan  litellm  57,454 hosts  Δ+12% vs baseline
    aimap fingerprinting top 5 hosts...

Run complete
  4 CVEs processed | 1 AI/ML matches
  [P1]  CVE-2026-42208  litellm  57,454 shodan  3c own  CVSS 9.8
```

## Notes

The aimap and Shodan exposure stages reach out to live hosts and external services. Run them against your own or authorized infrastructure only. `--dry-run` exercises the feed and scoring logic without touching any host, writing any ledger entry, or sending any alert.

## What sentinel is not

sentinel is not an always-on daemon. It runs once or in a 6-hour loop under `--loop`. It does not monitor network traffic or parse logs. Its corpus, dork catalog, and baseline integrations are tied to the local NuClide OSINT repository layout and are inert outside it. It does not replace aimap or visorlog; it drives them.

## License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
