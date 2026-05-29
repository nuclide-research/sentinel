# sentinel

CVE-reactive exposure pipeline for AI/ML infrastructure. A new CISA KEV entry
comes in, and sentinel answers one question: do we already see it on the
internet, and do we already see it in our own surveyed hosts.

A KEV listing tells you a vulnerability is being exploited. It does not tell you
whether the affected platform is one you track, how many instances are exposed
right now, or whether any of them are hosts you already fingerprinted. sentinel
chains those answers together. It polls the KEV feed, enriches each CVE from NVD,
looks for public PoC, decides whether the CVE touches an AI/ML platform, cross
references the affected version range against a local corpus of surveyed hosts,
counts live Shodan exposure, scores priority, and routes the result to a findings
ledger and a phone notification. Everything past the public feeds is optional and
degrades gracefully: with nothing but `requests` installed it still polls KEV,
enriches NVD, finds PoC, and scores.

## Install

```
git clone https://github.com/nuclide-research/sentinel
cd sentinel
pip install requests
```

Python 3.9+ (generic type subscripts like `dict[str, dict]` are used in
annotations). `requests` is the only hard requirement; sentinel exits with a
message if it is missing.

Optional:

```
pip install playwright           # Shodan via authenticated browser session
python -m playwright install chromium
```

`playwright` is only needed when the direct Shodan API key path is unavailable or
expired. Without it, sentinel uses the API key path alone.

## Requires (optional integrations)

These are discovered at runtime and skipped if absent. None block a run.

| Integration | Purpose | Where sentinel looks |
| --- | --- | --- |
| `aimap` | Fingerprint top P1/P2 exposed hosts | `PATH`, `~/go/bin`, `~/Tools/`, `~/<name>/`, `~/.local/bin` |
| `winnow` | False-positive screen on aimap output | `~/winnow/winnow.py` |
| `visorlog` | Ingest exposed hosts into the findings ledger | same search paths as `aimap` |
| `tome` | Source of strict per-platform Shodan dorks | same search paths as `aimap` |
| `visorscuba`, `jaxen`, `visorsd` | Discovered but not invoked by the current pipeline | same search paths |
| OSINT corpus | Version-range match against surveyed hosts, the dork catalog, and live baselines | `~/AI-LLM-Infrastructure-OSINT/` (data, evidence, working, `shodan/queries`, `visorlog.db`) |

The corpus integration lives in `corpus_query.py` and is imported on a guarded
basis. If `~/AI-LLM-Infrastructure-OSINT/` is not present, corpus matching,
catalog dorks, and anomaly baselines are simply empty and sentinel falls back to a
small built-in dork table.

## Configure

All configuration is environment variables or a JSON file. None are required to
run, but Shodan exposure and ntfy alerts need their respective values.

| Variable | Default | Used for |
| --- | --- | --- |
| `SHODAN_API_KEY` | (unset) | Shodan host count and search |
| `SENTINEL_NTFY_TOPIC` | `nuclide-sentinel` | ntfy alert topic |
| `NVD_API_KEY` | (unset) | Higher NVD rate limit |
| `GITHUB_TOKEN` | (unset) | Higher GitHub search rate limit |

JSON overrides load from `~/.config/sentinel/config.json` (keys match the `Config`
fields). If `SHODAN_API_KEY` is unset, sentinel also reads
`~/.config/nuclide/shodan.key` then `~/.config/shodan/api_key`.

State and logs are written under `~/.local/share/sentinel/` (`state.json`,
`pharos-queue.ndjson`, and dated `logs/sentinel-YYYY-MM-DD.ndjson`).

## Usage

```
python3 sentinel.py run                # full pipeline, once
python3 sentinel.py run --loop         # repeat every 6h
python3 sentinel.py run --dry-run      # no active probes, no ledger writes, no alerts
python3 sentinel.py status             # processed-CVE count + recent findings
python3 sentinel.py reset              # clear processed-CVE state
```

`run` processes only CVEs not already seen (state is checkpointed after each CVE,
so an interrupted run resumes). The pipeline per new CVE:

1. CISA KEV poll, filtered to the last 30 days.
2. NVD enrichment: CVSS, description, CPE products, affected version ranges.
3. GitHub PoC search (top 5 by stars).
4. Platform match: CISA vendor/product and NVD CPE against a registry of AI/ML
   platforms (Ollama, vLLM, MLflow, ChromaDB, Qdrant, Weaviate, Langflow, Dify,
   Flowise, LiteLLM, n8n, and others). No AI/ML match means the CVE is skipped.
5. Corpus match: surveyed hosts running a version inside the affected range.
6. Shodan exposure count plus a sample of hosts, with anomaly flagging against
   live baselines.
7. Priority score (CVSS, PoC presence, KEV membership, recency) to P1 through P4.
8. For P1/P2 with live hosts: aimap fingerprint of the top hosts, then a winnow
   false-positive screen.
9. visorlog ingest of exposed hosts (skipped under `--dry-run`).
10. ntfy alert if the priority clears the configured floor (default P2).

`--dry-run` skips every active or destructive step: no aimap probes, no visorlog
writes, no ntfy, no pharos queue entries. The read-only feed lookups still run.

`status` prints the processed-CVE and run counts, then the highest-priority
findings from the most recent daily log.

### corpus_query helper

`corpus_query.py` is importable by sentinel and also runs standalone for
inspecting the corpus and dork catalog:

```
python3 corpus_query.py stats          # corpus host/version/source/platform summary (default)
python3 corpus_query.py dorks          # dork catalog size + top platforms by hit count
python3 corpus_query.py cves           # CVE cross-references found in the catalog
python3 corpus_query.py match          # example: Ollama < 0.1.34 hosts in corpus
```

These require `~/AI-LLM-Infrastructure-OSINT/` to be present; without it they
report empty results.

## Notes

The aimap, visorlog, and Shodan stages reach out to live hosts and external
services. Run them against your own or authorized infrastructure only. `--dry-run`
exists so you can exercise the feed and scoring logic without touching any host.
The corpus, dork catalog, and baseline integrations are tied to the local NuClide
OSINT repository layout and are inert outside it.

## License

MIT. Part of the NuClide toolchain.
