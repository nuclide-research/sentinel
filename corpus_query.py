"""
corpus_query.py — NuClide OSINT corpus integration for sentinel.

Three capabilities:
  1. load_corpus()         — 493 surveyed AI/ML hosts with versions
  2. query_by_version()    — find corpus hosts running a vulnerable version range
  3. parse_dork_catalog()  — 181+ battle-tested Shodan dorks with hit counts + CVE notes
"""

import json
import re
from pathlib import Path
from typing import Optional

# ─── Paths ────────────────────────────────────────────────────────────────────

OSINT_ROOT = Path.home() / "AI-LLM-Infrastructure-OSINT"
DATA_DIR   = OSINT_ROOT / "data"
DORK_DIR   = OSINT_ROOT / "shodan" / "queries"


# ─── 1. Corpus loader ─────────────────────────────────────────────────────────

def load_corpus() -> dict[str, dict]:
    """
    Load all surveyed host records from OSINT state files.
    Keyed by IP. Deduplicates across files (later file wins on conflict).

    Returns dict: {ip_str -> host_record}

    Host record fields (where available):
      ip, org, hostnames, status, version, models, running,
      system_prompts, cloud_proxy, first_seen, last_probed, _source
    """
    corpus: dict[str, dict] = {}

    if not DATA_DIR.exists():
        return corpus

    # Load all ollama state files — sorted so later surveys overwrite earlier
    for state_file in sorted(DATA_DIR.glob("ollama-*state*.json")):
        try:
            data = json.loads(state_file.read_text())
            if not isinstance(data, dict):
                continue
            for ip, rec in data.items():
                rec = dict(rec)
                rec["_source"] = state_file.name
                rec["_platform"] = "ollama"
                corpus[ip] = rec
        except Exception:
            continue

    return corpus


def corpus_stats(corpus: dict) -> dict:
    """Summary statistics over the loaded corpus."""
    total = len(corpus)
    with_version = sum(1 for r in corpus.values() if r.get("version"))
    cloud_proxy = sum(1 for r in corpus.values() if r.get("cloud_proxy"))
    version_dist: dict[str, int] = {}
    for r in corpus.values():
        v = r.get("version")
        if v:
            version_dist[v] = version_dist.get(v, 0) + 1

    sources: dict[str, int] = {}
    for r in corpus.values():
        s = r.get("_source", "unknown")
        sources[s] = sources.get(s, 0) + 1

    return {
        "total_hosts": total,
        "with_version": with_version,
        "cloud_proxy": cloud_proxy,
        "top_versions": sorted(version_dist.items(), key=lambda x: -x[1])[:10],
        "by_source": sources,
    }


# ─── 2. Version range matching ────────────────────────────────────────────────

def _parse_semver(v: str) -> tuple[int, ...]:
    """Parse version string to comparable tuple. Handles 0.1.34, 0.20.2, etc."""
    if not v:
        return (0,)
    v = v.lstrip("v").strip()
    # Strip pre-release/build metadata
    v = re.split(r"[-+]", v)[0]
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts) if parts else (0,)


def _version_in_range(
    version: str,
    start_including: Optional[str] = None,
    end_excluding: Optional[str]   = None,
    end_including: Optional[str]   = None,
) -> bool:
    """True if version falls within the specified range."""
    if not version:
        return False
    v = _parse_semver(version)

    if start_including:
        if v < _parse_semver(start_including):
            return False

    if end_excluding:
        if v >= _parse_semver(end_excluding):
            return False

    if end_including:
        if v > _parse_semver(end_including):
            return False

    return True


def query_by_version_range(
    corpus: dict[str, dict],
    platform: str,
    start_including: Optional[str] = None,
    end_excluding: Optional[str]   = None,
    end_including: Optional[str]   = None,
) -> list[dict]:
    """
    Return corpus hosts for the given platform running a vulnerable version.

    Example:
        # Ollama < 0.1.34 (CVE-2024-37032 Probllama)
        hits = query_by_version_range(corpus, "ollama", end_excluding="0.1.34")

    Returns list of host dicts with ip, version, org, models, _source.
    """
    results = []
    for ip, rec in corpus.items():
        if rec.get("_platform") != platform:
            continue
        version = rec.get("version")
        if not version:
            continue
        if _version_in_range(version, start_including, end_excluding, end_including):
            results.append({
                "ip": ip,
                "version": version,
                "org": rec.get("org", ""),
                "hostname": (rec.get("hostnames") or [""])[0],
                "models": rec.get("models", []),
                "cloud_proxy": rec.get("cloud_proxy", False),
                "last_probed": rec.get("last_probed", ""),
                "_source": rec.get("_source", ""),
            })
    return results


def match_nvd_version_ranges(corpus: dict, platform: str, nvd_record) -> list[dict]:
    """
    Given an NVDRecord (from sentinel), extract version ranges from CPE
    configurations and query the corpus.

    Returns list of matching host dicts.
    """
    # nvd_record is the NVDRecord dataclass from sentinel
    # We need to re-fetch the raw NVD data for version ranges, OR
    # accept pre-parsed range tuples. For now, expose a simpler interface.
    # Callers should use query_by_version_range() directly with NVD-parsed ranges.
    return []


# ─── 3. Dork catalog parser ───────────────────────────────────────────────────

# Extract hit count from notes: "19,549 hits" or "37 hits" → 19549 or 37
_HIT_RE = re.compile(r"([\d,]+)\s+hits?", re.I)

# Extract CVE IDs from text
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Match version constraint from notes: "< 1.8.2", "< 0.1.34", etc.
_VER_RE = re.compile(r"[<>]=?\s*([\d]+\.[\d]+\.[\d]+)", re.I)


def parse_dork_catalog(dork_dir: Path = DORK_DIR) -> dict[str, list[dict]]:
    """
    Parse all markdown dork catalog files into a structured dict.

    Returns:
        {platform_slug -> [
            {
                query:     str,
                notes:     str,
                hits:      int or None,
                cves:      [str],
                ver_upper: str or None,   # "< X.Y.Z" upper bound if noted
            }
        ]}

    Platform slugs are lowercased, spaces/hyphens normalized:
        "flowise", "ollama", "open-webui", "n8n", "langflow", ...
    """
    catalog: dict[str, list[dict]] = {}

    if not dork_dir.exists():
        return catalog

    for md_file in sorted(dork_dir.glob("*.md")):
        _parse_md_file(md_file, catalog)

    return catalog


def _parse_md_file(path: Path, catalog: dict):
    """Parse one markdown dork file into catalog (mutates catalog in-place)."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    current_platform: Optional[str] = None

    for line in text.splitlines():
        line = line.strip()

        # H2 heading = new platform section
        if line.startswith("## "):
            heading = line[3:].strip()
            # Normalize: lowercase, collapse whitespace
            current_platform = re.sub(r"[^\w]+", "-", heading.lower()).strip("-")
            if current_platform not in catalog:
                catalog[current_platform] = []
            continue

        # H1 heading = category label, not a platform — skip but don't reset platform
        if line.startswith("# "):
            continue

        # Table row: | query | notes |
        if not (line.startswith("|") and "|" in line[1:]):
            continue

        parts = [p.strip() for p in line.split("|")]
        parts = [p for p in parts if p]  # remove empty first/last
        if len(parts) < 2:
            continue

        # Detect 4-column format: | label | `query` | description | tier |
        # The label column is: primary, secondary, tertiary, quaternary, identity-probe, etc.
        _LABELS = {"primary", "secondary", "tertiary", "quaternary", "identity-probe",
                   "broad", "api-confirm", "ssrf-probe", "title-match", "header-match",
                   "port-only", "banner-only"}
        if parts[0].lower().strip() in _LABELS and len(parts) >= 2:
            raw_query = parts[1].strip("`").strip()
            notes = " ".join(parts[2:]) if len(parts) > 2 else ""
        else:
            raw_query = parts[0].strip("`").strip()
            notes = " ".join(parts[1:]) if len(parts) > 1 else ""

        # Skip header rows and non-query artifacts
        _SKIP = {"shodan query", "query", "label", "description", "notes",
                 "filter", "dork", "example", "signal", "purpose"}
        if raw_query.lower() in _SKIP:
            continue
        if re.match(r"^[-:]+$", raw_query):
            continue
        # Skip rows that look like prose (no quotes, no colons, no dots, long text)
        if len(raw_query) > 80 and " " in raw_query and '"' not in raw_query:
            continue

        # Extract hit count
        hit_match = _HIT_RE.search(notes)
        hits = int(hit_match.group(1).replace(",", "")) if hit_match else None

        # Extract CVE references
        cves = list(set(_CVE_RE.findall(notes)))

        # Extract version upper bound (e.g., "< 1.8.2")
        ver_match = _VER_RE.search(notes)
        ver_upper = ver_match.group(1) if ver_match else None

        platform_key = current_platform or "_unknown"
        if platform_key not in catalog:
            catalog[platform_key] = []

        catalog[platform_key].append({
            "query":     raw_query,
            "notes":     notes,
            "hits":      hits,
            "cves":      cves,
            "ver_upper": ver_upper,
        })


# Explicit mapping from common platform IDs to catalog section slugs.
# Needed because platforms like Ollama appear as rows under "Other Orchestrators"
# rather than having their own H2 heading.
_PLATFORM_SLUG_MAP: dict[str, list[str]] = {
    "ollama":          ["other-orchestrators"],
    "open-webui":      ["other-orchestrators"],
    "n8n":             ["prompt-chain-management"],
    "langflow":        ["langflow"],
    "litellm":         ["ai-gateway-proxy", "litellm"],
    "dify":            ["dify"],
    "flowise":         ["flowise"],
    "chromadb":        ["chromadb"],
    "qdrant":          ["qdrant"],
    "weaviate":        ["weaviate"],
    "milvus":          ["milvus"],
    "mlflow":          ["mlflow-tracking-server"],
    "airflow":         ["ml-experiment-pipeline-tools", "airflow"],
    "jupyter":         ["jupyter", "version-specific-cve-targeting"],
    "grafana":         ["grafana"],
    "elasticsearch":   ["elasticsearch-opensearch"],
    "langfuse":        ["langfuse"],
    "langsmith":       ["langsmith-self-hosted"],
    "vllm":            ["vllm", "inference-servers"],
    "rayserve":        ["ray-serve-ray-dashboard", "ray-dashboard-ray-tune"],
    "temporal":        ["temporal"],
    "llamacpp":        ["llamacpp", "inference-servers"],
    "tgi":             ["tgi", "inference-servers"],
    "sglang":          ["sglang", "inference-servers"],
    "mlflow":          ["mlflow-tracking-server", "mlflow-model-registry", "ml-experiment-pipeline-tools"],
    "jupyter":         ["jupyter"],   # NOT version-specific-cve-targeting
}

# Dork-level keyword filters — for platforms that share a catalog section,
# pick only dorks whose query contains this string.
_PLATFORM_DORK_FILTER: dict[str, str] = {
    "ollama":     "Ollama",
    "open-webui": "WebUI",
    "n8n":        "n8n",
    "dify":       "ify",    # "Dify" or "dify"
    "litellm":    "LiteLLM",
    "vllm":       "vLLM",
    "langflow":   "Langflow",
}


def get_best_dork(platform: str, catalog: dict) -> Optional[str]:
    """
    Return the single best Shodan dork for a platform.
    Uses an explicit slug map to avoid false substring matches,
    then picks the highest-hit dork with a specific fingerprint.
    """
    slug = re.sub(r"[^\w]+", "-", platform.lower()).strip("-")

    # 1. Exact slug match
    candidates = catalog.get(slug, [])

    # 2. Explicit alias map
    if not candidates:
        for alias in _PLATFORM_SLUG_MAP.get(slug, _PLATFORM_SLUG_MAP.get(platform.lower(), [])):
            if alias in catalog:
                raw = catalog[alias]
                # Apply keyword filter for shared sections
                kw = _PLATFORM_DORK_FILTER.get(slug, "")
                if kw:
                    filtered = [e for e in raw if kw.lower() in e["query"].lower()]
                    candidates = filtered if filtered else raw
                else:
                    candidates = raw
                break

    # 3. Safe prefix match — only if the slug is >= 5 chars to avoid noise
    if not candidates and len(slug) >= 5:
        for key in sorted(catalog.keys()):
            # Must be an exact word boundary match, not a substring
            if key == slug or key.startswith(slug + "-") or key.endswith("-" + slug):
                candidates = catalog[key]
                break

    if not candidates:
        return None

    # Only entries that look like valid Shodan queries
    _OPERATORS = ('product:', 'http.title:', 'http.html:', 'port:', 'header:', '"', 'hostname:')
    valid = [
        e for e in candidates
        if any(op in e["query"] for op in _OPERATORS)
        and len(e["query"]) >= 6
        and e["query"].lower() not in ("primary", "secondary", "tertiary", "label", "notes")
    ]
    if not valid:
        return None

    # Prefer specific fingerprints (product:, http.title:, http.html:) with hit counts
    specific = [
        e for e in valid
        if any(k in e["query"] for k in ('product:"', 'http.title:"', 'http.html:"'))
        and e["hits"] is not None
    ]
    pool = specific if specific else [e for e in valid if e["hits"] is not None]

    if pool:
        return max(pool, key=lambda e: e["hits"])["query"]

    return valid[0]["query"] if valid else None


def get_cve_platform_map(catalog: dict) -> dict[str, list[dict]]:
    """
    Extract all CVE → platform mappings from the catalog.

    Returns:
        {cve_id -> [
            {platform: str, query: str, notes: str, ver_upper: str or None}
        ]}
    """
    cve_map: dict[str, list[dict]] = {}
    for platform, entries in catalog.items():
        for entry in entries:
            for cve in entry.get("cves", []):
                if cve not in cve_map:
                    cve_map[cve] = []
                cve_map[cve].append({
                    "platform":  platform,
                    "query":     entry["query"],
                    "notes":     entry["notes"],
                    "ver_upper": entry.get("ver_upper"),
                })
    return cve_map


def get_population_baselines(catalog: dict) -> dict[str, int]:
    """
    Return the highest confirmed hit count per platform.
    Used to detect anomalous growth in Shodan exposure.

    Returns: {platform_slug -> max_hit_count}
    """
    baselines: dict[str, int] = {}
    for platform, entries in catalog.items():
        hits = [e["hits"] for e in entries if e["hits"] is not None]
        if hits:
            baselines[platform] = max(hits)
    return baselines


# ─── Quick test / CLI ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"

    if cmd == "stats":
        corpus = load_corpus()
        stats = corpus_stats(corpus)
        print(f"\nCorpus: {stats['total_hosts']} hosts "
              f"({stats['with_version']} with version, "
              f"{stats['cloud_proxy']} cloud proxies)")
        print("\nTop versions:")
        for v, c in stats["top_versions"]:
            print(f"  {c:3}  v{v}")
        print("\nBy source:")
        for s, c in stats["by_source"].items():
            print(f"  {c:4}  {s}")

    elif cmd == "dorks":
        catalog = parse_dork_catalog()
        baselines = get_population_baselines(catalog)
        print(f"\nDork catalog: {sum(len(v) for v in catalog.values())} entries "
              f"across {len(catalog)} platforms")
        print("\nTop platforms by max hit count:")
        for platform, count in sorted(baselines.items(), key=lambda x: -x[1])[:20]:
            best = get_best_dork(platform, catalog)
            print(f"  {count:>7,}  {platform:<25}  {best}")

    elif cmd == "cves":
        catalog = parse_dork_catalog()
        cve_map = get_cve_platform_map(catalog)
        print(f"\nCVE cross-references: {len(cve_map)} unique CVEs")
        for cve, platforms in sorted(cve_map.items()):
            for p in platforms:
                print(f"  {cve:<22}  {p['platform']:<25}  {p['notes'][:80]}")

    elif cmd == "match":
        # Example: find all Ollama hosts < 0.1.34 (CVE-2024-37032 Probllama)
        corpus = load_corpus()
        hits = query_by_version_range(corpus, "ollama", end_excluding="0.1.34")
        print(f"\nOllama < 0.1.34 (CVE-2024-37032): {len(hits)} hosts in corpus")
        for h in hits[:10]:
            print(f"  {h['ip']:<16}  v{h['version']:<12}  {h['org']}")
        if len(hits) > 10:
            print(f"  ... and {len(hits)-10} more")
