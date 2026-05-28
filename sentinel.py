#!/usr/bin/env python3
"""
sentinel — CVE-Reactive AI/ML Infrastructure Exposure Pipeline

Poll CISA KEV → NVD enrichment → GitHub PoC → TOME platform match
→ Shodan exposure count + hosts → aimap fingerprint → priority score
→ winnow FP screen → visorlog ingest → visorscuba assess → ntfy alert

Usage:
    python3 sentinel.py run              # full pipeline, once
    python3 sentinel.py run --loop       # repeat every 6h
    python3 sentinel.py run --dry-run    # no active probes or alerts
    python3 sentinel.py status           # print recent findings
    python3 sentinel.py reset            # clear processed-CVE state
"""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

# Playwright-based Shodan (session auth, used when API key is expired)
try:
    from shodan_playwright import shodan_count as _shodan_count_pw, shodan_search as _shodan_search_pw
    _PW_SHODAN = True
except ImportError:
    _PW_SHODAN = False

# ─── ANSI colours ─────────────────────────────────────────────────────────────

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

RED    = lambda t: _c("1;31", t)
YELLOW = lambda t: _c("1;33", t)
CYAN   = lambda t: _c("1;36", t)
GREEN  = lambda t: _c("1;32", t)
DIM    = lambda t: _c("2",    t)
BOLD   = lambda t: _c("1",    t)

def badge(priority: str) -> str:
    return {
        "P1": RED(f"[{priority}]"),
        "P2": YELLOW(f"[{priority}]"),
        "P3": CYAN(f"[{priority}]"),
        "P4": DIM(f"[{priority}]"),
    }.get(priority, f"[{priority}]")

# ─── Platform registry (TOME names → CPE substrings) ──────────────────────────

# Maps TOME platform ID → CPE vendor:product substrings (case-insensitive contains)
PLATFORM_CPE = {
    "chromadb":   ["chromadb", "chroma-core", "trychroma"],
    "embedding-api": ["text-embedding-inference", "huggingface:text_embedding"],
    "kserve":     ["kserve"],
    "langfuse":   ["langfuse"],
    "langserve":  ["langserve"],
    "langsmith":  ["langsmith"],
    "llamacpp":   ["llama.cpp", "llama_cpp", "llamacpp", "ggerganov"],
    "milvus":     ["milvus", "zilliz"],
    "mlflow":     ["mlflow", "databricks:mlflow"],
    "n8n":        ["n8n"],
    "nvidia-nim": ["nvidia_nim", "nvidia nim", "nvidia:nim"],
    "ollama":     ["ollama"],
    "openvino-model-server": ["openvino", "ovms", "model_server"],
    "qdrant":     ["qdrant"],
    "rayserve":   ["ray serve", "ray-serve", "anyscale"],
    "sglang":     ["sglang"],
    "tgi":        ["text-generation-inference", "text_generation_inference"],
    "vllm":       ["vllm", "vllm-project"],
    "weaviate":   ["weaviate"],
    # Not in TOME but tracked by aimap / NuClide surveys:
    "langflow":   ["langflow"],
    "dify":       ["dify", "langgenius"],
    "flowise":    ["flowise"],
    "open-webui": ["open-webui", "open_webui", "openwebui"],
    "litellm":    ["litellm", "berriai"],
    "temporal":   ["temporal", "temporalio"],
    "jupyter":    ["jupyter", "jupyterhub", "jupyterlab"],
    "grafana":    ["grafana"],
    "airflow":    ["apache:airflow", "airflow"],
    "elasticsearch": ["elasticsearch", "elastic:elasticsearch"],
}

# Fallback Shodan dorks for platforms not in TOME's catalog
PLATFORM_DORK_FALLBACK = {
    "langflow":      'http.title:"Langflow" | http.html:"langflow" port:7860',
    "dify":          'http.title:"Dify" | http.html:"dify.ai" port:3000',
    "flowise":       'http.title:"Flowise" | http.html:"flowise" port:3000',
    "open-webui":    'http.html:"open-webui" | http.title:"Open WebUI"',
    "litellm":       'http.html:"LiteLLM" | http.title:"LiteLLM" port:4000',
    "temporal":      'product:Temporal | http.html:"temporal.io" port:7233',
    "jupyter":       'http.title:"Jupyter" | "Jupyter Notebook" port:8888',
    "grafana":       'http.title:"Grafana"',
    "airflow":       'http.title:"Airflow" | http.html:"Apache Airflow"',
    "elasticsearch": 'product:Elasticsearch | http.title:"Kibana"',
}

# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class Config:
    shodan_api_key: str = ""
    ntfy_topic: str = ""
    ntfy_url: str = "https://ntfy.sh"
    nvd_api_key: str = ""
    github_token: str = ""
    state_dir: Path = field(default_factory=lambda: Path.home() / ".local" / "share" / "sentinel")
    log_dir: Path = field(default_factory=lambda: Path.home() / ".local" / "share" / "sentinel" / "logs")
    lookback_days: int = 30
    min_priority: str = "P2"
    aimap_top_n: int = 5
    dry_run: bool = False

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        cfg.shodan_api_key = os.environ.get("SHODAN_API_KEY", "")
        cfg.ntfy_topic = os.environ.get("SENTINEL_NTFY_TOPIC", "nuclide-sentinel")
        cfg.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        cfg.github_token = os.environ.get("GITHUB_TOKEN", "")

        cfg_file = Path.home() / ".config" / "sentinel" / "config.json"
        if cfg_file.exists():
            d = json.loads(cfg_file.read_text())
            for k, v in d.items():
                if hasattr(cfg, k) and v:
                    setattr(cfg, k, v)

        # NuClide Shodan key convention
        if not cfg.shodan_api_key:
            for kf in [
                Path.home() / ".config" / "nuclide" / "shodan.key",
                Path.home() / ".config" / "shodan" / "api_key",
            ]:
                if kf.exists():
                    cfg.shodan_api_key = kf.read_text().strip()
                    break

        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        cfg.log_dir.mkdir(parents=True, exist_ok=True)
        return cfg


# ─── Tool discovery ───────────────────────────────────────────────────────────

def find_tool(name: str) -> Optional[str]:
    p = shutil.which(name)
    if p:
        return p
    for candidate in [
        Path.home() / "go" / "bin" / name,
        Path.home() / "Tools" / name / name,
        Path.home() / "Tools" / name,
        Path.home() / name / name,
        Path.home() / ".local" / "bin" / name,
    ]:
        if candidate.exists():
            return str(candidate)
    return None


TOOLS = {}

def init_tools():
    for t in ["aimap", "visorlog", "visorscuba", "jaxen", "visorsd", "tome"]:
        TOOLS[t] = find_tool(t)
    # winnow is a Python script
    wp = Path.home() / "winnow" / "winnow.py"
    TOOLS["winnow"] = str(wp) if wp.exists() else None


# ─── State (processed CVE IDs) ────────────────────────────────────────────────

def load_state(cfg: Config) -> dict:
    sf = cfg.state_dir / "state.json"
    if sf.exists():
        return json.loads(sf.read_text())
    return {"processed": [], "runs": []}


def save_state(cfg: Config, state: dict):
    sf = cfg.state_dir / "state.json"
    sf.write_text(json.dumps(state, indent=2))


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class CVERecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    due_date: str = ""


@dataclass
class NVDRecord:
    cve_id: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = "UNKNOWN"
    description: str = ""
    cpe_products: list = field(default_factory=list)
    references: list = field(default_factory=list)


@dataclass
class PoCRepo:
    name: str
    url: str
    stars: int
    description: str = ""


@dataclass
class ExposedHost:
    ip: str
    port: int
    org: str = ""
    hostname: str = ""
    product: str = ""
    platform: str = ""


@dataclass
class SentinelFinding:
    cve_id: str
    vendor_project: str
    product: str
    cvss_score: float
    cvss_vector: str
    has_poc: bool
    poc_count: int
    poc_repos: list
    in_cisa_kev: bool = True
    date_added: str = ""
    days_since_added: int = 0
    matched_platforms: list = field(default_factory=list)
    exposed_count: int = 0
    exposed_hosts: list = field(default_factory=list)
    priority_score: float = 0.0
    priority_level: str = "P4"
    description: str = ""
    aimap_results: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Phase 1: CISA KEV ────────────────────────────────────────────────────────

def poll_cisa_kev(cfg: Config) -> list[CVERecord]:
    print(f"\n{BOLD('Phase 1')}  CISA KEV poll (lookback {cfg.lookback_days}d)")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"  {RED('FAIL')} CISA KEV: {e}")
        return []

    data = r.json()
    cutoff = datetime.now(timezone.utc) - timedelta(days=cfg.lookback_days)
    records = []
    for v in data.get("vulnerabilities", []):
        try:
            added = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if added >= cutoff:
            records.append(CVERecord(
                cve_id=v["cveID"],
                vendor_project=v.get("vendorProject", ""),
                product=v.get("product", ""),
                vulnerability_name=v.get("vulnerabilityName", ""),
                date_added=v["dateAdded"],
                short_description=v.get("shortDescription", ""),
                due_date=v.get("dueDate", ""),
            ))

    print(f"  {GREEN('ok')}  {len(records)} CVEs in last {cfg.lookback_days}d "
          f"(catalog: {data.get('count', '?')} total)")
    return records


# ─── Phase 2: NVD enrichment ──────────────────────────────────────────────────

def enrich_nvd(cve_id: str, cfg: Config) -> NVDRecord:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    if cfg.nvd_api_key:
        headers["apiKey"] = cfg.nvd_api_key
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
    except Exception as e:
        return NVDRecord(cve_id=cve_id)

    rec = NVDRecord(cve_id=cve_id)
    try:
        vuln = r.json()["vulnerabilities"][0]["cve"]
    except (KeyError, IndexError):
        return rec

    # Description
    for d in vuln.get("descriptions", []):
        if d.get("lang") == "en":
            rec.description = d.get("value", "")
            break

    # CVSS (prefer v3.1, fallback to v3.0, then v2.0)
    metrics = vuln.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        mlist = metrics.get(key, [])
        if mlist:
            cv = mlist[0].get("cvssData", {})
            rec.cvss_score = cv.get("baseScore", 0.0)
            rec.cvss_vector = cv.get("vectorString", "")
            rec.severity = cv.get("baseSeverity", cv.get("accessVector", "UNKNOWN"))
            break

    # CPE products
    cpe_names = set()
    for cfg_node in vuln.get("configurations", []):
        for node in cfg_node.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                uri = cpe_match.get("criteria", "")
                parts = uri.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].lower()
                    product = parts[4].lower()
                    cpe_names.add(f"{vendor}:{product}")
    rec.cpe_products = list(cpe_names)

    # References
    rec.references = [ref.get("url", "") for ref in vuln.get("references", [])[:5]]

    return rec


# ─── Phase 3: GitHub PoC search ───────────────────────────────────────────────

def search_github_poc(cve_id: str, cfg: Config) -> list[PoCRepo]:
    url = f"https://api.github.com/search/repositories?q={cve_id}+poc&sort=stars&order=desc&per_page=5"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if cfg.github_token:
        headers["Authorization"] = f"token {cfg.github_token}"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 403:
            return []
        r.raise_for_status()
    except Exception:
        return []

    repos = []
    for item in r.json().get("items", []):
        repos.append(PoCRepo(
            name=item.get("full_name", ""),
            url=item.get("html_url", ""),
            stars=item.get("stargazers_count", 0),
            description=item.get("description") or "",
        ))
    return repos


# ─── Phase 4: TOME platform matching ──────────────────────────────────────────

_TOME_PLATFORMS: Optional[list] = None

def get_tome_platforms(cfg: Config) -> list:
    global _TOME_PLATFORMS
    if _TOME_PLATFORMS is not None:
        return _TOME_PLATFORMS

    tome_bin = TOOLS.get("tome")
    if tome_bin:
        try:
            out = subprocess.check_output(
                [tome_bin, "list", "--format", "json"],
                timeout=10, stderr=subprocess.DEVNULL
            )
            _TOME_PLATFORMS = json.loads(out)
            return _TOME_PLATFORMS
        except Exception:
            pass

    # Fallback: minimal platform list if tome not available
    _TOME_PLATFORMS = [
        {"platform": k, "shodan_dorks": {"strict": ""}, "default_ports": []}
        for k in PLATFORM_CPE
    ]
    return _TOME_PLATFORMS


def match_platforms(cve: CVERecord, nvd: NVDRecord, cfg: Config) -> list[str]:
    """Return list of platform IDs affected by this CVE."""
    matched = set()

    # Primary haystack: vendor/product fields from CISA + CPE products from NVD
    # Deliberately NOT including the full NVD description (too noisy for substring matching)
    primary = (
        cve.vendor_project.lower() + " " +
        cve.product.lower() + " " +
        " ".join(nvd.cpe_products)
    )
    # Secondary: NVD description (looser match — only for 3+ char hints to avoid noise)
    secondary = nvd.description.lower()

    for platform_id, cpe_hints in PLATFORM_CPE.items():
        for hint in cpe_hints:
            h = hint.lower()
            if h in primary:
                matched.add(platform_id)
                break
            # Allow description match only for longer, specific hints (>=7 chars)
            if len(h) >= 7 and h in secondary:
                matched.add(platform_id)
                break

    return list(matched)


# ─── Phase 5: Shodan exposure ─────────────────────────────────────────────────

def query_shodan_exposure(platform_id: str, cfg: Config) -> tuple[int, list[ExposedHost]]:
    """Return (count, hosts[:20]) using platform's strict Shodan dork.
    Tries direct API key first; falls back to Playwright authenticated session."""
    # Try TOME catalog first, then fallback dork table
    platforms = get_tome_platforms(cfg)
    dork = ""
    for p in platforms:
        if p.get("platform") == platform_id:
            dork = p.get("shodan_dorks", {}).get("strict", "")
            break
    if not dork:
        dork = PLATFORM_DORK_FALLBACK.get(platform_id, "")
    if not dork:
        return 0, []

    total = 0
    raw_hosts = []

    # Path 1: direct API key
    if cfg.shodan_api_key:
        count_url = (
            f"https://api.shodan.io/shodan/host/count"
            f"?key={cfg.shodan_api_key}&query={requests.utils.quote(dork)}"
        )
        try:
            r = requests.get(count_url, timeout=15)
            if r.status_code == 200:
                total = r.json().get("total", 0)
                if total > 0:
                    search_url = (
                        f"https://api.shodan.io/shodan/host/search"
                        f"?key={cfg.shodan_api_key}&query={requests.utils.quote(dork)}"
                        f"&fields=ip_str,port,org,hostnames,product"
                    )
                    sr = requests.get(search_url, timeout=20)
                    if sr.status_code == 200:
                        raw_hosts = sr.json().get("matches", [])[:20]
        except Exception:
            pass

    # Path 2: Playwright authenticated browser session (when API key is expired)
    if total == 0 and _PW_SHODAN:
        pw_total = _shodan_count_pw(dork)
        if pw_total is not None:
            total = pw_total
            if total > 0:
                raw_hosts = _shodan_search_pw(dork, limit=20)

    hosts = [
        ExposedHost(
            ip=m.get("ip_str", ""),
            port=m.get("port", 0),
            org=m.get("org", ""),
            hostname=(m.get("hostnames") or [""])[0],
            product=m.get("product", ""),
            platform=platform_id,
        )
        for m in raw_hosts
    ]
    return total, hosts


# ─── Phase 6: Priority scoring (book formula) ─────────────────────────────────

def score_priority(nvd: NVDRecord, poc_repos: list, date_added: str) -> tuple[float, str]:
    """
    Book formula: (cvss/10)*0.25 + (has_exploit)*0.25 + (in_cisa)*0.15 + exp(-days/30)*0.15
    Extended with exposure factor: + (has_exposure)*0.25 (replaces last 0.15, shifts to 1.0)
    """
    cvss_factor   = (nvd.cvss_score / 10.0) * 0.25
    exploit_factor = (1.0 if poc_repos else 0.0) * 0.25
    kev_factor    = 0.15  # always 1.0 since we only process CISA KEV entries
    recency_factor = 0.0
    try:
        added = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - added).days
        recency_factor = math.exp(-days / 30.0) * 0.15
    except Exception:
        pass

    score = cvss_factor + exploit_factor + kev_factor + recency_factor

    if score >= 0.80:
        level = "P1"
    elif score >= 0.60:
        level = "P2"
    elif score >= 0.40:
        level = "P3"
    else:
        level = "P4"

    return round(score, 4), level


# ─── Phase 7: aimap fingerprint ───────────────────────────────────────────────

def fingerprint_hosts(hosts: list[ExposedHost], cfg: Config) -> list[dict]:
    """Run aimap on top N hosts, return list of ScanReport dicts."""
    if cfg.dry_run or not TOOLS.get("aimap"):
        return []

    results = []
    top = hosts[:cfg.aimap_top_n]
    for host in top:
        target = host.ip
        print(f"    aimap {DIM(target)}", end="", flush=True)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            out_path = tf.name
        try:
            subprocess.run(
                [TOOLS["aimap"], "-target", target, "-o", out_path,
                 "-timeout", "8s", "-threads", "10"],
                timeout=90, capture_output=True
            )
            data = json.loads(Path(out_path).read_text())
            services = data.get("services", [])
            enum_count = len(data.get("enum_results", []))
            print(f"  {GREEN('ok')}  {len(services)} services, {enum_count} enum results")
            results.append({"host": target, "report": data})
        except Exception as e:
            print(f"  {RED('err')}  {e}")
        finally:
            Path(out_path).unlink(missing_ok=True)
        time.sleep(1)

    return results


# ─── Phase 8: winnow FP screen ────────────────────────────────────────────────

def winnow_screen(aimap_results: list, cfg: Config) -> list[dict]:
    """Screen aimap results through winnow, return PASS findings only."""
    if not aimap_results or not TOOLS.get("winnow"):
        return aimap_results

    with tempfile.TemporaryDirectory() as td:
        for i, r in enumerate(aimap_results):
            fp = Path(td) / f"aimap_{i}.json"
            fp.write_text(json.dumps(r["report"]))

        try:
            out = subprocess.check_output(
                ["python3", TOOLS["winnow"], "--json", "--passed", td],
                timeout=30, stderr=subprocess.DEVNULL
            )
            passed = json.loads(out)
            return [{"host": p["host"], "verdict": p["verdict"],
                     "check": p["check"], "severity": p["severity"]} for p in passed]
        except Exception:
            return aimap_results


# ─── Phase 9: visorlog ingest ─────────────────────────────────────────────────

def ingest_visorlog(finding: SentinelFinding, cfg: Config):
    if cfg.dry_run or not TOOLS.get("visorlog"):
        return

    for host in finding.exposed_hosts[:10]:
        try:
            subprocess.run(
                [TOOLS["visorlog"], "add",
                 "--ip", host.ip,
                 "--hostname", host.hostname or host.ip,
                 "--org", host.org or "unknown",
                 "--severity", _cvss_to_severity(finding.cvss_score),
                 "--tags", f"CVE,{finding.cve_id},{host.platform.upper()},SENTINEL",
                 "--source", "sentinel",
                 "--country", "?",
                 "--sector", "commercial"],
                timeout=10, capture_output=True
            )
        except Exception:
            pass


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "critical"
    if cvss >= 7.0: return "high"
    if cvss >= 4.0: return "medium"
    return "low"


# ─── Phase 10: ntfy alert ─────────────────────────────────────────────────────

def send_ntfy(finding: SentinelFinding, cfg: Config):
    if cfg.dry_run or not cfg.ntfy_topic:
        return

    priority_map = {"P1": 5, "P2": 4, "P3": 3, "P4": 2}
    ntfy_priority = priority_map.get(finding.priority_level, 2)

    platforms = ", ".join(finding.matched_platforms) or "unknown platform"
    title = f"{finding.priority_level}: {finding.cve_id} — {platforms}"
    body = (
        f"CVSS {finding.cvss_score} | PoC: {'yes' if finding.has_poc else 'no'} | "
        f"{finding.exposed_count:,} exposed instances\n"
        f"{finding.vendor_project} {finding.product}\n"
        f"{finding.description[:200]}"
    )

    try:
        requests.post(
            f"{cfg.ntfy_url}/{cfg.ntfy_topic}",
            data=body.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": str(ntfy_priority),
                "Tags": f"warning,{finding.priority_level.lower()},sentinel",
            },
            timeout=10,
        )
    except Exception as e:
        print(f"  {RED('ntfy err')}  {e}")


# ─── Logging ──────────────────────────────────────────────────────────────────

def log_finding(finding: SentinelFinding, cfg: Config):
    log_file = cfg.log_dir / f"sentinel-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.ndjson"
    with open(log_file, "a") as f:
        f.write(json.dumps(asdict(finding)) + "\n")


# ─── Full pipeline for one CVE ────────────────────────────────────────────────

def process_cve(cve: CVERecord, cfg: Config) -> Optional[SentinelFinding]:
    cve_id = cve.cve_id
    print(f"\n  {CYAN(cve_id)}  {DIM(cve.vendor_project)} / {cve.product}")

    # NVD enrichment
    nvd = enrich_nvd(cve_id, cfg)
    time.sleep(0.7)  # NVD rate limit (50 req/30s without key)

    # GitHub PoC
    poc_repos = search_github_poc(cve_id, cfg)
    time.sleep(0.3)

    # Platform match
    matched_platforms = match_platforms(cve, nvd, cfg)
    if not matched_platforms:
        print(f"    {DIM('no AI/ML platform match — skip')}")
        return None

    print(f"    platforms: {GREEN(', '.join(matched_platforms))}")

    # Priority scoring (before exposure — fast path to decide whether to probe)
    days_since = 0
    try:
        added = datetime.fromisoformat(cve.date_added).replace(tzinfo=timezone.utc)
        days_since = (datetime.now(timezone.utc) - added).days
    except Exception:
        pass

    priority_score, priority_level = score_priority(nvd, poc_repos, cve.date_added)
    print(f"    CVSS {nvd.cvss_score} | PoC {'yes' if poc_repos else 'no'} | "
          f"score {priority_score:.3f} → {badge(priority_level)}")

    # Shodan exposure
    total_exposed = 0
    all_hosts: list[ExposedHost] = []
    for platform_id in matched_platforms:
        print(f"    Shodan  {DIM(platform_id)}", end="", flush=True)
        count, hosts = query_shodan_exposure(platform_id, cfg)
        total_exposed += count
        all_hosts.extend(hosts)
        print(f"  {count:,} hosts")
        time.sleep(1)

    # Build finding
    finding = SentinelFinding(
        cve_id=cve_id,
        vendor_project=cve.vendor_project,
        product=cve.product,
        cvss_score=nvd.cvss_score,
        cvss_vector=nvd.cvss_vector,
        has_poc=bool(poc_repos),
        poc_count=len(poc_repos),
        poc_repos=[{"name": p.name, "url": p.url, "stars": p.stars} for p in poc_repos],
        date_added=cve.date_added,
        days_since_added=days_since,
        matched_platforms=matched_platforms,
        exposed_count=total_exposed,
        exposed_hosts=[asdict(h) for h in all_hosts[:20]],
        priority_score=priority_score,
        priority_level=priority_level,
        description=nvd.description[:500],
    )

    # aimap fingerprint (only if priority warrants + we have hosts)
    if all_hosts and priority_level in ("P1", "P2") and not cfg.dry_run:
        print(f"    {BOLD('aimap')} fingerprinting top {cfg.aimap_top_n} hosts...")
        finding.aimap_results = fingerprint_hosts(all_hosts, cfg)

        # winnow screen
        if finding.aimap_results:
            finding.aimap_results = winnow_screen(finding.aimap_results, cfg)

    # visorlog ingest
    if total_exposed > 0:
        ingest_visorlog(finding, cfg)

    # Alert
    priority_gate = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    min_gate = priority_gate.get(cfg.min_priority, 2)
    cve_gate = priority_gate.get(priority_level, 4)
    if cve_gate <= min_gate:
        print(f"    {BOLD('ntfy')} → {cfg.ntfy_topic}")
        send_ntfy(finding, cfg)

    # Log
    log_finding(finding, cfg)

    return finding


# ─── Main commands ────────────────────────────────────────────────────────────

def cmd_run(args, cfg: Config):
    state = load_state(cfg)
    processed_ids = set(state.get("processed", []))

    init_tools()
    print(f"\n{BOLD('sentinel')}  CVE-Reactive AI/ML Exposure Pipeline")
    print(DIM(f"  tools: " + "  ".join(
        f"{t}={'ok' if v else 'missing'}" for t, v in TOOLS.items()
    )))
    if cfg.dry_run:
        print(f"  {YELLOW('DRY RUN')} — no active probes, no alerts")

    while True:
        run_start = datetime.now(timezone.utc)
        print(f"\n{DIM('─'*60)}")
        print(f"  {run_start.strftime('%Y-%m-%dT%H:%M:%SZ')}")

        cves = poll_cisa_kev(cfg)
        new_cves = [c for c in cves if c.cve_id not in processed_ids]
        print(f"  {len(new_cves)} new CVEs to process ({len(processed_ids)} already seen)")

        findings = []
        for cve in new_cves:
            result = process_cve(cve, cfg)
            processed_ids.add(cve.cve_id)
            if result:
                findings.append(result)
            # Checkpoint state after each CVE
            state["processed"] = list(processed_ids)
            save_state(cfg, state)

        # Run summary
        ai_hits = [f for f in findings if f.matched_platforms]
        print(f"\n{BOLD('Run complete')}")
        print(f"  {len(new_cves)} CVEs processed | {len(ai_hits)} AI/ML matches")
        for f in sorted(ai_hits, key=lambda x: x.priority_score, reverse=True):
            print(f"  {badge(f.priority_level)}  {f.cve_id}  "
                  f"{', '.join(f.matched_platforms)}  "
                  f"{f.exposed_count:,} exposed  CVSS {f.cvss_score}")

        state["runs"].append({
            "timestamp": run_start.isoformat(),
            "new_cves": len(new_cves),
            "ai_matches": len(ai_hits),
        })
        save_state(cfg, state)

        if not args.loop:
            break

        print(f"\n  {DIM('next run in 6h...')}")
        time.sleep(6 * 3600)


def cmd_status(args, cfg: Config):
    state = load_state(cfg)
    print(f"\n{BOLD('sentinel status')}")
    print(f"  processed CVEs: {len(state.get('processed', []))}")
    print(f"  runs: {len(state.get('runs', []))}")

    # Show recent log entries
    log_files = sorted(cfg.log_dir.glob("sentinel-*.ndjson"), reverse=True)
    if not log_files:
        print("  no log files found")
        return

    print(f"\n  Recent findings ({log_files[0].name}):")
    findings = []
    with open(log_files[0]) as f:
        for line in f:
            try:
                findings.append(json.loads(line))
            except Exception:
                pass

    for fn in sorted(findings, key=lambda x: x.get("priority_score", 0), reverse=True)[:20]:
        print(f"  {badge(fn.get('priority_level','P4'))}  "
              f"{fn.get('cve_id','?')}  "
              f"{','.join(fn.get('matched_platforms',[])):<20}  "
              f"CVSS {fn.get('cvss_score',0):<5}  "
              f"{fn.get('exposed_count',0):>6,} exposed")


def cmd_reset(args, cfg: Config):
    state = load_state(cfg)
    n = len(state.get("processed", []))
    state["processed"] = []
    save_state(cfg, state)
    print(f"  cleared {n} processed CVE IDs")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="sentinel — CVE-Reactive AI/ML Infrastructure Exposure Pipeline"
    )
    sub = parser.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="Run the full pipeline")
    p_run.add_argument("--loop", action="store_true", help="Repeat every 6h")
    p_run.add_argument("--dry-run", action="store_true", help="No active probes or alerts")

    sub.add_parser("status", help="Show recent findings")
    sub.add_parser("reset", help="Clear processed-CVE state")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(0)

    cfg = Config.load()
    if hasattr(args, "dry_run") and args.dry_run:
        cfg.dry_run = True

    if args.cmd == "run":
        cmd_run(args, cfg)
    elif args.cmd == "status":
        cmd_status(args, cfg)
    elif args.cmd == "reset":
        cmd_reset(args, cfg)


if __name__ == "__main__":
    main()
