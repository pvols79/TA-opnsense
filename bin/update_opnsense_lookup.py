#!/usr/bin/env python3

import os
import sys
import csv
import io
import re
import json
import requests
import urllib3
import configparser
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOOKUP_FIELDS = [
    "join_key",
    "join_key_type",
    "rule_action",
    "rule_desc",
    "rule_interface",
    "rule_source",
    "pf_rule_number",
    "rule_tracker",
    "rule_uuid",
    "rule_sequence",
    "rule_enabled",
]


def log(msg: str) -> None:
    print(msg)


def get_config() -> Dict[str, Any]:
    config = configparser.ConfigParser()
    bin_dir = os.path.dirname(os.path.realpath(__file__))
    app_root = os.path.abspath(os.path.join(bin_dir, ".."))
    config_path = os.path.join(app_root, "local", "opnsense_settings.conf")
    lookup_path = os.path.join(app_root, "lookups", "opnsense_rules.csv")

    if not os.path.exists(config_path):
        log(f"CRITICAL: Config not found at {config_path}")
        sys.exit(1)

    config.read(config_path)

    selected_section = None
    for section in config.sections():
        options = set(config.options(section))
        if all(k in options for k in ("api_key", "api_secret", "base_url")):
            selected_section = section
            break

    if not selected_section:
        log("CRITICAL: No section with api_key/api_secret/base_url found in opnsense_settings.conf")
        sys.exit(1)

    verify_ssl = False
    if config.has_option(selected_section, "verify_ssl"):
        raw_verify = config.get(selected_section, "verify_ssl").strip().lower()
        verify_ssl = raw_verify in ("1", "true", "yes", "on")

    return {
        "api_key": config.get(selected_section, "api_key").strip(),
        "api_secret": config.get(selected_section, "api_secret").strip(),
        "base_url": config.get(selected_section, "base_url").strip().rstrip("/"),
        "verify_ssl": verify_ssl,
        "lookup_path": lookup_path,
    }


def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def normalize_action(raw: Any) -> str:
    a = str(raw or "").strip().lower()

    if a in ("pass", "block", "reject", "rdr", "nat", "binat", "npt"):
        return a

    if a in ("allow", "allowed", "accept", "permit"):
        return "pass"

    if a in ("deny", "denied", "drop"):
        return "block"

    return a or "pass"


def normalize_boolish(raw: Any) -> str:
    v = str(raw or "").strip().lower()
    if v in ("1", "true", "yes", "on", "enabled"):
        return "1"
    if v in ("0", "false", "no", "off", "disabled"):
        return "0"
    return ""


def clean_desc(value: Any) -> str:
    desc = str(value or "").strip().strip('"')
    return desc if desc else "OPNsense Rule"


def first_nonempty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        s = str(value).strip()
        if s:
            return s
    return ""


def normalize_interface(value: Any) -> str:
    if value is None:
        return "unknown"

    if isinstance(value, list):
        items = [str(x).strip() for x in value if str(x).strip()]
        return ",".join(items) if items else "unknown"

    s = str(value).strip()
    return s if s else "unknown"


def source_rank(source: str) -> int:
    ranks = {
        "mvc_filter": 500,
        "download_rules": 450,
        "mvc_nat": 400,
        "diag_runtime_json": 200,
        "diag_runtime_text": 150,
    }
    return ranks.get(source, 0)


def new_rule_stub() -> Dict[str, str]:
    return {
        "rule_uuid": "",
        "rule_tracker": "",
        "pf_rule_number": "",
        "rule_action": "pass",
        "rule_desc": "OPNsense Rule",
        "rule_interface": "unknown",
        "rule_source": "",
        "rule_sequence": "",
        "rule_enabled": "",
    }


def merge_rule(preferred: Dict[str, str], incoming: Dict[str, str]) -> Dict[str, str]:
    current = dict(preferred)

    if source_rank(incoming.get("rule_source", "")) > source_rank(current.get("rule_source", "")):
        winner = incoming
        loser = current
    else:
        winner = current
        loser = incoming

    merged = dict(winner)

    for field in (
        "rule_uuid",
        "rule_tracker",
        "pf_rule_number",
        "rule_sequence",
        "rule_enabled",
        "rule_interface",
        "rule_desc",
        "rule_action",
        "rule_source",
    ):
        if not str(merged.get(field, "")).strip():
            merged[field] = loser.get(field, "")

    desc_a = str(current.get("rule_desc", "")).strip()
    desc_b = str(incoming.get("rule_desc", "")).strip()
    if desc_b and desc_b != "OPNsense Rule" and len(desc_b) > len(desc_a):
        merged["rule_desc"] = desc_b

    if merged.get("rule_interface", "") == "unknown":
        merged["rule_interface"] = first_nonempty(
            current.get("rule_interface", ""),
            incoming.get("rule_interface", ""),
            "unknown",
        )

    return merged


def http_get(
    url: str,
    auth: Tuple[str, str],
    verify_ssl: bool,
    timeout: int = 20,
) -> Optional[requests.Response]:
    try:
        return requests.get(url, auth=auth, verify=verify_ssl, timeout=timeout)
    except Exception as e:
        log(f"[-] GET failed: {url} :: {e}")
        return None


def http_post(
    url: str,
    auth: Tuple[str, str],
    verify_ssl: bool,
    data: Optional[Dict[str, Any]] = None,
    timeout: int = 20,
) -> Optional[requests.Response]:
    try:
        return requests.post(url, auth=auth, verify=verify_ssl, data=data or {}, timeout=timeout)
    except Exception as e:
        log(f"[-] POST failed: {url} :: {e}")
        return None


def get_real_api_ids(conf: Dict[str, Any], auth: Tuple[str, str]) -> List[str]:
    targets = ["floating"]
    url = f"{conf['base_url']}/api/firewall/filter/get_interface_list"
    r = http_get(url, auth, conf["verify_ssl"], timeout=10)
    if r is not None and r.status_code == 200:
        data = safe_json(r) or {}
        for section in ("interfaces", "groups"):
            items = (data.get(section, {}) or {}).get("items", {})
            if isinstance(items, dict):
                for internal_id in items.keys():
                    if internal_id not in targets:
                        targets.append(internal_id)
    elif r is not None:
        log(f"[-] Interface discovery returned HTTP {r.status_code}: {url}")

    for fallback in (
        "lan", "wan", "opt1", "opt2", "opt3", "opt4", "opt5", "opt6", "opt7",
        "openvpn", "wireguard"
    ):
        if fallback not in targets:
            targets.append(fallback)

    return targets


def normalize_tracker(value: Any) -> str:
    s = str(value or "").strip()
    if not s or s == "0":
        return ""
    if s.isdigit():
        return s
    m = re.search(r"(\d{6,12})", s)
    return m.group(1) if m else s


def extract_pf_rule_number_from_value(value: Any) -> str:
    s = str(value or "").strip()
    if s.isdigit():
        return s
    m = re.search(r"\b(\d+)\b", s)
    return m.group(1) if m else ""


def extract_pf_rule_number(rule: Dict[str, Any]) -> str:
    for key in (
        "rulenr",
        "rule_nr",
        "rule",
        "nr",
        "rulenum",
        "rulenumber",
        "pf_rule_number",
        "rule_number",
        "id",
    ):
        if key in rule:
            candidate = extract_pf_rule_number_from_value(rule.get(key))
            if candidate:
                return candidate
    return ""


def parse_mvc_rule(row: Dict[str, Any], src_type: str, forced_action: Optional[str] = None) -> Dict[str, str]:
    rule = new_rule_stub()

    rule["rule_uuid"] = first_nonempty(row.get("uuid"))
    rule["rule_tracker"] = normalize_tracker(row.get("tracker"))
    rule["pf_rule_number"] = extract_pf_rule_number(row)
    rule["rule_action"] = normalize_action(forced_action or row.get("action"))
    rule["rule_desc"] = clean_desc(
        first_nonempty(
            row.get("description"),
            row.get("descr"),
            row.get("label"),
            row.get("name"),
        )
    )
    rule["rule_interface"] = normalize_interface(
        first_nonempty(row.get("interface"), row.get("__src_iface"))
    )
    rule["rule_source"] = src_type
    rule["rule_sequence"] = first_nonempty(row.get("sequence"), row.get("seq"), row.get("sort_order"))
    rule["rule_enabled"] = normalize_boolish(first_nonempty(row.get("enabled")))

    if not rule["rule_enabled"]:
        disabled = normalize_boolish(row.get("disabled"))
        if disabled == "1":
            rule["rule_enabled"] = "0"

    return rule


def parse_download_rule(row: Dict[str, Any]) -> Dict[str, str]:
    rule = new_rule_stub()

    rule["rule_uuid"] = first_nonempty(row.get("@uuid"), row.get("uuid"))
    rule["rule_tracker"] = normalize_tracker(row.get("tracker"))
    rule["pf_rule_number"] = extract_pf_rule_number(row)
    rule["rule_action"] = normalize_action(row.get("action"))
    rule["rule_desc"] = clean_desc(row.get("description"))
    rule["rule_interface"] = normalize_interface(row.get("interface"))
    rule["rule_source"] = "download_rules"
    rule["rule_sequence"] = first_nonempty(row.get("sequence"))
    rule["rule_enabled"] = normalize_boolish(row.get("enabled"))

    return rule


def flatten_diag_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]

    if isinstance(payload, dict):
        for key in ("rows", "items", "rules", "data", "result"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                return [x for x in candidate if isinstance(x, dict)]
            if isinstance(candidate, dict):
                for subkey in ("rows", "items", "rules", "data"):
                    nested = candidate.get(subkey)
                    if isinstance(nested, list):
                        return [x for x in nested if isinstance(x, dict)]

    return []


def parse_diag_rule_json(row: Dict[str, Any]) -> Dict[str, str]:
    rule = new_rule_stub()

    tracker = normalize_tracker(
        first_nonempty(row.get("tracker"), row.get("trackerid"), row.get("tracker_id"))
    )
    label = clean_desc(
        first_nonempty(
            row.get("label"),
            row.get("description"),
            row.get("descr"),
            row.get("name"),
        )
    )

    rule["rule_uuid"] = first_nonempty(row.get("uuid"))
    rule["rule_tracker"] = tracker
    rule["pf_rule_number"] = extract_pf_rule_number(row)
    rule["rule_action"] = normalize_action(first_nonempty(row.get("type"), row.get("action")))
    rule["rule_desc"] = label
    rule["rule_interface"] = normalize_interface(
        first_nonempty(row.get("interface"), row.get("if"), row.get("iface"))
    )
    rule["rule_source"] = "diag_runtime_json"
    rule["rule_sequence"] = first_nonempty(row.get("sequence"))
    rule["rule_enabled"] = normalize_boolish(row.get("enabled"))

    return rule


PF_RULE_LINE_RE = re.compile(
    r"""
    ^\s*
    @(?P<pfnum>\d+)
    (?:\([^)]*\))?
    \s+
    (?P<action>pass|block|reject|match|rdr|nat|binat)\b
    .*?
    \bon\s+(?P<interface>[A-Za-z0-9_.:-]+)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

PF_LABEL_RE = re.compile(r'label\s+"([^"]+)"', re.IGNORECASE)
PF_TRACKER_RE = re.compile(r'tracker\s+(\d+)', re.IGNORECASE)


def parse_diag_rules_text(text: str) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []

    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw or not raw.startswith("@"):
            continue

        m = PF_RULE_LINE_RE.search(raw)
        if not m:
            continue

        label_match = PF_LABEL_RE.search(raw)
        tracker_match = PF_TRACKER_RE.search(raw)

        rule = new_rule_stub()
        rule["pf_rule_number"] = m.group("pfnum")
        rule["rule_action"] = normalize_action(m.group("action"))
        rule["rule_interface"] = normalize_interface(m.group("interface"))
        rule["rule_desc"] = clean_desc(label_match.group(1) if label_match else "")
        rule["rule_tracker"] = normalize_tracker(tracker_match.group(1) if tracker_match else "")
        rule["rule_source"] = "diag_runtime_text"
        rules.append(rule)

    return rules


def collect_mvc_filter_rules(conf: Dict[str, Any], auth: Tuple[str, str]) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []
    search_targets = get_real_api_ids(conf, auth)

    log("\n" + "=" * 70)
    log("STAGE 1: ENUMERATE INTERFACES")
    log("=" * 70)
    log(f"[+] Discovered {len(search_targets)} logical segments.")

    log("\n" + "=" * 70)
    log("STAGE 2: COLLECT FIREWALL FILTER RULES (MVC)")
    log("=" * 70)

    for target in search_targets:
        url = f"{conf['base_url']}/api/firewall/filter/search_rule"
        r = http_post(
            url,
            auth,
            conf["verify_ssl"],
            data={"rowCount": -1, "interface": target, "show_all": 1},
            timeout=20,
        )
        if r is None:
            continue

        if r.status_code != 200:
            log(f"[-] mvc filter search_rule HTTP {r.status_code} for interface={target}")
            continue

        payload = safe_json(r) or {}
        rows = payload.get("rows", []) or []
        captured = 0

        for row in rows:
            if not isinstance(row, dict):
                continue
            row["__src_iface"] = target
            rules.append(parse_mvc_rule(row, "mvc_filter"))
            captured += 1

        if captured:
            log(f"    -> {target.ljust(15)}: captured {captured} rules")

    return rules


def collect_mvc_nat_rules(conf: Dict[str, Any], auth: Tuple[str, str]) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []

    log("\n" + "=" * 70)
    log("STAGE 3: COLLECT NAT RULES (MVC)")
    log("=" * 70)

    nat_missions = [
        ("d_nat", "rdr"),
        ("source_nat", "nat"),
        ("one_to_one", "binat"),
        ("npt", "npt"),
    ]

    for controller, forced_action in nat_missions:
        url = f"{conf['base_url']}/api/firewall/{controller}/search_rule"
        r = http_post(
            url,
            auth,
            conf["verify_ssl"],
            data={"rowCount": -1},
            timeout=20,
        )
        if r is None:
            continue

        if r.status_code != 200:
            log(f"[-] {controller} search_rule HTTP {r.status_code}")
            continue

        payload = safe_json(r) or {}
        rows = payload.get("rows", []) or []
        captured = 0

        for row in rows:
            if not isinstance(row, dict):
                continue
            rules.append(parse_mvc_rule(row, "mvc_nat", forced_action=forced_action))
            captured += 1

        log(f"[+] {controller.ljust(15)}: captured {captured} rules")

    return rules


def parse_csv_text(csv_text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    sio = io.StringIO(csv_text)
    reader = csv.DictReader(sio, delimiter=";")
    for row in reader:
        if not isinstance(row, dict):
            continue
        rows.append({str(k or "").strip(): str(v or "").strip() for k, v in row.items()})
    return rows


def collect_download_rules(conf: Dict[str, Any], auth: Tuple[str, str]) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []

    log("\n" + "=" * 70)
    log("STAGE 4: COLLECT DOWNLOAD_RULES EXPORT")
    log("=" * 70)

    candidate_urls = [
        f"{conf['base_url']}/api/firewall/filter/download_rules",
        f"{conf['base_url']}/api/firewall/migration/download_rules",
    ]

    used_url = ""
    response_text = ""

    for url in candidate_urls:
        r = http_get(url, auth, conf["verify_ssl"], timeout=30)
        if r is None:
            continue

        if r.status_code != 200:
            log(f"[-] download_rules candidate returned HTTP {r.status_code}: {url}")
            continue

        text = r.text or ""
        content_type = str(r.headers.get("Content-Type", "")).lower()

        if "@uuid;" in text or "description;" in text or ("csv" in content_type and text.strip()):
            used_url = url
            response_text = text
            break

    if not response_text:
        log("[-] No usable download_rules CSV returned from tested endpoints.")
        return rules

    csv_rows = parse_csv_text(response_text)
    for row in csv_rows:
        rules.append(parse_download_rule(row))

    log(f"[+] download_rules: captured {len(rules)} rows from {used_url}")
    return rules


def collect_diag_rules(conf: Dict[str, Any], auth: Tuple[str, str]) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []

    log("\n" + "=" * 70)
    log("STAGE 5: COLLECT DIAGNOSTICS RUNTIME RULES")
    log("=" * 70)

    # First try JSON-ish diagnostics endpoints
    json_candidate_urls = [
        f"{conf['base_url']}/api/diagnostics/firewall/list_rules",
        f"{conf['base_url']}/api/diagnostics/firewall/pf/rules",
    ]

    json_rows_seen = 0
    pfnum_count = 0
    tracker_count = 0

    for url in json_candidate_urls:
        r = http_get(url, auth, conf["verify_ssl"], timeout=30)
        if r is None:
            continue
        if r.status_code != 200:
            log(f"[-] diagnostics candidate returned HTTP {r.status_code}: {url}")
            continue

        payload = safe_json(r)
        rows = flatten_diag_payload(payload)
        if rows:
            added = 0
            for row in rows:
                normalized = parse_diag_rule_json(row)
                rules.append(normalized)
                json_rows_seen += 1
                if normalized.get("pf_rule_number"):
                    pfnum_count += 1
                if normalized.get("rule_tracker"):
                    tracker_count += 1
                added += 1
            log(f"[+] diagnostics JSON: captured {added} rows from {url}")

    # Then try text/raw PF rules
    text_candidate_urls = [
        f"{conf['base_url']}/api/diagnostics/firewall/pf/rules",
    ]

    text_rows_seen = 0
    text_pfnum_count = 0
    text_tracker_count = 0

    for url in text_candidate_urls:
        r = http_get(url, auth, conf["verify_ssl"], timeout=30)
        if r is None:
            continue
        if r.status_code != 200:
            continue

        parsed_text_rules = parse_diag_rules_text(r.text or "")
        if parsed_text_rules:
            rules.extend(parsed_text_rules)
            text_rows_seen += len(parsed_text_rules)
            text_pfnum_count += sum(1 for x in parsed_text_rules if x.get("pf_rule_number"))
            text_tracker_count += sum(1 for x in parsed_text_rules if x.get("rule_tracker"))
            log(f"[+] diagnostics text: captured {len(parsed_text_rules)} rows from {url}")

    log(
        "[+] diagnostics summary: "
        f"json_rows={json_rows_seen}, json_pfnums={pfnum_count}, json_trackers={tracker_count}, "
        f"text_rows={text_rows_seen}, text_pfnums={text_pfnum_count}, text_trackers={text_tracker_count}"
    )

    return rules


def build_rule_candidates(rule: Dict[str, str]) -> List[Tuple[str, str]]:
    keys: List[Tuple[str, str]] = []

    pf_rule_number = str(rule.get("pf_rule_number", "")).strip()
    tracker = normalize_tracker(rule.get("rule_tracker", ""))
    uuid = str(rule.get("rule_uuid", "")).strip()

    # Prefer runtime-friendly correlation keys first
    if pf_rule_number and pf_rule_number.isdigit():
        keys.append(("pf_rule_number", pf_rule_number))

    if tracker:
        keys.append(("tracker", tracker))

    if uuid:
        keys.append(("uuid", uuid))

    return keys


def build_primary_signature(rule: Dict[str, str]) -> Tuple[str, str, str]:
    tracker = normalize_tracker(rule.get("rule_tracker", ""))
    uuid = str(rule.get("rule_uuid", "")).strip()
    pf_rule_number = str(rule.get("pf_rule_number", "")).strip()
    action = normalize_action(rule.get("rule_action", "pass"))

    if tracker:
        key = f"tracker:{tracker}"
    elif uuid:
        key = f"uuid:{uuid}"
    elif pf_rule_number:
        key = f"pf:{pf_rule_number}"
    else:
        key = "desc:" + "|".join([
            clean_desc(rule.get("rule_desc")),
            normalize_interface(rule.get("rule_interface")),
            first_nonempty(rule.get("rule_sequence"), ""),
        ])

    return (key, action, normalize_interface(rule.get("rule_interface")))


def build_secondary_signature(rule: Dict[str, str]) -> Tuple[str, str, str]:
    action = normalize_action(rule.get("rule_action", "pass"))
    return (
        clean_desc(rule.get("rule_desc")),
        action,
        normalize_interface(rule.get("rule_interface")),
    )


def build_lookup_rows(collected_rules: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    source_counts: Dict[str, int] = {}

    # First merge exact-ish logical rules
    merged_primary: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    for rule in collected_rules:
        source = rule.get("rule_source", "") or "unknown"
        source_counts[source] = source_counts.get(source, 0) + 1

        sig = build_primary_signature(rule)
        existing = merged_primary.get(sig)
        if existing:
            merged_primary[sig] = merge_rule(existing, rule)
        else:
            merged_primary[sig] = dict(rule)

    # Then merge diagnostics-only rows into named rows when there is an obvious match
    merged_secondary: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    for rule in merged_primary.values():
        sig2 = build_secondary_signature(rule)
        existing = merged_secondary.get(sig2)
        if existing:
            merged_secondary[sig2] = merge_rule(existing, rule)
        else:
            merged_secondary[sig2] = dict(rule)

    # Finally emit one row per usable correlation key
    final_rows_by_key: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    emitted_pf = 0
    emitted_tracker = 0
    emitted_uuid = 0

    for merged_rule in merged_secondary.values():
        candidates = build_rule_candidates(merged_rule)
        if not candidates:
            continue

        for join_key_type, join_key in candidates:
            row = {
                "join_key": join_key,
                "join_key_type": join_key_type,
                "rule_action": normalize_action(merged_rule.get("rule_action", "pass")),
                "rule_desc": clean_desc(merged_rule.get("rule_desc")),
                "rule_interface": normalize_interface(merged_rule.get("rule_interface")),
                "rule_source": merged_rule.get("rule_source", ""),
                "pf_rule_number": str(merged_rule.get("pf_rule_number", "")).strip(),
                "rule_tracker": normalize_tracker(merged_rule.get("rule_tracker", "")),
                "rule_uuid": str(merged_rule.get("rule_uuid", "")).strip(),
                "rule_sequence": str(merged_rule.get("rule_sequence", "")).strip(),
                "rule_enabled": str(merged_rule.get("rule_enabled", "")).strip(),
            }

            dedupe_key = (row["join_key_type"], row["join_key"], row["rule_action"])
            existing = final_rows_by_key.get(dedupe_key)
            if existing:
                incumbent = {
                    "rule_source": existing.get("rule_source", ""),
                    "rule_desc": existing.get("rule_desc", ""),
                    "rule_interface": existing.get("rule_interface", ""),
                    "rule_uuid": existing.get("rule_uuid", ""),
                    "rule_tracker": existing.get("rule_tracker", ""),
                    "pf_rule_number": existing.get("pf_rule_number", ""),
                    "rule_sequence": existing.get("rule_sequence", ""),
                    "rule_enabled": existing.get("rule_enabled", ""),
                    "rule_action": existing.get("rule_action", ""),
                }
                merged = merge_rule(incumbent, row)
                row.update(merged)

            final_rows_by_key[dedupe_key] = row

    final_rows = sorted(
        final_rows_by_key.values(),
        key=lambda r: (
            r["join_key_type"],
            r["join_key"],
            r["rule_action"],
            r["rule_interface"],
            r["rule_desc"].lower(),
        ),
    )

    for row in final_rows:
        if row["join_key_type"] == "pf_rule_number":
            emitted_pf += 1
        elif row["join_key_type"] == "tracker":
            emitted_tracker += 1
        elif row["join_key_type"] == "uuid":
            emitted_uuid += 1

    stats = {
        "raw_total": len(collected_rules),
        "logical_primary_total": len(merged_primary),
        "logical_secondary_total": len(merged_secondary),
        "lookup_row_total": len(final_rows),
        "emitted_pf_rule_number_rows": emitted_pf,
        "emitted_tracker_rows": emitted_tracker,
        "emitted_uuid_rows": emitted_uuid,
    }
    stats.update({f"src_{k}": v for k, v in sorted(source_counts.items())})

    return final_rows, stats


def write_lookup(path: str, rows: List[Dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=LOOKUP_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in LOOKUP_FIELDS})


def update_lookup() -> None:
    conf = get_config()
    auth = (conf["api_key"], conf["api_secret"])

    collected_rules: List[Dict[str, str]] = []
    collected_rules.extend(collect_mvc_filter_rules(conf, auth))
    collected_rules.extend(collect_mvc_nat_rules(conf, auth))
    collected_rules.extend(collect_download_rules(conf, auth))
    collected_rules.extend(collect_diag_rules(conf, auth))

    log("\n" + "=" * 70)
    log("STAGE 6: MERGE & DEDUPLICATE")
    log("=" * 70)

    final_rows, stats = build_lookup_rows(collected_rules)

    log(f"[+] Raw rows collected             : {stats.get('raw_total', 0)}")
    log(f"[+] Logical primary rules         : {stats.get('logical_primary_total', 0)}")
    log(f"[+] Logical secondary rules       : {stats.get('logical_secondary_total', 0)}")
    log(f"[+] Final lookup rows written     : {stats.get('lookup_row_total', 0)}")
    log(f"[+] Emitted pf_rule_number rows   : {stats.get('emitted_pf_rule_number_rows', 0)}")
    log(f"[+] Emitted tracker rows          : {stats.get('emitted_tracker_rows', 0)}")
    log(f"[+] Emitted uuid rows             : {stats.get('emitted_uuid_rows', 0)}")

    for key in sorted(stats.keys()):
        if key.startswith("src_"):
            log(f"    - {key[4:]:<22}: {stats[key]}")

    log("\n" + "=" * 70)
    log("STAGE 7: WRITE LOOKUP FILE")
    log("=" * 70)

    try:
        write_lookup(conf["lookup_path"], final_rows)
        log(f"[+] Successfully saved {len(final_rows)} rows to: {conf['lookup_path']}")
    except Exception as e:
        log(f"[!] File write error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    update_lookup()