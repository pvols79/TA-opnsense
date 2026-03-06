#!/usr/bin/env python3
import os
import sys
import csv
import requests
import urllib3
import configparser
import re
from typing import Any, Dict, List, Optional, Tuple

# Disable SSL warnings (common for internal OPNsense with self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_config() -> Dict[str, str]:
    """
    Reads local/opnsense_settings.conf (required) and returns api_key/api_secret/base_url + lookup path.
    """
    config = configparser.ConfigParser()
    bin_dir = os.path.dirname(os.path.realpath(__file__))
    app_root = os.path.abspath(os.path.join(bin_dir, ".."))
    config_path = os.path.join(app_root, "local", "opnsense_settings.conf")
    lookup_path = os.path.join(app_root, "lookups", "opnsense_rules.csv")

    if not os.path.exists(config_path):
        print(f"CRITICAL: Config not found at {config_path}")
        sys.exit(1)

    config.read(config_path)
    settings: Dict[str, str] = {}

    for section in config.sections():
        options = set(config.options(section))
        if all(k in options for k in ("api_key", "api_secret", "base_url")):
            settings = {
                "api_key": config.get(section, "api_key").strip(),
                "api_secret": config.get(section, "api_secret").strip(),
                "base_url": config.get(section, "base_url").strip().rstrip("/"),
                "lookup_path": lookup_path,
            }
            break

    if not settings:
        print("CRITICAL: No section with api_key/api_secret/base_url found in opnsense_settings.conf")
        sys.exit(1)

    return settings


def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def get_real_api_ids(conf: Dict[str, str], auth: Tuple[str, str]) -> List[str]:
    """
    PRESERVED: This logic successfully finds your logical segments.
    """
    targets = ["floating"]
    try:
        r = requests.get(
            f"{conf['base_url']}/api/firewall/filter/get_interface_list",
            auth=auth,
            verify=False,
            timeout=10,
        )
        if r.status_code == 200:
            data = safe_json(r) or {}
            for section in ("interfaces", "groups"):
                items = (data.get(section, {}) or {}).get("items", {})
                if isinstance(items, dict):
                    for internal_id in items.keys():
                        if internal_id not in targets:
                            targets.append(internal_id)
    except Exception:
        pass

    # Fallbacks commonly present on many systems
    for fallback in ("lan", "wan", "opt1", "opt2", "opt3", "opt4", "opt5"):
        if fallback not in targets:
            targets.append(fallback)

    return targets


def normalize_action(raw: str) -> str:
    """
    Keep pf-ish actions where possible to support composite matching against filterlog action_raw:
    pass/block/reject/rdr/nat/binat/npt
    """
    a = (raw or "pass").strip().lower()

    # keep explicit pf-style actions
    if a in ("pass", "block", "reject", "rdr", "nat", "binat", "npt"):
        return a

    # common aliases
    if a in ("allow", "allowed", "accept", "permit"):
        return "pass"
    if a in ("deny", "denied", "drop"):
        return "block"

    # safe default
    return "pass"


def clean_desc(label: str, tracker: str) -> str:
    label = label or ""
    tracker = tracker or ""

    if tracker and tracker != "0":
        # remove tracker substring if present
        cleaned = label.replace(tracker, "").strip()
        return cleaned if cleaned else label.strip()

    return label.strip()


def extract_tracker_from_label(label: str) -> Optional[str]:
    """
    Try to extract a numeric tracker-like token from the label prefix.
    (Tracker formats vary; allow a wider digit range than just 10.)
    Example: "1570123456 some description"
    """
    if not label:
        return None
    m = re.match(r"^(\d{6,12})\s+.*", label)
    if not m:
        return None
    return m.group(1)


def update_lookup() -> None:
    conf = get_config()
    auth = (conf["api_key"], conf["api_secret"])

    # Store all captured data in a flat list before merging
    raw_rules: List[Dict[str, Any]] = []

    print("\n" + "=" * 70)
    print("STAGE 1: ENUMERATE INTERFACES")
    print("=" * 70)
    search_targets = get_real_api_ids(conf, auth)
    print(f"[+] Discovered {len(search_targets)} logical segments.")

    print("\n" + "=" * 70)
    print("STAGE 2: COLLECT FIREWALL INTERFACE RULES (MVC)")
    print("=" * 70)
    for target in search_targets:
        url = (
            f"{conf['base_url']}/api/firewall/filter/search_rule"
            f"?rowCount=-1&interface={target}&show_all=1"
        )
        try:
            r = requests.post(url, auth=auth, verify=False, timeout=15)
            if r.status_code != 200:
                continue
            rows = (safe_json(r) or {}).get("rows", []) or []
            for row in rows:
                row["__src_type"] = "filter"
                row["__src_iface"] = target
                raw_rules.append(row)
            if rows:
                print(f"    -> {target.ljust(15)}: Captured {len(rows)} rules")
        except Exception:
            continue

    print("\n" + "=" * 70)
    print("STAGE 3: COLLECT NAT RULES (D-NAT, S-NAT, 1:1, NPT)")
    print("=" * 70)

    # NOTE: These MVC endpoints typically cover Automation rules; classic Outbound NAT may not appear here.
    nat_missions = [
        ("d_nat", "rdr"),       # Port Forwards / Destination NAT
        ("source_nat", "nat"),  # Source NAT (Automation, not always Outbound NAT)
        ("one_to_one", "binat"),
        ("npt", "npt"),
    ]

    for ctrl, forced_act in nat_missions:
        url = f"{conf['base_url']}/api/firewall/{ctrl}/search_rule?rowCount=-1"
        try:
            r = requests.post(url, auth=auth, verify=False, timeout=15)
            if r.status_code != 200:
                continue
            rows = (safe_json(r) or {}).get("rows", []) or []
            for row in rows:
                row["__src_type"] = "nat"
                row["__forced_act"] = forced_act
                raw_rules.append(row)
            print(f"[+] {ctrl.ljust(15)}: Captured {len(rows)} rules")
        except Exception:
            continue

    print("\n" + "=" * 70)
    print("STAGE 4: GLOBAL DIAGNOSTICS SWEEP (PULL ACTIVE PF RULES)")
    print("=" * 70)

    diag_url = f"{conf['base_url']}/api/diagnostics/firewall/list_rules"
    diag_count = 0

    try:
        r = requests.get(diag_url, auth=auth, verify=False, timeout=20)
        if r.status_code == 200:
            rules = safe_json(r) or []
            if isinstance(rules, list):
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue

                    label = str(rule.get("label", "") or "")
                    tracker = str(rule.get("tracker", "") or "").strip()

                    # Some systems embed tracker in label; if missing or 0, try to extract.
                    if not tracker or tracker == "0":
                        extracted = extract_tracker_from_label(label)
                        if extracted:
                            tracker = extracted

                    desc = clean_desc(label, tracker)

                    # Attempt to detect a pf rule number field (varies by version).
                    pf_rule_number: Optional[str] = None
                    for k in ("rulenr", "rule_nr", "rule", "nr", "rulenum", "rulenumber"):
                        v = rule.get(k)
                        if v is None:
                            continue
                        sv = str(v).strip()
                        if sv.isdigit():
                            pf_rule_number = sv
                            break

                    raw_rules.append(
                        {
                            "__src_type": "diag",
                            "tracker": tracker,
                            "pf_rule_number": pf_rule_number,
                            "action": rule.get("type", "pass"),
                            "description": desc or (f"System Rule {tracker}" if tracker else "System Rule"),
                            "interface": rule.get("interface", "unknown"),
                        }
                    )
                    diag_count += 1

            print(f"[+] Diagnostics: Captured {diag_count} active engine rules.")
        else:
            print(f"[-] Diagnostics: HTTP {r.status_code}")
    except Exception as e:
        print(f"[-] Diagnostics Sweep Failed: {e}")

    print("\n" + "=" * 70)
    print("STAGE 5: CORRELATION MAPPING & DEDUPLICATION")
    print("=" * 70)

    # Final lookup rows keyed by (join_key, rule_action)
    final_rows: Dict[Tuple[str, str], Dict[str, str]] = {}

    def add_row(join_key: Optional[str], action: str, desc: str, iface: str) -> None:
        if not join_key:
            return
        jk = str(join_key).strip()
        if not jk:
            return

        key = (jk, action)
        # Prefer non-diag rules over diag if there is a collision, because MVC rules often have better descriptions.
        existing = final_rows.get(key)
        if existing:
            # If existing is diag-ish and this is non-diag, replace; else keep existing.
            if existing.get("__src_type") == "diag" and current_src_type != "diag":
                pass
            else:
                return

        final_rows[key] = {
            "join_key": jk,
            "rule_action": action,
            "rule_desc": desc or "OPNsense Rule",
            "rule_interface": iface or "unknown",
            "__src_type": current_src_type,  # internal, removed before writing
        }

    for rule in raw_rules:
        current_src_type = str(rule.get("__src_type", "") or "")

        # Action
        if rule.get("__forced_act"):
            action = str(rule.get("__forced_act")).strip().lower()
        else:
            action = normalize_action(str(rule.get("action", "pass") or "pass"))

        # Desc / iface
        desc = str(rule.get("description", "") or "OPNsense Rule")
        iface = str(rule.get("interface", rule.get("__src_iface", "unknown")) or "unknown")

        # Best join key: tracker when present and not 0
        tracker = str(rule.get("tracker", "") or rule.get("uuid", "") or "").strip()
        if tracker and tracker != "0":
            add_row(tracker, action, desc, iface)

        # Fallback join key: pf rule number when present (small integers like 9/66/70)
        pf_rule_number = rule.get("pf_rule_number")
        if pf_rule_number:
            s = str(pf_rule_number).strip()
            if s.isdigit():
                add_row(s, action, desc, iface)

    # Remove internal helper field
    for k in list(final_rows.keys()):
        final_rows[k].pop("__src_type", None)

    print(f"[+] Merged {len(raw_rules)} raw entries into {len(final_rows)} unique keys.")

    print("\n" + "=" * 70)
    print("STAGE 6: WRITE LOOKUP FILE")
    print("=" * 70)

    try:
        os.makedirs(os.path.dirname(conf["lookup_path"]), exist_ok=True)
        with open(conf["lookup_path"], "w", newline="") as f:
            fieldnames = ["join_key", "rule_action", "rule_desc", "rule_interface"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(final_rows.values())
            f.flush()

        print(f"[+] Successfully saved {len(final_rows)} rules to: {conf['lookup_path']}")
    except Exception as e:
        print(f"[!] File write error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    update_lookup()