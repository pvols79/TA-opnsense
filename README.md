# TA-opnsense

**Status: alpha**

TA-opnsense is a Splunk **Technical Add-on (TA)** focused on ingesting OPNsense logs and progressively normalizing them into CIM-aligned fields. This repository intentionally excludes full app UI wrappers and setup workflows so parsing and field extraction logic can evolve quickly.

## What this TA does

- Provides starter configuration for OPNsense sourcetypes.
- Establishes a clean baseline for `props.conf` + `transforms.conf`-driven parsing.
- Supports iterative field extraction development aimed at Splunk CIM compatibility.

## Supported sourcetypes (initial scaffold)

- `opnsense:filterlog`
- `opnsense:unbound`
- `opnsense:openvpn`
- `opnsense:cron`
- `opnsense:dhclient`
- `opnsense:firewall`
- `opnsense:lighttpd`
- `opnsense:dhcpd`
- `opnsense:configctl`
- `opnsense:configd.py`
- `opnsense:undefined`

## Installation

1. Package or clone this repository directory as `TA-opnsense`.
2. Copy/untar into:
   - `$SPLUNK_HOME/etc/apps/TA-opnsense`
3. Restart Splunk:
   - `splunk restart`

> Note: You will need to modify the inputs.conf. I am currently using the sysloging feature in OPNsense to send the logs out over UDP:515



- This project follows **Semantic Versioning**.
- Current scaffold version: `0.1.0`.
- Suggested tag format: `vMAJOR.MINOR.PATCH` (example: `v0.1.0`).
- For each tag, create a GitHub Release summarizing:
  - parsing/extraction changes
  - CIM mapping updates
  - backward compatibility notes

## License choice

This project uses **Apache-2.0** to provide explicit patent grants and clear contribution terms, which is often preferable for security/log-parsing ecosystems where reusable detection logic may be redistributed.
