# TA-opnsense

**Status: alpha**

TA-opnsense is a Splunk **Technical Add-on (TA)** scaffold focused on ingesting OPNsense logs and progressively normalizing them into CIM-aligned fields. This repository intentionally excludes full app UI wrappers and setup workflows so parsing and field extraction logic can evolve quickly.

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

> Note: This TA does **not** include `inputs.conf` by design. Configure data inputs in your deployment-managed input apps or Splunk indexer/heavy forwarder configs.

## Upgrade instructions

1. Back up any local overrides under `local/`.
2. Replace app files with the new release contents.
3. Re-apply validated local overrides if needed.
4. Restart Splunk.
5. Verify effective configs and key searches (see `docs/DEV_NOTES.md`).

## Development workflow (Docker)

A simple iterative workflow is to bind-mount this repo into a Splunk container:

```bash
docker run --name splunk-dev \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD='ChangeMeNow!' \
  -p 8000:8000 -p 8089:8089 \
  -v "$(pwd)":/opt/splunk/etc/apps/TA-opnsense \
  splunk/splunk:latest
```

Recommended loop:
1. Edit files under `default/`.
2. Validate with `btool`.
3. Restart Splunk when parse-time settings change.
4. Test with sample data and SPL validations.

## btool validation checks

Run these from inside the Splunk environment:

```bash
$SPLUNK_HOME/bin/splunk btool props list --app=TA-opnsense --debug
$SPLUNK_HOME/bin/splunk btool transforms list --app=TA-opnsense --debug
$SPLUNK_HOME/bin/splunk btool app list TA-opnsense --debug
```

## AppInspect guidance

Run AppInspect before tagging releases and before publishing artifacts:

```bash
splunk-appinspect inspect TA-opnsense \
  --mode precert \
  --included-tags cloud \
  --output-file appinspect-report.json
```

When to run:
- Before each release candidate.
- After adding new parsing/extraction logic.
- After metadata/packaging changes.

## Versioning and releases

- This project follows **Semantic Versioning**.
- Current scaffold version: `0.1.0`.
- Suggested tag format: `vMAJOR.MINOR.PATCH` (example: `v0.1.0`).
- For each tag, create a GitHub Release summarizing:
  - parsing/extraction changes
  - CIM mapping updates
  - backward compatibility notes

## License choice

This project uses **Apache-2.0** to provide explicit patent grants and clear contribution terms, which is often preferable for security/log-parsing ecosystems where reusable detection logic may be redistributed.
