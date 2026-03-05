# Development Notes

## Testing parsing changes

Parsing changes in `props.conf` / `transforms.conf` are generally parse-time and may require a restart.

Typical flow:
1. Update config files under `default/`.
2. Restart Splunk to ensure parse-time settings are reloaded:
   - `splunk restart`
3. Re-index representative sample events where needed.
4. Validate extracted fields in Search.

> Tip: Search-time aliases/eval changes can often be validated with `| extract reload=t` or knowledge object refreshes, but index-time routing and line-breaking changes usually require restart + reingest.

## Validate effective conf with btool

Run from Splunk host/container:

```bash
$SPLUNK_HOME/bin/splunk btool props list --app=TA-opnsense --debug
$SPLUNK_HOME/bin/splunk btool transforms list --app=TA-opnsense --debug
$SPLUNK_HOME/bin/splunk btool eventtypes list --app=TA-opnsense --debug
$SPLUNK_HOME/bin/splunk btool tags list --app=TA-opnsense --debug
```

Use `--debug` to confirm file precedence and ensure no unintended overrides.

## Sample validation searches

Use these SPL patterns after ingesting sample OPNsense events:

```spl
index=* sourcetype=opnsense:filterlog
| head 20
| table _time host sourcetype action src_ip src_port dest_ip dest_port transport
```

```spl
index=* sourcetype=opnsense:unbound
| stats count by host query qtype src_ip
```

```spl
index=* sourcetype=opnsense:openvpn
| stats count by host user src_ip status
```

```spl
index=* sourcetype=opnsense:*
| stats count by sourcetype
```
