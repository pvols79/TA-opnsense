# Expected Fields (Initial Targets)

These are initial expected fields for validation as extraction logic is implemented.

## `opnsense:filterlog`

- `_time`
- `host`
- `sourcetype`
- `action` (for example: `pass`, `block`)
- `direction` (for example: `in`, `out`)
- `transport` (for example: `tcp`, `udp`)
- `src_ip`
- `src_port`
- `dest_ip`
- `dest_port`
- `protocol`

## `opnsense:unbound`

- `_time`
- `host`
- `sourcetype`
- `src_ip`
- `query`
- `qtype`
- `dns_class`
- `message`

## `opnsense:openvpn`

- `_time`
- `host`
- `sourcetype`
- `user`
- `src_ip`
- `src_port`
- `status`
- `vpn_assigned_ip`
- `message`
