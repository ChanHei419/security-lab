# Intrusion Detection with Suricata

Notes from running Suricata as a network IDS sensor in my lab, generating traffic with Nmap, and triaging alerts.

## 1. Setup

```bash
sudo apt update && sudo apt install -y suricata
sudo suricata-update                 # fetch the latest rule sets
sudo suricata -T -c /etc/suricata/suricata.yaml -v   # validate config
sudo systemctl restart suricata
```

Key config (`/etc/suricata/suricata.yaml`):

| Setting | Value | Why |
| --- | --- | --- |
| `HOME_NET` | `10.10.0.0/24` | Defines what counts as "inside" |
| `af-packet` interface | `eth1` | Interface receiving mirrored traffic |
| `outputs.fast` | enabled | Human-readable `fast.log` |
| `outputs.eve-log` | enabled | JSON events (`eve.json`) for tooling |

## 2. Rule basics

Rules live in `/var/lib/suricata/rules/` and follow the signature format:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
  msg:"LAB Possible SSH brute force";
  flow:to_server;
  threshold: type both, track by_src, count 5, seconds 60;
  sid:1000001; rev:1;
)
```

| Part | Meaning |
| --- | --- |
| `alert tcp ... -> ... 22` | Match direction and port |
| `flow:to_server` | Only client→server traffic |
| `threshold` | Rate-based detection — 5 attempts per minute |
| `sid` / `rev` | Unique rule ID and revision for tracking changes |

Custom lab rules use the `1000000+` SID range so they never collide with the official rule set.

## 3. Generating test traffic (my own lab)

```bash
# From the "attacker" VM against my own target VM
nmap -sS -T4 -p 22,80,443 10.10.0.5
```

Aggressive scans are ideal test cases: they trip scan-detection rules and produce enough events to practise triage.

## 4. Reading alerts

```bash
# Quick view
sudo tail -f /var/log/suricata/fast.log

# JSON events: filter by signature
jq 'select(.event_type=="alert") | {time: .timestamp, sig: .alert.signature, src: .src_ip, dst: .dest_ip}' \
  /var/log/suricata/eve.json
```

Triage checklist:

1. **What triggered?** — signature name and SID
2. **Who?** — source/destination, internal or external
3. **How often?** — one hit vs a sustained pattern (`threshold` reduces noise, but bursts still matter)
4. **True or false positive?** — e.g. scheduled vulnerability scans from IT will look like attacks
5. **Action** — document, tune the rule, or escalate

## 5. Tuning notes

- Suppress noisy signatures with `threshold`/`suppress` rather than disabling whole rule files
- Keep `suricata-update` on a schedule — new rules matter more than tweaking old ones
- Ship `eve.json` to a SIEM (Elastic/Filebeat) when the lab grows; `fast.log` doesn't scale

## 6. Lessons learned

1. **A sensor with no traffic is useless** — generate known traffic to validate rules.
2. **False positives are the norm** — tuning is the actual skill, not installation.
3. **Nmap is a great teacher** — scan patterns are well documented, so mismatches are easy to spot.
4. **Log → JSON → SIEM** is the path from a toy lab to something realistic.

## Ethics

All traffic was generated between VMs I own on an isolated network. Never run scans or IDS sensors against networks you do not control.
