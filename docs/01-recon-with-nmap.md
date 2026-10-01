# Reconnaissance with Nmap

Notes from scanning my isolated lab network (`10.10.0.0/24`) — methodology, commands, and how I read the output.

## 1. Host discovery

```bash
# Ping sweep — which hosts are alive?
nmap -sn 10.10.0.0/24

# Fast scan of common ports only
nmap -F 10.10.0.0/24
```

`-sn` sends ARP/ICMP probes and lists live hosts without port scanning. I use it first to build a target list instead of scanning the whole subnet blindly.

## 2. Service and version detection

```bash
nmap -sV -T4 -p- 10.10.0.5 -oX scans/web.xml
```

| Flag | Meaning |
| --- | --- |
| `-sV` | Probe open ports to identify service + version |
| `-p-` | Scan all 65,535 TCP ports |
| `-T4` | Aggressive timing (fine on a local lab, risky over WAN) |
| `-oX` | Save XML output — machine-readable for reporting |

**Reading the output:** version banners are the valuable part. `nginx 1.24` or `OpenSSH 9.6` tell you exactly which CVEs to check; `tcpwrapped` means a firewall or proxy is answering instead of the service.

## 3. Default scripts and OS hints

```bash
nmap -sC -sV -O 10.10.0.5 -oX scans/web-full.xml
```

- `-sC` runs the default NSE script set (HTTP titles, TLS certificate details, SMB info, …)
- `-O` attempts OS fingerprinting

## 4. Turning scans into reports

Raw XML is hard to share. My utility converts it to Markdown:

```bash
python scripts/nmap_xml_to_markdown.py scans/web-full.xml --output reports/web.md
```

It lists **open ports only**, with service and version — closed and filtered ports are summarised with a note instead of cluttering the table.

## 5. Sample findings (sanitised)

| Host | Port | Service | Version | Note |
| --- | --- | --- | --- | --- |
| 10.10.0.5 | 22/tcp | ssh | OpenSSH 9.6 | Key-only auth enforced |
| 10.10.0.5 | 443/tcp | https | nginx 1.24 | TLS 1.2+ only |
| 10.10.0.14 | 5432/tcp | postgresql | PostgreSQL 16.2 | Bound to LAN, needs review |

## 6. Lessons learned

1. **Discovery before scanning** — `-sn` first keeps scan noise and time down.
2. **Version > open/closed** — an open port is only interesting with a version attached.
3. **Timing matters** — `-T4`/`-T5` can trip IDS and drop packets; stay conservative on real networks.
4. **XML output enables automation** — scan once, report many times.

## Ethics

Scanning systems without permission is illegal in most jurisdictions (including Hong Kong's Crimes Ordinance s.161). Everything here was run against VMs I own on an isolated network.
