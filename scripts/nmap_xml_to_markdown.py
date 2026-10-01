"""Convert Nmap XML output into a Markdown report."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# Allow running as a plain script from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@dataclass
class Port:
    port: int
    protocol: str
    state: str
    service: str
    version: str


@dataclass
class Host:
    address: str
    hostname: str
    ports: list[Port] = field(default_factory=list)


def parse_nmap_root(root: ET.Element) -> list[Host]:
    """Parse an ``<nmaprun>`` element into Host objects."""
    hosts: list[Host] = []

    for host_element in root.findall("host"):
        address_element = host_element.find("address")
        address = (
            address_element.get("addr", "unknown")
            if address_element is not None
            else "unknown"
        )
        hostname_element = host_element.find("hostnames/hostname")
        hostname = (
            hostname_element.get("name", "") if hostname_element is not None else ""
        )

        ports: list[Port] = []
        for port_element in host_element.findall("ports/port"):
            state_element = port_element.find("state")
            service_element = port_element.find("service")
            version_parts = []
            if service_element is not None:
                version_parts = [
                    service_element.get("product", ""),
                    service_element.get("version", ""),
                ]
            ports.append(
                Port(
                    port=int(port_element.get("portid", "0")),
                    protocol=port_element.get("protocol", "tcp"),
                    state=(
                        state_element.get("state", "unknown")
                        if state_element is not None
                        else "unknown"
                    ),
                    service=(
                        service_element.get("name", "")
                        if service_element is not None
                        else ""
                    ),
                    version=" ".join(part for part in version_parts if part),
                )
            )

        hosts.append(Host(address=address, hostname=hostname, ports=ports))

    return hosts


def parse_nmap_xml(path: str | Path) -> tuple[list[Host], str]:
    """Parse an Nmap XML file; returns ``(hosts, scan_command)``."""
    root = ET.parse(path).getroot()
    return parse_nmap_root(root), root.get("args", "")


def render_markdown(hosts: list[Host], scan_command: str = "") -> str:
    """Render hosts as a Markdown report listing open ports only."""
    lines = ["# Nmap Scan Report", ""]
    if scan_command:
        lines.extend([f"**Command:** `{scan_command}`", ""])
    lines.extend([f"**Hosts discovered:** {len(hosts)}", ""])

    for host in hosts:
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        lines.extend([f"## {title}", ""])

        open_ports = [port for port in host.ports if port.state == "open"]
        if not open_ports:
            lines.extend(["_No open ports found._", ""])
            continue

        lines.append("| Port | Protocol | State | Service | Version |")
        lines.append("| --- | --- | --- | --- | --- |")
        for port in open_ports:
            lines.append(
                f"| {port.port} | {port.protocol} | {port.state} | "
                f"{port.service} | {port.version} |"
            )
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml", type=Path, help="Nmap XML file (from nmap -oX)")
    parser.add_argument("--output", type=Path, default=None, help="Write report here")
    args = parser.parse_args(argv)

    hosts, scan_command = parse_nmap_xml(args.xml)
    report = render_markdown(hosts, scan_command)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote report for {len(hosts)} hosts to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
