import xml.etree.ElementTree as ET
import unittest

from scripts.nmap_xml_to_markdown import (
    parse_nmap_root,
    render_markdown,
)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.0.0.0/24">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.lab.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/><service name="https" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/><service name="mysql"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="filtered"/><service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.hosts = parse_nmap_root(ET.fromstring(SAMPLE_XML))

    def test_parses_all_hosts(self):
        self.assertEqual(len(self.hosts), 2)

    def test_host_details_and_ports(self):
        web = self.hosts[0]
        self.assertEqual(web.address, "10.0.0.5")
        self.assertEqual(web.hostname, "web.lab.local")
        self.assertEqual(len(web.ports), 3)

    def test_version_is_joined(self):
        ssh = self.hosts[0].ports[0]
        self.assertEqual(ssh.service, "ssh")
        self.assertEqual(ssh.version, "OpenSSH 9.6")


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.hosts = parse_nmap_root(ET.fromstring(SAMPLE_XML))
        self.report = render_markdown(self.hosts, "nmap -sV 10.0.0.0/24")

    def test_includes_command_and_host_count(self):
        self.assertIn("`nmap -sV 10.0.0.0/24`", self.report)
        self.assertIn("**Hosts discovered:** 2", self.report)

    def test_lists_open_ports_with_service_version(self):
        self.assertIn("| 443 | tcp | open | https | nginx 1.24 |", self.report)

    def test_excludes_non_open_ports(self):
        self.assertNotIn("3306", self.report)
        self.assertNotIn("| 80 |", self.report)

    def test_notes_hosts_without_open_ports(self):
        self.assertIn("_No open ports found._", self.report)

    def test_empty_scan(self):
        report = render_markdown([], "")
        self.assertIn("**Hosts discovered:** 0", report)


if __name__ == "__main__":
    unittest.main()
