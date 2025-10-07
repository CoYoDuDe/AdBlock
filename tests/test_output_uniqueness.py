import asyncio
from pathlib import Path

import adblock


def test_load_unique_sorted_domains_removes_duplicates(tmp_path):
    reachable_path = tmp_path / "reachable.txt"
    reachable_path.write_text("b.example.com\nb.example.com\na.example.com\n")

    result = asyncio.run(adblock.load_unique_sorted_domains(str(reachable_path)))

    assert result == ["a.example.com", "b.example.com"]


def test_hosts_and_dnsmasq_outputs_are_unique(tmp_path, monkeypatch):
    reachable_path = tmp_path / "reachable.txt"
    reachable_path.write_text("example.com\nexample.com\nfoo.example\n")

    config_copy = adblock.CONFIG.copy()
    monkeypatch.setattr(adblock, "CONFIG", config_copy)
    monkeypatch.setattr(adblock, "REACHABLE_FILE", str(reachable_path))
    monkeypatch.setattr(adblock, "SCRIPT_DIR", str(tmp_path))

    config_copy.update(
        {
            "dns_config_file": "dnsmasq.conf",
            "hosts_file": "hosts.txt",
            "use_ipv4_output": True,
            "use_ipv6_output": False,
            "hosts_ip": "0.0.0.0",
            "web_server_ipv4": "127.0.0.1",
        }
    )

    sorted_domains = asyncio.run(adblock.load_unique_sorted_domains(str(reachable_path)))

    dns_lines = adblock.build_dnsmasq_lines(sorted_domains, config_copy, include_ipv6=False)
    dns_path = Path(tmp_path) / config_copy["dns_config_file"]
    dns_path.write_text("\n".join(dns_lines))

    hosts_content = adblock.build_hosts_content(sorted_domains, config_copy)
    hosts_path = Path(tmp_path) / config_copy["hosts_file"]
    hosts_path.write_text(hosts_content)

    dns_domains = [
        line.split("/")[1]
        for line in dns_path.read_text().splitlines()
        if line
    ]
    hosts_domains = [
        line.split(" ", 1)[1]
        for line in hosts_path.read_text().splitlines()
        if line
    ]

    assert len(dns_domains) == len(set(dns_domains))
    assert len(hosts_domains) == len(set(hosts_domains))
