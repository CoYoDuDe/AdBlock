from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from filter_engine import (  # noqa: E402
    categorize_list,
    ist_gueltige_domain,
    parse_domains,
)


def test_parse_domains_typical_lines():
    content = """
    0.0.0.0 example.com
    ||ads.example.com^
    # Kommentar
    127.0.0.1    sub.example.com

    ! weitere Kommentare
    """
    result = list(parse_domains(content, "dummy"))
    assert result == ["example.com", "ads.example.com", "sub.example.com"]


def test_ist_gueltige_domain():
    gueltige = [
        "example.com",
        "sub.domain.de",
        "xn--d1acufc.xn--p1ai",  # IDN
    ]
    ungueltige = [
        "-invalid.com",
        "invalid-.de",
        "no spaces.com",
        "ex_ample.com",
    ]
    for domain in gueltige:
        assert ist_gueltige_domain(domain)
    for domain in ungueltige:
        assert not ist_gueltige_domain(domain)


def test_categorize_list():
    assert categorize_list("https://malware.example.com/list.txt") == "malware"
    assert categorize_list("https://ads.example.com/list.txt") == "ads"
    assert categorize_list("https://porn.example.com/list.txt") == "adult"
    assert categorize_list("https://unknown.example.com/list.txt") == "unknown"
