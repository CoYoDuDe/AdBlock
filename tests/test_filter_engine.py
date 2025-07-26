from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from filter_engine import parse_domains  # noqa: E402


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
