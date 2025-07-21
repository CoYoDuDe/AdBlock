from filter_engine import parse_domains


def test_valid_domain_extraction():
    content = """\
0.0.0.0 valid.com
127.0.0.1 valid.org
valid.net
valid.io
"""
    assert list(parse_domains(content, url="test")) == [
        "valid.com",
        "valid.org",
        "valid.net",
        "valid.io",
    ]


def test_ignore_comments_and_invalid_lines():
    content = """\
# comment
! another comment
0.0.0.0 invalid_domain
||*wildcard.example.com^
http://example.com
127.0.0.1 valid.com
"""
    assert list(parse_domains(content, url="test")) == ["valid.com"]
