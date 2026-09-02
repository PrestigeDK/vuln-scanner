from src.api import parse_banner


def test_parse_banner_ssh() -> None:
    raw_banner = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    product, version = parse_banner(raw_banner)
    assert product == "OpenSSH"
    assert version == "6.6.1"


def test_parse_banner_apache() -> None:
    raw_banner = "Apache/2.4.41 (Ubuntu)"
    product, version = parse_banner(raw_banner)
    assert product == "Apache"
    assert version == "2.4.41"


def test_parse_banner_invalid() -> None:
    raw_banner = "Unknown Custom Service Header"
    product, version = parse_banner(raw_banner)
    assert product is None
    assert version is None
