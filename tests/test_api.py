from src.api import is_version_vulnerable, parse_banner, parse_version_tuple


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


def test_parse_version_tuple() -> None:
    assert parse_version_tuple("6.6.1p1") == (6, 6, 1, 1)
    assert parse_version_tuple("2.4.41") == (2, 4, 41)


def test_is_version_vulnerable() -> None:
    mock_cve_data = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "versionStartIncluding": "6.0",
                                "versionEndExcluding": "6.7",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert is_version_vulnerable(mock_cve_data, "6.6.1") is True
    assert is_version_vulnerable(mock_cve_data, "7.0") is False
