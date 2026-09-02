from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import pytest

from src.scanner import (
    scan_port,
    scan_ports,
)


@pytest.mark.asyncio
async def test_scan_port_open() -> None:
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"SSH-2.0-OpenSSH_8.2"

    # close() is synchronous, wait_closed() is asynchronous
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    with patch(
        "src.scanner.asyncio.open_connection", return_value=(mock_reader, mock_writer)
    ):
        result = await scan_port("127.0.0.1", 22)
        assert result is not None
        assert result["port"] == 22
        assert result["status"] == "open"
        assert result["banner"] == "SSH-2.0-OpenSSH_8.2"


@pytest.mark.asyncio
async def test_scan_port_closed() -> None:
    # Simulate connection refused / timeout error
    with patch(
        "src.scanner.asyncio.open_connection", side_effect=OSError("Connection refused")
    ):
        result = await scan_port("127.0.0.1", 9999)
        assert result is None


@pytest.mark.asyncio
async def test_scan_ports_filtering() -> None:
    # Mock scan_port to return open status for port 80, None for port 81
    async def mock_scan(host: str, port: int, timeout: float = 1.0):
        if port == 80:
            return {"port": 80, "status": "open", "banner": "HTTP/1.1 200 OK"}
        return None

    with patch("src.scanner.scan_port", side_effect=mock_scan):
        results = await scan_ports("127.0.0.1", [80, 81])
        assert len(results) == 1
        assert results[0]["port"] == 80
