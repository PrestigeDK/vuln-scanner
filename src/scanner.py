import asyncio
import socket
from typing import Any, NamedTuple


class ServiceInfo(NamedTuple):
    product: str
    version: str | None


def estimate_os_from_ttl(ttl: int | None) -> str:
    """
    Estimates target operating system based on IP Time-To-Live (TTL) value.
    """
    if ttl is None or not isinstance(ttl, int):
        return "Unknown"
    if ttl <= 64:
        return "Linux / Unix / macOS"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco / Network Device"
    return "Unknown"


async def probe_http_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    timeout: float = 1.0,
) -> str | None:
    """
    Sends an HTTP HEAD request to extract the Server response header.
    """
    try:
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VulnScanner/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode("utf-8"))
        await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        response_text = data.decode("utf-8", errors="ignore")

        for line in response_text.split("\r\n"):
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
    except (TimeoutError, OSError):
        pass
    return None


async def scan_port(
    host: str, port: int, timeout: float = 1.0
) -> dict[str, Any] | None:
    """
    Checks if a port is open, grabs banner (with HTTP fallback), and estimates OS.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = ""
        ttl = None

        sock = writer.get_extra_info("socket")
        if sock and hasattr(sock, "getsockopt"):
            try:
                val = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                if isinstance(val, int):
                    ttl = val
            except (OSError, TypeError):
                ttl = None

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = data.decode("utf-8", errors="ignore").strip()
        except (TimeoutError, OSError):
            banner = ""

        if not banner or banner == "No banner received":
            http_banner = await probe_http_banner(reader, writer, host, timeout=timeout)
            if http_banner:
                banner = http_banner
            else:
                banner = "No banner received"

        os_guess = estimate_os_from_ttl(ttl)

        writer.close()
        await writer.wait_closed()

        return {
            "port": port,
            "status": "open",
            "banner": banner,
            "ttl": ttl,
            "os_guess": os_guess,
        }
    except (TimeoutError, OSError):
        return None


async def scan_ports(
    host: str,
    ports: list[int],
    concurrency: int = 100,
    timeout: float = 1.0,
) -> list[dict[str, Any]]:
    """
    Scans a list of ports asynchronously with limited concurrency (Semaphore).
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def worker(port: int) -> dict[str, Any] | None:
        async with semaphore:
            return await scan_port(host, port, timeout=timeout)

    tasks = [worker(port) for port in ports]
    results = await asyncio.gather(*tasks)
    return [result for result in results if result is not None]
