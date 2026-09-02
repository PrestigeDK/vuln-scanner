import asyncio
from typing import Any


async def scan_port(
    host: str, port: int, timeout: float = 1.0
) -> dict[str, Any] | None:
    """
    Checks if a specific port is open and attempts to retrieve a banner.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

        banner = ""
        try:
            # Wait briefly for the service to send a banner (e.g., SSH, FTP, SMTP)
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = data.decode("utf-8", errors="ignore").strip()
        except (asyncio.TimeoutError, OSError):
            banner = "No banner received"
        finally:
            writer.close()
            await writer.wait_closed()

        return {"port": port, "status": "open", "banner": banner}

    except (asyncio.TimeoutError, OSError):
        # Port is closed or filtered
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

    # Filter out closed/unreachable ports (None)
    return [result for result in results if result is not None]


if __name__ == "__main__":
    # Quick local test directly against scanme.nmap.org
    target_host = "scanme.nmap.org"
    target_ports = [21, 22, 80, 443, 8080]

    print(f"Scanning {target_host}...")
    open_ports = asyncio.run(scan_ports(target_host, target_ports))

    print("\nOpen ports found:")
    for item in open_ports:
        print(f" Port {item['port']}: {item['banner']}")
