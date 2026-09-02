import asyncio
from typing import Annotated

import typer
from rich.console import Console

from src.api import fetch_cves_for_query, parse_banner
from src.reporter import print_scan_results
from src.scanner import scan_ports

app = typer.Typer(
    name="VulnScanner",
    help="Async Port & Vulnerability Scanner for CLI",
    add_completion=False,
)
console = Console()

DEFAULT_PORTS = [21, 22, 80, 443, 8080, 8443]


@app.command()
def scan(
    target: Annotated[
        str, typer.Argument(help="Target IP address or hostname to scan.")
    ],
    ports: Annotated[
        str | None,
        typer.Option(
            "--ports",
            "-p",
            help="Comma-separated list of ports (e.g. '22,80,443').",
        ),
    ] = None,
    max_cves: Annotated[
        int,
        typer.Option(
            "--max-cves",
            "-c",
            help="Maximum number of CVEs to fetch per service.",
        ),
    ] = 3,
) -> None:
    """
    Scans a target for open ports and queries known CVEs for identified services.
    """
    # Determine ports to scan
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            console.print(
                "[bold red]Error:[/] Ports must be integers separated by commas."
            )
            raise typer.Exit(code=1)
    else:
        port_list = DEFAULT_PORTS

    console.print(
        "\n[bold blue][*][/] Initiating scan against "
        f"[bold]{target}[/] on {len(port_list)} ports..."
    )

    # Step 1: Run port scan asynchronously
    raw_scan_data = asyncio.run(scan_ports(target, port_list))

    if not raw_scan_data:
        console.print("[bold yellow][!][/] No open ports detected.")
        raise typer.Exit()

    # Step 2: Parse banners and fetch CVEs
    enriched_results = []
    for item in raw_scan_data:
        banner = item["banner"]
        product, version = parse_banner(banner)

        cves = []
        if product:
            console.print(f"[bold blue][*][/] Fetching CVEs for [cyan]{product}[/]...")
            cves = asyncio.run(fetch_cves_for_query(product, max_results=max_cves))

        enriched_results.append(
            {
                "port": item["port"],
                "banner": banner,
                "product": product,
                "version": version,
                "cves": cves,
            }
        )

    # Step 3: Render output
    print_scan_results(target, enriched_results)


if __name__ == "__main__":
    app()
