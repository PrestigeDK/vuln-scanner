import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from src.api import fetch_cves_for_query, parse_banner
from src.reporter import export_results, print_scan_results
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
    min_score: Annotated[
        float,
        typer.Option(
            "--min-score",
            "-s",
            help="Filter CVEs by minimum CVSS score (0.0 to 10.0).",
        ),
    ] = 0.0,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Export scan report to JSON or HTML file path.",
        ),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option(
            "--api-key",
            help="NIST NVD API Key (or set NVD_API_KEY environment variable).",
        ),
    ] = None,
) -> None:
    """Scans a target for open ports and queries known CVEs for identified services."""
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
        f"\n[bold blue][*][/] Initiating scan against "
        f"[bold]{target}[/] on {len(port_list)} ports..."
    )

    raw_scan_data = asyncio.run(scan_ports(target, port_list))

    if not raw_scan_data:
        console.print("[bold yellow][!][/] No open ports detected.")
        raise typer.Exit()

    enriched_results = []
    for item in raw_scan_data:
        banner = item["banner"]
        product, version = parse_banner(banner)

        cves = []
        if product:
            console.print(f"[bold blue][*][/] Fetching CVEs for [cyan]{product}[/]...")
            raw_cves = asyncio.run(
                fetch_cves_for_query(product, max_results=max_cves, api_key=api_key)
            )
            # Filter CVEs based on minimum CVSS score
            cves = [c for c in raw_cves if c.get("score", 0.0) >= min_score]

        enriched_results.append(
            {
                "port": item["port"],
                "banner": banner,
                "product": product,
                "version": version,
                "cves": cves,
            }
        )

    # Render terminal UI
    print_scan_results(target, enriched_results)

    # Export report if requested
    if output:
        export_results(target, enriched_results, output)


if __name__ == "__main__":
    app()
