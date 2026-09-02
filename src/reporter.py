from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def get_severity_color(severity: str, score: float) -> str:
    """
    Returns a Rich color tag based on vulnerability severity or CVSS score.
    """
    sev_upper = severity.upper()
    if sev_upper == "CRITICAL" or score >= 9.0:
        return "bold red"
    if sev_upper == "HIGH" or score >= 7.0:
        return "red"
    if sev_upper == "MEDIUM" or score >= 4.0:
        return "yellow"
    if sev_upper == "LOW" or score > 0.0:
        return "blue"
    return "dim"


def print_scan_results(target: str, results: list[dict[str, Any]]) -> None:
    """
    Renders scan results and associated CVEs in formatted Rich tables.
    """
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Target:[/] [green]{target}[/]",
            title="[bold yellow]VulnScanner CLI[/]",
            border_style="bright_blue",
        )
    )

    if not results:
        console.print("[yellow]No open ports or services identified.[/]\n")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Banner", style="white")
    table.add_column("Parsed Product", style="green")
    table.add_column("Top CVEs", style="white")

    for item in results:
        port_str = str(item.get("port", "N/A"))
        banner = item.get("banner", "N/A")
        product = item.get("product") or "Unknown"
        version = item.get("version") or ""
        parsed_info = f"{product} {version}".strip()

        cves = item.get("cves", [])
        cve_summary_lines = []

        if cves:
            for cve in cves[:3]:  # Limit to top 3 CVEs per port for display
                cve_id = cve.get("cve_id", "N/A")
                severity = cve.get("severity", "UNKNOWN")
                score = cve.get("score", 0.0)
                color = get_severity_color(severity, score)
                cve_summary_lines.append(f"• [{color}]{cve_id}[/] ({severity} {score})")
        else:
            cve_summary_lines.append("[dim]No CVEs found[/]")

        cve_formatted = "\n".join(cve_summary_lines)
        table.add_row(port_str, banner[:40], parsed_info, cve_formatted)

    console.print(table)
    console.print()


if __name__ == "__main__":
    # Mock data for local visual testing of the UI component
    mock_results = [
        {
            "port": 22,
            "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
            "product": "OpenSSH",
            "version": "6.6.1",
            "cves": [
                {
                    "cve_id": "CVE-2016-10009",
                    "severity": "HIGH",
                    "score": 7.5,
                },
                {
                    "cve_id": "CVE-2015-5600",
                    "severity": "MEDIUM",
                    "score": 5.3,
                },
            ],
        },
        {
            "port": 80,
            "banner": "No banner received",
            "product": None,
            "version": None,
            "cves": [],
        },
    ]

    print_scan_results("scanme.nmap.org", mock_results)
