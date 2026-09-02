import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def get_severity_color(severity: str, score: float) -> str:
    """Returns a Rich color tag based on vulnerability severity or CVSS score."""
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
    """Renders scan results and associated CVEs in formatted Rich tables."""
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
            for cve in cves:
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


def export_results(target: str, results: list[dict[str, Any]], filepath: Path) -> None:
    """Exports scan data to a JSON or HTML file based on the file extension."""
    suffix = filepath.suffix.lower()

    if suffix == ".json":
        data = {"target": target, "results": results}
        filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[bold green][+][/] Scan report saved to [bold]{filepath}[/]")

    elif suffix == ".html":
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background-color: #f4f4f9;
            color: #333;
        }}
        h1 {{ color: #2c3e50; }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
            background: white;
        }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            color: white;
        }}
        .HIGH, .CRITICAL {{ background-color: #e74c3c; }}
        .MEDIUM {{ background-color: #f39c12; }}
        .LOW {{ background-color: #3498db; }}
        .UNKNOWN {{ background-color: #7f8c8d; }}
    </style>
</head>
<body>
    <h1>VulnScanner Report for {target}</h1>
    <table>
        <tr>
            <th>Port</th>
            <th>Banner</th>
            <th>Service</th>
            <th>Vulnerabilities</th>
        </tr>
"""
        for item in results:
            cve_html = ""
            for cve in item.get("cves", []):
                sev = cve.get("severity", "UNKNOWN")
                description = cve.get("description", "")
                cve_html += (
                    "<div><strong>"
                    f"{cve['cve_id']}"
                    "</strong> <span class='badge "
                    f"{sev}'>{sev} {cve['score']}</span> - "
                    f"{description[:100]}...</div><br>"
                )

            if not cve_html:
                cve_html = "<em>No CVEs match criteria</em>"

            html_content += f"""
        <tr>
            <td>{item["port"]}</td>
            <td>{item["banner"][:50]}</td>
            <td>{item.get("product", "Unknown")} {item.get("version", "")}</td>
            <td>{cve_html}</td>
        </tr>
"""
        html_content += """
    </table>
</body>
</html>
"""
        filepath.write_text(html_content, encoding="utf-8")
        console.print(f"[bold green][+][/] HTML report saved to [bold]{filepath}[/]")
    else:
        console.print(
            f"[bold red][!][/] Unsupported file format: {suffix}. Use .json or .html"
        )
