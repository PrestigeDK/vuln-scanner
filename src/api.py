import os
import re
from typing import Any

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_banner(banner: str) -> tuple[str | None, str | None]:
    """
    Extracts product name and version as separate strings from a raw service banner.
    """
    pattern = r"([a-zA-Z]+)[/\_]([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
    match = re.search(pattern, banner)

    if match:
        product = match.group(1)
        version = match.group(2)
        return product, version

    return None, None


async def fetch_cves_for_query(
    query: str,
    max_results: int = 5,
    timeout: float = 10.0,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """Fetches known CVEs from the NIST NVD API based on a search keyword."""
    headers = {"User-Agent": "VulnScanner-CLI/1.0"}

    # Use explicitly passed key or fallback to environment variable
    resolved_key = api_key or os.getenv("NVD_API_KEY")
    if resolved_key:
        headers["apiKey"] = resolved_key

    params = {"keywordSearch": query, "resultsPerPage": max_results}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(NVD_API_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

        cves = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "N/A")

            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )

            metrics = cve_data.get("metrics", {})
            cvss_data = None
            if metrics.get("cvssMetricV31"):
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})

            severity = (
                cvss_data.get("baseSeverity", "UNKNOWN") if cvss_data else "UNKNOWN"
            )
            score = cvss_data.get("baseScore", 0.0) if cvss_data else 0.0

            cves.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "score": score,
                    "severity": severity,
                }
            )

        return cves

    except httpx.HTTPStatusError as err:
        print(f"HTTP error occurred while fetching CVEs: {err}")
        return []
    except httpx.RequestError as err:
        print(f"Network error occurred while fetching CVEs: {err}")
        return []
