import asyncio
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
    query: str, max_results: int = 5, timeout: float = 10.0
) -> list[dict[str, Any]]:
    """
    Fetches known CVEs from the NIST NVD API based on a search keyword.
    """
    headers = {"User-Agent": "VulnScanner-CLI/1.0"}
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

            # Extract English description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )

            # Extract CVSS v3.1 rating if available
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


if __name__ == "__main__":
    raw_banner = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    print(f"Raw banner: '{raw_banner}'")

    product, version = parse_banner(raw_banner)
    print(f"Parsed product: '{product}', version: '{version}'")

    if product:
        # We query by product name (e.g. OpenSSH) to match NVD descriptions
        print(f"Querying NVD API for product: '{product}'...")
        results = asyncio.run(fetch_cves_for_query(product, max_results=5))

        if results:
            print(f"\nFound {len(results)} CVEs for {product}:")
            for cve in results:
                print(
                    f"- [{cve['cve_id']}] Severity: {cve['severity']}"
                    f" (Score: {cve['score']})"
                )
                print(f"  Summary: {cve['description'][:120]}...\n")
        else:
            print("No CVEs found.")
    else:
        print("Could not parse product/version from banner.")
