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


def parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """
    Converts a version string into a tuple of integers for numerical version comparison.
    """
    numbers = re.findall(r"\d+", version_str)
    return tuple(int(n) for n in numbers)


def is_version_vulnerable(cve_data: dict[str, Any], target_version: str | None) -> bool:
    """
    Checks whether a target version falls within the vulnerable ranges of a CVE record.
    """
    if not target_version:
        return True

    target_tuple = parse_version_tuple(target_version)
    if not target_tuple:
        return True

    configurations = cve_data.get("configurations", [])
    if not configurations:
        return True

    matched_any_node = False
    is_vulnerable = False

    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                if not match.get("vulnerable", True):
                    continue

                matched_any_node = True
                start_inc = match.get("versionStartIncluding")
                start_exc = match.get("versionStartExcluding")
                end_inc = match.get("versionEndIncluding")
                end_exc = match.get("versionEndExcluding")

                bounds_exist = any([start_inc, start_exc, end_inc, end_exc])
                if bounds_exist:
                    valid = True
                    if start_inc and target_tuple < parse_version_tuple(start_inc):
                        valid = False
                    if start_exc and target_tuple <= parse_version_tuple(start_exc):
                        valid = False
                    if end_inc and target_tuple > parse_version_tuple(end_inc):
                        valid = False
                    if end_exc and target_tuple >= parse_version_tuple(end_exc):
                        valid = False

                    if valid:
                        is_vulnerable = True
                        break
                else:
                    criteria = match.get("criteria", "")
                    if f":{target_version}:" in criteria or target_version in criteria:
                        is_vulnerable = True
                        break

            if is_vulnerable:
                break
        if is_vulnerable:
            break

    return not (matched_any_node and not is_vulnerable)


async def fetch_cves_for_query(
    query: str,
    version: str | None = None,
    max_results: int = 5,
    timeout: float = 10.0,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """
    Fetches known CVEs from the NIST NVD API based on product name and version.
    """
    headers = {"User-Agent": "VulnScanner-CLI/1.0"}
    resolved_key = api_key or os.getenv("NVD_API_KEY")
    if resolved_key:
        headers["apiKey"] = resolved_key

    search_keyword = f"{query} {version}" if version else query
    fetch_limit = max_results * 3 if version else max_results
    params = {"keywordSearch": search_keyword, "resultsPerPage": fetch_limit}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(NVD_API_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

        cves = []
        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve_data = item.get("cve", {})

            if not is_version_vulnerable(cve_data, version):
                continue

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

            if len(cves) >= max_results:
                break

        return cves
    except httpx.HTTPStatusError as err:
        print(f"HTTP error occurred while fetching CVEs: {err}")
        return []
    except httpx.RequestError as err:
        print(f"Network error occurred while fetching CVEs: {err}")
        return []
