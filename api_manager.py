from typing import Any, Dict, List, Optional, Tuple

import requests

from database_manager import DataProvider

NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_description(descriptions: List[Dict[str, Any]]) -> str:
    if not descriptions:
        return ""

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")

    return descriptions[0].get("value", "")


def _extract_cvss_v3_score(metrics: Dict[str, Any]) -> Optional[float]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        values = metrics.get(key, [])
        if values:
            return values[0].get("cvssData", {}).get("baseScore")
    return None


def fetch_latest_cves() -> Tuple[List[Dict[str, Any]], int]:
    parsed_cves: List[Dict[str, Any]] = []
    saved_count = 0

    try:
        response = requests.get(
            NVD_CVES_URL,
            params={"resultsPerPage": 5},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()

        vulnerabilities = payload.get("vulnerabilities", [])

        for item in vulnerabilities[:5]:
            cve = item.get("cve", {})
            parsed_item = {
                "cve_id": cve.get("id"),
                "published_date": cve.get("published"),
                "description": _extract_description(cve.get("descriptions", [])),
                "cvss_v3_score": _extract_cvss_v3_score(cve.get("metrics", {})),
            }
            parsed_cves.append(parsed_item)

    except requests.RequestException as exc:
        print(f"NVD API istegi basarisiz: {exc}")
        return [], 0
    except ValueError as exc:
        print(f"NVD API JSON parse hatasi: {exc}")
        return [], 0
    except Exception as exc:
        print(f"CVE verileri parse edilirken hata olustu: {exc}")
        return [], 0

    try:
        data_provider = DataProvider()
        try:
            for cve_item in parsed_cves:
                cve_id = cve_item.get("cve_id")
                if not cve_id:
                    continue
                data_provider.cve_records.update_one(
                    {"cve_id": cve_id},
                    {"$set": cve_item},
                    upsert=True,
                )
                saved_count += 1
        finally:
            data_provider.close()
    except Exception as exc:
        print(f"MongoDB kayit hatasi: {exc}")

    return parsed_cves, saved_count


if __name__ == "__main__":
    cves, saved = fetch_latest_cves()
    fetched = len(cves)

    print(f"NVD API'den cekilen CVE sayisi: {fetched}")

    if fetched == 0:
        print("Islem sonlandi: API'den veri cekilemedi.")
    elif saved == fetched:
        print(f"Basarili: {saved} kayit MongoDB'deki CVE_Records koleksiyonuna yazildi.")
    else:
        print(f"Kismi durum: {saved}/{fetched} kayit MongoDB'ye yazildi.")
