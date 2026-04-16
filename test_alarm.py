from database_manager import DataProvider


def insert_test_cve_record() -> None:
    test_vuln = {
        "cve_id": "CVE-2026-99999",
        "published_date": "2026-04-16",
        "description": (
            "Kritik güvenlik açığı: Microsoft IIS httpd 10.0 üzerinde "
            "kimlik doğrulamasız Remote Code Execution (RCE) zafiyeti tespit edildi."
        ),
        "cvss_score": 9.8,
    }

    provider = DataProvider()
    try:
        provider.cve_records.insert_one(test_vuln)
    finally:
        provider.close()

    print("Test zafiyeti eklendi")


if __name__ == "__main__":
    insert_test_cve_record()
