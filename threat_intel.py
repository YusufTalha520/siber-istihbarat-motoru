from datetime import datetime
from typing import Any, Dict, List, Set

from database_manager import DataProvider


def _extract_keywords(server_doc: Dict[str, Any]) -> Set[str]:
    """
    Sunucu dokumanindaki Servis ve Isletim Sistemi metinlerinden
    eslestirmede kullanilacak anahtar kelimeleri uretir.
    """
    keywords: Set[str] = set()
    candidate_fields = ["Servis", "İşletim Sistemi"]

    for field in candidate_fields:
        raw_value = server_doc.get(field, "")
        if not isinstance(raw_value, str):
            continue

        keywords.add(raw_value.strip())
        for token in raw_value.replace("/", " ").replace("-", " ").split():
            clean_token = token.strip(" ,.;:()[]{}")
            if len(clean_token) >= 3:
                keywords.add(clean_token)

    return {kw for kw in keywords if kw}


def find_and_store_vulnerability_alerts() -> List[Dict[str, Any]]:
    """
    Target_Servers ve CVE_Records koleksiyonlarini okuyup eslesme yakalar,
    eslesen kayitlari Analysis_Reports koleksiyonuna kaydeder.
    """
    provider = DataProvider()
    try:
        server_docs = list(provider.target_servers.find({}))
        cve_docs = list(provider.cve_records.find({}))

        alerts: List[Dict[str, Any]] = []

        for server in server_docs:
            target_ip = server.get("Hedef IP", "Bilinmeyen IP")
            keywords = _extract_keywords(server)
            if not keywords:
                continue

            for cve in cve_docs:
                description = str(cve.get("description", ""))
                description_lower = description.lower()

                matched_keyword = next(
                    (kw for kw in keywords if kw.lower() in description_lower),
                    None,
                )
                if not matched_keyword:
                    continue

                cve_id = cve.get("cve_id") or cve.get("id") or "Bilinmeyen-CVE"
                alert = {
                    "target_ip": target_ip,
                    "matched_cve_id": cve_id,
                    "vulnerability_description": description,
                    "matched_keyword": matched_keyword,
                    "created_at": datetime.utcnow(),
                }
                alerts.append(alert)

        if alerts:
            provider.analysis_reports.insert_many(alerts)

        return alerts
    finally:
        provider.close()


def run_analysis() -> List[Dict[str, Any]]:
    """Master Agent tarafindan cagirilan analiz giris noktasi."""
    return find_and_store_vulnerability_alerts()


if __name__ == "__main__":
    try:
        matched_alerts = run_analysis()

        if not matched_alerts:
            print("Eslestirme bulunamadi. Yeni kritik uyari uretilmedi.")
        else:
            for alert in matched_alerts:
                print(
                    f"KRİTİK UYARI: {alert['target_ip']} adresindeki sunucu "
                    f"{alert['matched_cve_id']} zafiyetinden etkilenebilir!"
                )
            print(f"Toplam {len(matched_alerts)} uyari Analysis_Reports koleksiyonuna kaydedildi.")
    except Exception as exc:
        print(f"Hata olustu: {exc}")
