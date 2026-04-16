import re
from pathlib import Path
from typing import Dict, List

import pdfplumber

from database_manager import DataProvider


def read_pdf_text(pdf_path: Path) -> str:
    """PDF dosyasindaki tum sayfalarin metnini tek string olarak dondurur."""
    full_text: List[str] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            full_text.append(page_text)
    return "\n".join(full_text)


def extract_server_info(text: str) -> List[Dict[str, str]]:
    """
    Metinden regex ile Hedef IP, Isletim Sistemi ve Servis alanlarini ayiklar.
    Once kayit bloklari yakalanir, bulunamazsa satir bazli esleme fallback'i kullanilir.
    """
    records: List[Dict[str, str]] = []

    block_pattern = re.compile(
        r"Hedef IP\s*[:\-]\s*(?P<hedef_ip>[^\n\r]+).*?"
        r"İşletim Sistemi\s*[:\-]\s*(?P<isletim_sistemi>[^\n\r]+).*?"
        r"Servis\s*[:\-]\s*(?P<servis>[^\n\r]+)",
        re.IGNORECASE | re.DOTALL,
    )

    for match in block_pattern.finditer(text):
        records.append(
            {
                "Hedef IP": match.group("hedef_ip").strip(),
                "İşletim Sistemi": match.group("isletim_sistemi").strip(),
                "Servis": match.group("servis").strip(),
            }
        )

    if records:
        return records

    # Fallback: blok yapisi bozuksa alanlari ayri ayri toplayip index bazli birlestir.
    ip_list = re.findall(r"Hedef IP\s*[:\-]\s*([^\n\r]+)", text, flags=re.IGNORECASE)
    os_list = re.findall(r"İşletim Sistemi\s*[:\-]\s*([^\n\r]+)", text, flags=re.IGNORECASE)
    service_list = re.findall(r"Servis\s*[:\-]\s*([^\n\r]+)", text, flags=re.IGNORECASE)

    min_len = min(len(ip_list), len(os_list), len(service_list))
    for i in range(min_len):
        records.append(
            {
                "Hedef IP": ip_list[i].strip(),
                "İşletim Sistemi": os_list[i].strip(),
                "Servis": service_list[i].strip(),
            }
        )

    return records


def process_pdf_and_save(pdf_path: Path | None = None) -> int:
    """
    PDF'yi okuyup hedef sunucu bilgilerini ayiklar ve MongoDB Target_Servers koleksiyonuna kaydeder.
    Donus: Eklenen kayit sayisi.
    """
    effective_pdf_path = pdf_path or (Path(__file__).resolve().parent / "tarama_raporu.pdf")
    pdf_text = read_pdf_text(effective_pdf_path)
    extracted_records = extract_server_info(pdf_text)

    if not extracted_records:
        return 0

    provider = DataProvider()
    try:
        insert_result = provider.target_servers.insert_many(extracted_records)
        return len(insert_result.inserted_ids)
    finally:
        provider.close()


if __name__ == "__main__":
    pdf_file_path = Path(__file__).resolve().parent / "tarama_raporu.pdf"

    try:
        inserted_count = process_pdf_and_save(pdf_file_path)
        if inserted_count == 0:
            print("Kayit bulunamadi, veritabani isleme yapilmadi.")
        else:
            print(f"Islem tamamlandi. {inserted_count} kayit Target_Servers koleksiyonuna eklendi.")
    except Exception as exc:
        print(f"Hata olustu: {exc}")
