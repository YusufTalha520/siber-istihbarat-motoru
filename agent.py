import logging

from api_manager import fetch_latest_cves
from pdf_processor import process_pdf_and_save
from threat_intel import run_analysis

# Ajanin log kayitlarini tutmasi icin ayarlar
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def run_cyber_agent() -> None:
    logging.info("Siber Istihbarat (Threat Intel) Ajani Uykudan Uyandi ve Baslatiliyor...")

    try:
        # 1. Asama: Dis Istihbarat (NVD API)
        logging.info("Adim 1: NVD uzerinden en guncel zafiyetler cekiliyor...")
        fetch_latest_cves()

        # 2. Asama: Ic Analiz (PDF Tarama Raporlari)
        logging.info("Adim 2: Ag tarama raporlari (PDF) ayristirilip hedefler belirleniyor...")
        process_pdf_and_save()

        # 3. Asama: Zeka ve Eslestirme Motoru
        logging.info("Adim 3: Eslestirme motoru calistiriliyor ve risk analizi yapiliyor...")
        run_analysis()

        logging.info("Ajan gorevini basariyla tamamladi. Eslesmeler veritabanina kaydedildi.")
    except Exception as e:
        logging.error(f"Ajan calisirken kritik bir hata olustu: {e}")


if __name__ == "__main__":
    run_cyber_agent()
