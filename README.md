# 🛡️ Autonomous Threat Intel & Vulnerability Matcher

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green?style=flat-square&logo=mongodb)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

## 📌 Proje Özeti (Overview)
Bu proje, kurumsal ağlardaki hedef sunucuların altyapı bilgileri ile (İşletim Sistemi, Açık Portlar, Servis Sürümleri) Amerikan Ulusal Zafiyet Veritabanı'ndan (NVD) çekilen en güncel CVE kayıtlarını **otomatik olarak eşleştiren** otonom bir siber savunma (Blue Team) aracıdır.

Sistem, Nmap/Nessus gibi araçların ürettiği karmaşık PDF raporlarını okur, envanteri NoSQL (MongoDB) üzerinde yapılandırır ve her sabah dış tehdit istihbaratı ile çapraz doğrulama yaparak sıfırıncı gün (0-day) ve yeni yayınlanmış zafiyetler için erken uyarı üretir.

## ⚙️ Mimari ve Kullanılan Teknolojiler (Tech Stack)
* **Veri Çekme (Data Provider):** `requests`, NVD REST API 2.0
* **PDF OCR/İşleme:** `pdfplumber`, `re` (Regular Expressions)
* **Veritabanı (NoSQL):** MongoDB Atlas, `pymongo`
* **Ortam Yönetimi:** `python-dotenv`

## 🚀 Nasıl Çalışır?
1. **Veri Toplama:** `api_manager.py` NVD'den son yayınlanan zafiyetleri çeker.
2. **Hedef Analizi:** `pdf_processor.py` kuruma ait güvenlik tarama raporlarını okuyarak IP ve Servis detaylarını ayrıştırır.
3. **Zeka Katmanı (Core Engine):** `threat_intel.py` Regex tabanlı bir eşleştirme algoritmasıyla sunuculardaki servisler ile yeni çıkan zafiyetleri çarpıştırır ve kritik alarmlar üretir.
4. **Otonomi:** `agent.py` tüm süreci yönetir ve zamanlanmış görevlerle (Cron/Task Scheduler) insan müdahalesi olmadan çalışır.

## 🛠️ Kurulum
```bash
git clone https://github.com/KULLANICI_ADIN/siber-istihbarat-motoru.git
cd siber-istihbarat-motoru
pip install -r requirements.txt
```

Not: Sistemi çalıştırmak için `.env` dosyası oluşturup MongoDB bağlantı URI'nizi girmeniz gerekmektedir.
