import os
from typing import Optional

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError


class DataProvider:
    def __init__(self, db_name: Optional[str] = None, env_path: str = ".env") -> None:
        load_dotenv(dotenv_path=env_path)

        mongo_uri = os.getenv("MONGO_URI")
        if not mongo_uri:
            raise ValueError("MONGO_URI .env dosyasinda tanimli degil.")

        self.client = MongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=20000,
        )
        # Baglanti dogrulama: Hata varsa burada yakalanir.
        try:
            self.client.admin.command("ping")
        except ServerSelectionTimeoutError as exc:
            raise ConnectionError(
                "MongoDB baglantisi kurulamadi. MONGO_URI, Atlas Network Access (IP whitelist), "
                "kullanici sifresi ve TLS/Firewall ayarlarini kontrol et."
            ) from exc
        except PyMongoError as exc:
            raise ConnectionError(f"MongoDB baglanti hatasi: {exc}") from exc

        selected_db_name = db_name or os.getenv("MONGO_DB_NAME", "siberpython")
        self.db: Database = self.client[selected_db_name]

        self.cve_records: Collection = self.db["CVE_Records"]
        self.target_servers: Collection = self.db["Target_Servers"]
        self.analysis_reports: Collection = self.db["Analysis_Reports"]

    def close(self) -> None:
        self.client.close()
