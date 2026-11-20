import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", 8000))
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

settings = Settings()
