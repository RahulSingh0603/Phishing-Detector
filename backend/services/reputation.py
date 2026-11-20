import httpx
import base64
from backend.config import settings

class ReputationService:
    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.gsb_api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY

    async def check_virustotal(self, url: str) -> dict:
        if not self.vt_api_key:
            return {"enabled": False, "malicious_votes": 0}
            
        # VT requires base64 url-safe encoding without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "x-apikey": self.vt_api_key
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    return {
                        "enabled": True,
                        "malicious_votes": malicious + suspicious,
                        "total_votes": sum(stats.values()) if stats else 0
                    }
        except Exception as e:
            print(f"VT Error: {e}")
            
        return {"enabled": True, "error": "Failed to fetch"}
