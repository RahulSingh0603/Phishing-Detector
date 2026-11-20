import tldextract
from urllib.parse import urlparse
from backend.ml.predict import PhishDetector

# Trusted top domains that should not be blocked on normal search or navigation
TOP_TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'google.co.uk',
    'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com',
    'youtube.com', 'wikipedia.org', 'github.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'amazon.in', 'linkedin.com',
    'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
    'whatsapp.com', 'wa.me',
    'reddit.com', 'netflix.com', 'cloudflare.com'
}

# Official Academic and Government TLDs (Heavily regulated institutions)
REGULATED_INSTITUTIONAL_TLDS = {
    'ac.in', 'edu.in', 'gov.in', 'nic.in', 'res.in',
    'edu', 'gov', 'mil', 'ac.uk', 'gov.uk'
}

class RiskEngine:
    def __init__(self):
        self.detector = PhishDetector()

    def analyze_url(self, url: str) -> dict:
        parsed = urlparse(url if url.startswith('http') else f"http://{url}")
        domain = parsed.netloc.lower()
        
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower()

        # Whitelist / trusted domain check for legitimate search engines and top sites
        if registered_domain in TOP_TRUSTED_DOMAINS:
            # Check if there is an obvious deceptive trick like an '@' symbol
            if '@' not in url:
                return {
                    "url": url,
                    "domain": domain,
                    "status": "SAFE",
                    "risk_score": 0,
                    "confidence": 0.99,
                    "reasons": ["Verified trusted domain"],
                    "action": "ALLOW"
                }

        # Regulated institutional domain check (.ac.in, .edu.in, .gov.in, etc.)
        if ext.suffix.lower() in REGULATED_INSTITUTIONAL_TLDS and '@' not in url and not ext.subdomain.count('.') > 3:
            return {
                "url": url,
                "domain": domain,
                "status": "SAFE",
                "risk_score": 0,
                "confidence": 0.99,
                "reasons": [f"Verified institutional/academic domain (.{ext.suffix})"],
                "action": "ALLOW"
            }

        # Get ML prediction
        ml_result = self.detector.predict(url)
        if "error" in ml_result:
            phishing_prob = 0.0
            ml_features = {}
        else:
            phishing_prob = ml_result["phishing_probability"]
            ml_features = ml_result["features_used"]

        reasons = []
        risk_score = int(phishing_prob * 100)
        
        # Base risk from ML
        if phishing_prob > 0.8:
            reasons.append("ML model classified as highly malicious")
        elif phishing_prob > 0.5:
            reasons.append("ML model detected suspicious patterns")

        # Heuristics based on features
        if ml_features.get('has_at_symbol'):
            reasons.append("Contains '@' symbol (often used to obscure URLs)")
            risk_score = min(100, risk_score + 20)
            
        if ml_features.get('has_ip_in_hostname'):
            reasons.append("Uses IP address instead of domain name")
            risk_score = min(100, risk_score + 30)
            
        if ml_features.get('has_unusual_tld'):
            reasons.append("Uses an unusual or high-risk top-level domain (TLD)")
            risk_score = min(100, risk_score + 10)
            
        if ml_features.get('num_suspicious_keywords', 0) > 0:
            reasons.append(f"Contains {ml_features.get('num_suspicious_keywords')} suspicious keywords")
            risk_score = min(100, risk_score + 15 * ml_features.get('num_suspicious_keywords'))

        if not ml_features.get('is_https'):
            reasons.append("Does not use HTTPS")
            risk_score = min(100, risk_score + 10)

        # Determine status and action based on score
        if risk_score < 30:
            status = "SAFE"
            action = "ALLOW"
        elif risk_score < 60:
            status = "SUSPICIOUS"
            action = "WARN"
        elif risk_score < 80:
            status = "PHISHING"
            action = "BLOCK"
        else:
            status = "MALICIOUS"
            action = "BLOCK"

        domain = urlparse(url if url.startswith('http') else f"http://{url}").netloc
            
        return {
            "url": url,
            "domain": domain,
            "status": status,
            "risk_score": risk_score,
            "confidence": round(phishing_prob, 2) if "error" not in ml_result else 0.0,
            "reasons": reasons,
            "action": action
        }
