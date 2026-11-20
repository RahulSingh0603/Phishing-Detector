import re
from urllib.parse import urlparse
import tldextract
import math

# Keywords often used in phishing/malicious URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'secure', 'banking', 'confirm', 
    'password', 'billing', 'support', 'service', 'auth', 'admin', 'payment', 
    'bank', 'wallet', 'crypto'
]

# TLDs that are historically abused
UNUSUAL_TLDS = [
    'xyz', 'top', 'pw', 'space', 'club', 'info', 'site', 'online', 'tk', 'ml', 'ga', 'cf', 'gq'
]

def calculate_entropy(string: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def extract_features(url: str) -> dict:
    """
    Extracts features from a URL for ML classification.
    Returns a dictionary of feature names to numerical values.
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""
    
    # Base lengths
    features = {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),
    }
    
    # Counts of specific characters
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    # Subdomain count (ignore standard 'www')
    sub = ext.subdomain
    if sub.lower().startswith('www.'):
        sub = sub[4:]
    elif sub.lower() == 'www':
        sub = ''
    features['num_subdomains'] = len(sub.split('.')) if sub else 0
    features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\.\-:/=\?&]', url))
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_query_params'] = len(query.split('&')) if query else 0
    
    # Suspicious patterns
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # IP address in hostname?
    features['has_ip_in_hostname'] = 1 if re.match(r'^[0-9\.]+$', hostname) else 0
    
    # HTTPS usage
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
    
    # Keyword checks
    url_lower = url.lower()
    features['num_suspicious_keywords'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    # Specific high-risk keywords as binary features
    for kw in ['login', 'verify', 'account', 'payment', 'bank', 'password']:
        features[f'has_kw_{kw}'] = 1 if kw in url_lower else 0
        
    # Unusual TLD check
    features['has_unusual_tld'] = 1 if ext.suffix in UNUSUAL_TLDS else 0
    
    # Entropy
    features['url_entropy'] = calculate_entropy(url)
    features['hostname_entropy'] = calculate_entropy(hostname)
    
    return features

def get_feature_names() -> list:
    """Returns the ordered list of feature names to maintain consistency."""
    # Dummy URL to extract keys
    dummy_features = extract_features("https://example.com")
    return list(dummy_features.keys())
