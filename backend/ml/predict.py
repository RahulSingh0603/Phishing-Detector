import os
import sys
import pandas as pd
import joblib

# Add the root directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend.ml.features import extract_features, get_feature_names

class PhishDetector:
    def __init__(self, model_path=None):
        if model_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_path = os.path.join(base_dir, 'backend', 'ml', 'model.pkl')
            
        self.model_path = model_path
        self.model = None
        self.feature_names = get_feature_names()
        self.load_model()
        
    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            print(f"Warning: Model not found at {self.model_path}. Please run train.py first.")
            
    def predict(self, url: str) -> dict:
        """
        Predicts if a URL is phishing/malicious.
        Returns a dictionary with prediction and probability.
        """
        if self.model is None:
            return {"error": "Model not loaded. Train the model first."}
            
        features = extract_features(url)
        # Convert to DataFrame with same column order as training
        X = pd.DataFrame([features])[self.feature_names]
        
        prob = self.model.predict_proba(X)[0]
        phishing_prob = float(prob[1])  # Probability of class 1 (phishing/malicious)
        
        return {
            "url": url,
            "phishing_probability": phishing_prob,
            "features_used": features
        }

if __name__ == "__main__":
    detector = PhishDetector()
    test_urls = [
        "https://google.com",
        "http://secure-login-verify-account.tk/auth"
    ]
    for url in test_urls:
        res = detector.predict(url)
        print(f"URL: {res.get('url')}")
        print(f"Phishing Probability: {res.get('phishing_probability'):.4f}\n")
