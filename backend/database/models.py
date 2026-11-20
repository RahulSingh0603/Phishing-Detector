from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from backend.database.database import Base

class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    domain = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String) # SAFE, SUSPICIOUS, PHISHING, MALICIOUS
    risk_score = Column(Integer)
    confidence = Column(Float)
    action = Column(String) # ALLOW, BLOCK
