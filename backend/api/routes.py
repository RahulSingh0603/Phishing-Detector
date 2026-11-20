from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from backend.database.database import get_db
from backend.database import models
from backend.services.risk_engine import RiskEngine

router = APIRouter()
risk_engine = RiskEngine()

class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    url: str
    status: str
    risk_score: int
    confidence: float
    reasons: List[str]
    action: str

class StatsResponse(BaseModel):
    total_scans: int
    safe: int
    suspicious: int
    phishing: int
    malicious: int
    blocked: int

@router.get("/health")
def health_check():
    return {"status": "ok", "service": "PhishGuard AI"}

@router.post("/predict", response_model=URLResponse)
def predict_url(request: URLRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    result = risk_engine.analyze_url(request.url)
    
    # Save to history in background
    background_tasks.add_task(save_scan_history, db, result)
    
    return result

def save_scan_history(db: Session, result: dict):
    db_scan = models.URLScan(
        url=result["url"],
        domain=result.get("domain", ""),
        status=result["status"],
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        action=result["action"]
    )
    db.add(db_scan)
    db.commit()

@router.get("/history")
def get_history(limit: int = 50, db: Session = Depends(get_db)):
    scans = db.query(models.URLScan).order_by(models.URLScan.timestamp.desc()).limit(limit).all()
    return scans

@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    total = db.query(models.URLScan).count()
    safe = db.query(models.URLScan).filter(models.URLScan.status == "SAFE").count()
    suspicious = db.query(models.URLScan).filter(models.URLScan.status == "SUSPICIOUS").count()
    phishing = db.query(models.URLScan).filter(models.URLScan.status == "PHISHING").count()
    malicious = db.query(models.URLScan).filter(models.URLScan.status == "MALICIOUS").count()
    blocked = db.query(models.URLScan).filter(models.URLScan.action == "BLOCK").count()
    
    return {
        "total_scans": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing,
        "malicious": malicious,
        "blocked": blocked
    }
