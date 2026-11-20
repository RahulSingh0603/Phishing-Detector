import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.api.routes import router
from backend.database.database import engine, Base
from backend.config import settings

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PhishGuard AI",
    description="Real-time URL prediction API",
    version="1.0.0"
)

# CORS configuration to allow Chrome Extension and Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to extension ID and local dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("backend.app:app", host=settings.API_HOST, port=settings.API_PORT, reload=True)
