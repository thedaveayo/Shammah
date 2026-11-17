"""
Security MCP Backend - FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import CORS_ORIGINS, HOST, PORT
from database import engine, Base, SessionLocal
from api.routes import router
import schedule
import time
from threading import Thread

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Shammah Backend",
    description="Security Agent - Processes CVE/CWE/Telegram → generates enforcement rules",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Include API routes
app.include_router(router, prefix="/api")

@app.get("/")
def root():
    return {
        "name": "Shammah Backend",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

# Background scheduler for periodic CVE fetching
def run_scheduler():
    """Run scheduled tasks in background"""
    from services.cve_fetcher import CVEFetcher

    def fetch_cves_job():
        print("Scheduled: Fetching CVEs (last 90 days)...")
        db = SessionLocal()
        cve_fetcher = CVEFetcher()
        try:
            saved = cve_fetcher.sync_cves(db, days_back=90)
            print(f"Scheduled: Saved {saved} CVEs")
        except Exception as e:
            print(f"Scheduled: Error fetching CVEs: {e}")
        finally:
            db.close()

    # Schedule CVE fetch every 6 hours
    schedule.every(6).hours.do(fetch_cves_job)

    while True:
        schedule.run_pending()
        time.sleep(60)

# Start background scheduler
scheduler_thread = Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
