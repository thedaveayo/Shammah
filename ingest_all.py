#!/usr/bin/env python3
"""
Full Ingestion Script
Ingests: CVEs (last 90 days ~7,500 CVEs) + All CWEs (~600)
Time: ~45-75 minutes total
Cost: ~$0.25-0.50 (Qwen API for CWEs)
"""
import sys
import os
import threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from database import SessionLocal, Base, engine
from services.cve_fetcher import CVEFetcher
from services.cwe_fetcher import CWEFetcher
from services.export_generator import ExportGenerator
from services.rule_cache import RuleCache

# Create tables
Base.metadata.create_all(bind=engine)

def ingest_cves():
    """Ingest CVEs from last 90 days + Hall of Fame"""
    print("\n" + "="*70)
    print("CVE INGESTION (Last 90 Days + Hall of Fame)")
    print("="*70)
    
    db = SessionLocal()
    fetcher = CVEFetcher()
    
    try:
        # Include Hall of Fame (critical CVEs for popular frameworks from last year)
        saved = fetcher.sync_cves(db, days_back=90, include_hall_of_fame=True)
        print(f"\n[OK] CVE Ingestion Complete: Saved {saved} CVE rules")
        return saved
    except Exception as e:
        print(f"\n[ERROR] CVE Ingestion Failed: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        db.close()

def ingest_cwes():
    """Ingest all CWEs (~600)"""
    print("\n" + "="*70)
    print("CWE INGESTION (Full Taxonomy - ~600 CWEs)")
    print("="*70)
    
    db = SessionLocal()
    fetcher = CWEFetcher()
    
    try:
        saved = fetcher.sync_cwe_taxonomy(db, force=False)
        print(f"\n[OK] CWE Ingestion Complete: Saved {saved} CWE rules")
        return saved
    except Exception as e:
        print(f"\n[ERROR] CWE Ingestion Failed: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        db.close()

def generate_export():
    """Regenerate public export JSON"""
    print("\n" + "="*70)
    print("GENERATING EXPORT JSON")
    print("="*70)
    
    db = SessionLocal()
    try:
        cache = RuleCache(db)
        all_rules = cache.get_all_rules()
        export_gen = ExportGenerator()
        export_path = export_gen.generate_and_save(all_rules)
        
        print(f"\n[OK] Export generated: {export_path}")
        print(f"  Total rules exported: {len(all_rules)}")
        return True
    except Exception as e:
        print(f"\n[ERROR] Export Generation Failed: {e}")
        return False
    finally:
        db.close()

def print_stats():
    """Print final statistics"""
    db = SessionLocal()
    try:
        cache = RuleCache(db)
        stats = cache.get_rule_count()
        
        print("\n" + "="*70)
        print("FINAL STATISTICS")
        print("="*70)
        print(f"""
Total Rules: {stats['total']}
  - CVE-derived: {stats['cve']}
  - CWE-derived: {stats['cwe']}
  - DSV (Telegram): {stats['dsv']}

Database: backend/security_mcp.db
Export: backend/exports/rules.json
        """)
        print("="*70)
        return stats
    finally:
        db.close()

def main():
    print("\n" + "="*70)
    print("SECURITY MCP - FULL RULE INGESTION")
    print("="*70)
    print("""
This script will ingest:
  1. CVEs from last 90 days (~2,000) + Hall of Fame (~200-500)
     Hall of Fame = Critical CVEs for popular frameworks from last year
     FREE, ~30-60 min total
  2. All CWEs (~600 patterns) - ~$0.25-0.50, ~30-60 min

Both run in PARALLEL to save time.

Starting now...
    """)
    
    # Run CVE and CWE ingestion in parallel
    cve_thread = threading.Thread(target=ingest_cves)
    cwe_thread = threading.Thread(target=ingest_cwes)
    
    print("\n[STARTING] Both ingestions running in parallel...")
    
    cve_thread.start()
    cwe_thread.start()
    
    # Wait for both to complete
    cve_thread.join()
    cwe_thread.join()
    
    print("\n[COMPLETE] Both ingestions finished!")
    
    # Generate export
    generate_export()
    
    # Print stats
    stats = print_stats()
    
    print("""
[OK] INGESTION COMPLETE!

Next steps:
  1. Test rules: curl http://localhost:8000/api/stats
  2. View export: curl http://localhost:8000/api/public/rules
  3. Daily sync: Automated (runs every 6 hours)
    """)

if __name__ == "__main__":
    main()
