from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException, status, BackgroundTasks
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import re

from bson.objectid import ObjectId
from app.database import get_reports_collection, MONGO_URI
from app.scanner import scan_code
from app.llm_service import enrich_vulnerabilities
from app.pdf_service import generate_pdf

app = FastAPI()

# CORS - allow configured origins in production, default to localhost for dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static frontend
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Simple vulnerability rules
rules = [
    {
        "name": "SQL Injection Risk",
        "pattern": r"SELECT.*\+",
        "severity": "High",
        "fix": "Use parameterized queries instead of string concatenation."
    },
    {
        "name": "Debug Mode Enabled",
        "pattern": r"debug=True",
        "severity": "Medium",
        "fix": "Disable debug mode in production environments."
    },
    {
        "name": "Hardcoded Password",
        "pattern": r"password\s*=\s*['\"].+['\"]",
        "severity": "High",
        "fix": "Store sensitive credentials in environment variables."
    }
]


@app.get("/")
async def home():
    """Redirect root to the static frontend upload page."""
    return RedirectResponse(url="/static/index.html", status_code=302)

@app.post("/scan")
async def scan_endpoint(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    content = await file.read()
    code = content.decode("utf-8")

    # Use scanner module
    result = await scan_code(code)

    report_data = {
        "timestamp": result["timestamp"],
        "score": result["score"],
        "grade": result["grade"],
        "vulnerabilities": result["vulnerabilities"],
    }

    # Persist and enqueue LLM enrichment in background
    try:
        reports_collection = await get_reports_collection()
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except Exception as e:
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable")

    try:
        insert_res = await reports_collection.insert_one(report_data)
        report_id = str(insert_res.inserted_id)
    except Exception as e:
        print(f"Database insert error: {e}")
        # still return scan results but no report id
        report_id = None

    # schedule LLM enrichment asynchronously (do not block response)
    if report_id and background_tasks is not None:
        background_tasks.add_task(_background_enrich, report_id, report_data["vulnerabilities"])
    elif report_id:
        # best-effort task
        try:
            import asyncio

            asyncio.create_task(_background_enrich(report_id, report_data["vulnerabilities"]))
        except Exception:
            pass

    response = {"security_score": result["score"], "grade": result["grade"], "vulnerabilities": result["vulnerabilities"]}
    if report_id:
        response["report_id"] = report_id
    return response


async def _background_enrich(report_id: str, vulnerabilities: list):
    try:
        enriched = await enrich_vulnerabilities(report_id, vulnerabilities)
    except Exception as e:
        print(f"LLM enrichment task failed: {e}")
        enriched = None

    if enriched is None:
        return

    # Save enrichment back to DB; be tolerant of errors
    try:
        reports_collection = await get_reports_collection()
        await reports_collection.update_one({"_id": ObjectId(report_id)}, {"$set": {"llm": enriched}})
    except Exception as e:
        print(f"Failed to save LLM enrichment: {e}")

@app.get("/history")
async def get_history():
    # Fetch all reports
    try:
        reports_collection = await get_reports_collection()
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except Exception as e:
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable")

    try:
        docs = await reports_collection.find().to_list(length=100)
    except Exception as e:
        print(f"Database read error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to read from database")

    for doc in docs:
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
    return docs


@app.get("/history/{report_id}")
async def get_report(report_id: str):
    try:
        reports_collection = await get_reports_collection()
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except Exception as e:
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable")

    # Validate ObjectId
    try:
        oid = ObjectId(report_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report id")

    try:
        doc = await reports_collection.find_one({"_id": oid})
    except Exception as e:
        print(f"Database read error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to read from database")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    doc["_id"] = str(doc["_id"])
    return doc


@app.get("/report/{report_id}/pdf")
async def get_report_pdf(report_id: str):
    """Generate and return a PDF for a report."""
    try:
        reports_collection = await get_reports_collection()
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except Exception as e:
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable")

    # Validate ObjectId
    try:
        oid = ObjectId(report_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report id")

    try:
        doc = await reports_collection.find_one({"_id": oid})
    except Exception as e:
        print(f"Database read error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to read from database")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    # Convert MongoDB document for PDF generation
    doc["_id"] = str(doc["_id"])

    # Generate PDF
    try:
        pdf_bytes = await generate_pdf(doc)
    except Exception as e:
        print(f"PDF generation error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate PDF")

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{report_id}.pdf"}
    )


@app.get("/test-db")
async def test_db():
    """Test DB connection and configuration."""
    if not MONGO_URI:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="MONGO_URI not configured")

    try:
        reports_collection = await get_reports_collection()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"DB connection error: {e}")

    return {"collection": "reports", "db_type": str(type(reports_collection))}
