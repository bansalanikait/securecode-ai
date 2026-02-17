from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException, status
import re

from bson.objectid import ObjectId
from app.database import get_reports_collection, MONGO_URI

app = FastAPI()

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
    return {"message": "SecureCode AI is running"}

@app.post("/scan")
async def scan_code(file: UploadFile = File(...)):
    content = await file.read()
    code = content.decode("utf-8")

    vulnerabilities = []
    score = 100

    severity_penalty = {
        "High": 30,
        "Medium": 15,
        "Low": 5
    }

    for rule in rules:
        if re.search(rule["pattern"], code, re.IGNORECASE):
            vulnerabilities.append({
                "issue": rule["name"],
                "severity": rule["severity"],
                "recommended_fix": rule["fix"]
            })
            score -= severity_penalty[rule["severity"]]
    if score < 0:
        score = 0

    # Assign grade
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    report_data = {
        "timestamp": datetime.utcnow(),
        "score": score,
        "grade": grade,
        "vulnerabilities": vulnerabilities
    }
    
    # Try to persist report if DB is configured and reachable.
    try:
        reports_collection = await get_reports_collection()
    except RuntimeError as e:
        # configuration problem (MONGO_URI missing)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except Exception as e:
        # connection problem - return a service unavailable error
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable")

    try:
        await reports_collection.insert_one(report_data)
    except Exception as e:
        # Do not fail the whole request on DB insert error; log and return result
        print(f"Database insert error: {e}")

    return {
        "security_score": score,
        "grade": grade,
        "vulnerabilities": vulnerabilities
    }

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
