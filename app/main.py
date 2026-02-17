from fastapi import FastAPI, UploadFile, File
import re

app = FastAPI()

# Simple vulnerability rules
rules = [
    {
        "name": "SQL Injection Risk",
        "pattern": r"SELECT.*\+",
        "severity": "High"
    },
    {
        "name": "Debug Mode Enabled",
        "pattern": r"debug=True",
        "severity": "Medium"
    },
    {
        "name": "Hardcoded Password",
        "pattern": r"password\s*=\s*['\"].+['\"]",
        "severity": "High"
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
                "severity": rule["severity"]
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

    return {
        "security_score": score,
        "grade": grade,
        "vulnerabilities": vulnerabilities
    }
