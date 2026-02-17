import re
from datetime import datetime
from typing import List, Dict, Any

# Modular rule structure
RULES = [
    {"id": "sql_concat", "name": "SQL Injection Risk", "pattern": r"SELECT.*\+", "severity": "High", "fix": "Use parameterized queries instead of string concatenation."},
    {"id": "debug_true", "name": "Debug Mode Enabled", "pattern": r"debug\s*=\s*True|debug=True", "severity": "Medium", "fix": "Disable debug mode in production."},
    {"id": "hardcoded_password", "name": "Hardcoded Password", "pattern": r"password\s*=\s*['\"].+['\"]", "severity": "High", "fix": "Store secrets in environment variables."},
    {"id": "xss_script", "name": "Reflected XSS (script tag)", "pattern": r"<script[\s>]", "severity": "High", "fix": "Escape or sanitize user input before rendering in HTML."},
    {"id": "eval_usage", "name": "eval() usage", "pattern": r"\beval\s*\(", "severity": "High", "fix": "Avoid eval(); use safer parsing/execution patterns."},
    {"id": "hardcoded_api_key", "name": "Hardcoded API Key", "pattern": r"api_key\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]", "severity": "High", "fix": "Keep API keys in environment variables or vault."},
    {"id": "insecure_http", "name": "Insecure HTTP URL", "pattern": r"http://[\w\.-]+", "severity": "Medium", "fix": "Use HTTPS for all external endpoints."},
    {"id": "weak_hash", "name": "Weak Hashing Function", "pattern": r"\b(md5|sha1)\b", "severity": "High", "fix": "Use modern hashing like bcrypt, scrypt, or Argon2."},
    {"id": "dangerous_subprocess", "name": "Dangerous subprocess usage", "pattern": r"subprocess\.(system|Popen)\s*\(", "severity": "High", "fix": "Avoid shell=True and validate arguments; use safe APIs."},
    {"id": "open_cors", "name": "Open CORS Configuration", "pattern": r"allow_origins\s*=\s*\[?\s*\"\*\"", "severity": "Medium", "fix": "Restrict CORS origins to trusted domains."},
    {"id": "insecure_jwt", "name": "Insecure JWT handling", "pattern": r"jwt\.decode\(|jwt\s*\.\s*encode\(|alg\s*[:=]\s*['\"]?none['\"]?", "severity": "High", "fix": "Use strong algorithms and validate tokens properly."},
    {"id": "exposed_secrets", "name": "Exposed Secret Key", "pattern": r"SECRET_KEY\s*=\s*['\"].{8,}['\"]", "severity": "High", "fix": "Rotate and store secrets securely."}
]

SEVERITY_PENALTY = {"High": 30, "Medium": 15, "Low": 5}


async def scan_code(code: str) -> Dict[str, Any]:
    """Scan code string and return security score, grade, and vulnerabilities."""
    vulnerabilities: List[Dict[str, str]] = []
    score = 100

    for rule in RULES:
        try:
            if re.search(rule["pattern"], code, re.IGNORECASE):
                vulnerabilities.append({
                    "id": rule["id"],
                    "issue": rule["name"],
                    "severity": rule["severity"],
                    "recommended_fix": rule["fix"]
                })
                score -= SEVERITY_PENALTY.get(rule["severity"], 0)
        except re.error:
            # Skip invalid regex
            continue

    if score < 0:
        score = 0

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

    return {"timestamp": datetime.utcnow(), "score": score, "grade": grade, "vulnerabilities": vulnerabilities}
