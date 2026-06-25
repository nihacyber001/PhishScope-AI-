import re

# Dictionary of phishing heuristic categories and their associated keywords/patterns
PHISHING_HEURISTICS = {
    "urgency": [
        r"\burgent\b", r"\bimmediate(?:ly)?\b", r"\baction required\b", 
        r"\bwithin \d+ hours\b", r"\bsoon as possible\b", r"\basap\b"
    ],
    "threats": [
        r"\bsuspend(?:ed)?\b", r"\bterminat(?:e|ed)\b", r"\bclos(?:e|ed) your account\b", 
        r"\block(?:ed)?\b", r"\brestrict(?:ed)?\b", r"\bunauthorized access\b"
    ],
    "credential_harvesting": [
        r"\bverify your (?:account|identity)\b", r"\blogin details\b", 
        r"\bupdate your (?:password|credentials)\b", r"\bclick here to (?:login|log in)\b"
    ],
    "financial_scams": [
        r"\binvoice attached\b", r"\bpayment confirmation\b", r"\bbank details\b", 
        r"\bwire transfer\b", r"\bgift card\b", r"\brefund\b"
    ]
}

def analyze_content(text):
    """
    Analyzes text for phishing heuristics and returns a risk score.
    """
    if not text or not text.strip():
        return {
            "risk": "Clean",
            "score": 0,
            "findings": []
        }
        
    text_lower = text.lower()
    findings = []
    total_score = 0
    
    for category, patterns in PHISHING_HEURISTICS.items():
        matched_in_category = set()
        for pattern in patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                # Add unique matches
                for match in matches:
                    matched_in_category.add(match)
        
        if matched_in_category:
            findings.append({
                "category": category.replace("_", " ").title(),
                "matches": list(matched_in_category)
            })
            total_score += len(matched_in_category)
            
    # Determine risk level based on score
    if total_score >= 3:
        risk = "High"
    elif total_score >= 1:
        risk = "Suspicious"
    else:
        risk = "Clean"
        
    return {
        "risk": risk,
        "score": total_score,
        "findings": findings
    }
