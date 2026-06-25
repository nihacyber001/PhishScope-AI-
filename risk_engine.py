def calculate_risk(vt_results):
    """Calculates risk based on VirusTotal stats."""
    if "error" in vt_results:
        return {"risk": "Unknown", "score": 0, "color": "gray", "reason": vt_results["error"]}
    
    if vt_results.get("status") == "unrated":
        return {"risk": "Unrated", "score": 0, "color": "gray", "reason": vt_results["message"]}
        
    stats = vt_results.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    
    if malicious >= 3:
        return {"risk": "Critical", "score": malicious, "color": "#ff4444", "reason": f"{malicious} vendors flagged as malicious."}
    elif malicious > 0 or suspicious >= 2:
        return {"risk": "High", "score": malicious + suspicious, "color": "#ffaa00", "reason": f"{malicious} malicious, {suspicious} suspicious."}
    elif suspicious == 1:
        return {"risk": "Suspicious", "score": 1, "color": "#ffee00", "reason": "1 vendor flagged as suspicious."}
    else:
        return {"risk": "Clean", "score": 0, "color": "#00C851", "reason": f"{harmless} vendors flagged as harmless."}
