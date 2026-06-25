import os, requests, base64
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": API_KEY} if API_KEY else {}

def check_url(url):
    """Checks a URL against VirusTotal v3 API."""
    if not API_KEY:
        return {"error": "VirusTotal API key not configured."}
    
    # URL-safe Base64 encode the target URL
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    vt_api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(vt_api_url, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"status": "success", "stats": stats, "details": "URL found in VT."}
        elif response.status_code == 404:
            return {"status": "unrated", "message": "URL not previously scanned by VirusTotal."}
        else:
            return {"error": f"VT API returned status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
