
import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")

def scan_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
        return result.json()
    return {"error": "VirusTotal API failed"}

def scan_gsb(url):
    payload = {
        "client": {"clientId": "malscanai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    res = requests.post(gsb_url, json=payload)
    return res.json()
