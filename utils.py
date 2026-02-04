import hashlib
import os
import requests
import base64
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

HEADERS = {
    "x-apikey": VT_API_KEY
}


def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_lookup(ioc_value: str, ioc_type: str) -> dict :
    """
    Fast VT lookup (NO rescan)
    ioc_type: url | domain | ip | hash
    """

    if not VT_API_KEY:
        raise RuntimeError("VirusTotal API key not found")

    try:
        if ioc_type == "url":
            # VT requires URL to be base64 encoded
            url_id = base64.urlsafe_b64encode(
                ioc_value.encode()
            ).decode().strip("=")

            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"

        elif ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"

        elif ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"

        else:
            return None

        r = requests.get(url, headers=HEADERS, timeout=10)

        if r.status_code != 200:
            return None

        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
        }

    except Exception:
        return None

