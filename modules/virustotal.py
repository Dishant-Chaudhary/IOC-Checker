import requests
import time
import yaml
import re

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

API_KEY = config["virustotal"]["api_key"]
BASE_URL = config["virustotal"]["base_url"]
HEADERS = {'x-apikey': API_KEY}

# def get_ioc_type(ioc):
#     if ioc.startswith("http://") or ioc.startswith("https://"):
#         return "urls"
#     elif all(x.isdigit() for x in ioc.split('.') if x.isdigit()):
#         return "ip_addresses"
#     else:
#         return "domains"

def get_ioc_type(ioc):
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "urls"
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):  # Matches IPv4
        return "ip_addresses"
    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):  # Domain pattern
        return "domains"
    else:
        return "unknown"
    
    #Hashes are not support yet in this function


def check_virustotal(iocs):
    print("\nChecking IOCs on VirusTotal:")
    for ioc in iocs:
        ioc_type = get_ioc_type(ioc)

        if ioc_type == "urls":
            import base64
            encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{BASE_URL}/urls/{encoded_url}"
        else:
            url = f"{BASE_URL}/{ioc_type}/{ioc}"

        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                result = data["data"]["attributes"]["last_analysis_results"] #To show vendor details
                malicious = stats.get("malicious", 0)
                print(f"[{ioc_type.upper()}] {ioc} → Malicious: {malicious}")
                if malicious > 0:
                    print("Vendors flagged as malicious:")
                    for vendor, result in result.items():
                        if result["category"] == "malicious":
                            print(f" - {vendor}: {result['result']}")

            elif response.status_code == 404:
                print(f"[{ioc_type.upper()}] {ioc} → Not found.")

            else:
                print(f"[{ioc_type.upper()}] {ioc} → Error: {response.status_code}")

        except Exception as e:
            print(f"[{ioc_type.upper()}] {ioc} → Request failed: {e}")
        
        time.sleep(15)  # Stay within free API rate limits
