import urllib3
import json
import os
import yaml

def load_config():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    config_path = os.path.join(base_dir, "config.yaml")
    with open(config_path, "r") as file:
        return yaml.safe_load(file)

def query_threatfox(iocs):
    """Accepts a list of IPs/IOCs and queries each against ThreatFox."""
    config = load_config()
    api_key = config.get("threatfox", {}).get("api_key")
    base_url = config.get("threatfox", {}).get("base_url", "threatfox-api.abuse.ch")

    if not api_key:
        print("[!] API key not found in config.yaml under 'threatfox.api_key'")
        return

    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }

    pool = urllib3.HTTPSConnectionPool(base_url, port=443, maxsize=10, headers=headers)

    for search_term in iocs:
        data = {
            'query': 'search_ioc',
            'search_term': search_term
        }
        json_data = json.dumps(data)

        try:
            response = pool.request("POST", "/api/v1/", body=json_data)
            decoded_response = response.data.decode("utf-8", "ignore")
            result = json.loads(decoded_response)

            print(f"\n[+] Querying ThreatFox for: {search_term}")
            if result.get("query_status") == "ok":
                print("Results from ThreatFox:")
                print(json.dumps(result, indent=4))
            elif result.get("query_status") == "no_results":
                print(f"[!] No results found for: {search_term}")
            else:
                print(f"[!] Error: {result.get('query_status')}")
        except Exception as e:
            print(f"[ERROR] Failed to query ThreatFox for {search_term}: {e}")
