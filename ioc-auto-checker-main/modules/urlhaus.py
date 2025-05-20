import yaml
import requests
import json
import os

def load_config():
    """Load config.yaml from parent directory."""
    base_dir = os.path.dirname(os.path.dirname(__file__))
    config_path = os.path.join(base_dir, "config.yaml")
    with open(config_path, "r") as file:
        return yaml.safe_load(file)

def query_urlhaus(urls):
    """Query URLHaus for one or more suspicious URLs."""
    config = load_config()
    urlhaus_config = config.get("urlhaus", {})
    api_key = urlhaus_config.get("api_key")
    endpoint = urlhaus_config.get("base_url", "https://urlhaus-api.abuse.ch/v1/url/")

    if not api_key:
        print("API key not found in config.yaml under 'urlhaus.api_key'")
        return

    headers = {"Auth-Key": api_key}

    for url_to_check in urls:
        data = {"url": url_to_check}
        try:
            response = requests.post(endpoint, data=data, headers=headers)
            response.raise_for_status()
            json_response = response.json()

            if json_response.get("query_status") == "ok":
                print(f"\n[+] Results for URL: {url_to_check}")
                print(json.dumps(json_response, indent=4))
            elif json_response.get("query_status") == "no_results":
                print(f"[!] No results found for URL: {url_to_check}")
            else:
                print(f"[!] Unexpected response: {json_response.get('query_status')}")
        except Exception as e:
            print(f"[ERROR] URLHaus request failed for {url_to_check}: {e}")
