import os
from io import StringIO
from contextlib import redirect_stdout
from modules.utils import extract_iocs_from_file, get_hash_type
from modules import urlhaus, virustotal, threatfox, Malware
from modules import signature_detect

def show_iocs(iocs):
    print("\n===== Extracted IOCs =====")
    print(f"IPs     : {iocs.get('ips', [])}")
    print(f"Domains : {iocs.get('domains', [])}")
    print(f"Hashes  : {iocs.get('hashes', [])}")
    print(f"URLs    : {iocs.get('urls', [])}")
    print("=" * 30)

def process_iocs(iocs):
    show_iocs(iocs)

    for ip in iocs.get("ips", []):
        print(f"\n[IP] -> {ip}")
        virustotal.check_virustotal([ip])
        threatfox.query_threatfox([ip])

    for domain in iocs.get("domains", []):
        print(f"\n[DOMAIN] -> {domain}")
        virustotal.check_virustotal([domain])

    for url in iocs.get("urls", []):
        print(f"\n[URL] -> {url}")
        urlhaus.query_urlhaus([url])

    hashes = iocs.get("hashes", [])
    if hashes:
        print("[HASHES]")
        for h in hashes:
            print(f" - {get_hash_type(h)}: {h}")
        Malware.query_malwarebazaar(hashes)

def main():
    log_file_path = input("Enter log file path (e.g., logs.txt): ").strip()

    if not os.path.exists(log_file_path):
        print(f"Error: {log_file_path} not found.")
        return

    save_choice = input("Do you want to save the result to a file? (yes/no): ").strip().lower()
    save_to_file = save_choice in ['yes', 'y']
    filename = ""

    if save_to_file:
        filename = input("Enter the file name to save results (e.g., result.txt): ").strip()

    # Signature-based detection
    with open(log_file_path, 'r') as f:
        log_lines = f.readlines()

    alerts = signature_detect.detect_attacks(log_lines)
    if alerts:
        print("===== Signature-based Detections =====")
        for alert in alerts:
            print(alert)
        print("=" * 30)

    # IOC extraction and Process
    iocs = extract_iocs_from_file(log_file_path)

    if save_to_file:
        buffer = StringIO()
        with redirect_stdout(buffer):
            process_iocs(iocs)
        output = buffer.getvalue()
        print(output)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Results saved to {filename}")
    else:
        process_iocs(iocs)

if __name__ == "__main__":
    main()
