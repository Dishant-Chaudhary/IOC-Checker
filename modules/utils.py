import re

# === Regular Expressions ===
IPV4_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s\)\"\'<>\]]+"  # Improved to avoid trailing junk
# HASH_REGEX = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"  # MD5/SHA1/SHA256
HASH_REGEX = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})\b"

def get_hash_type(h):
    length = len(h)
    return {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
        96: "SHA384 / SHA3-384",
        128: "SHA512"
    }.get(length, "Unknown")

def extract_iocs_from_text(text):
    """Extract IOCs (IPs, domains, URLs, hashes) from a line of text."""
    
    # Step 1: Extract URLs first
    urls = re.findall(URL_REGEX, text)
    
    # Step 2: Remove URLs from text so they don't interfere with domain/ip extraction
    cleaned_text = text
    for url in urls:
        cleaned_text = cleaned_text.replace(url, "")
    
    # Step 3: Extract IPs, domains, hashes from the cleaned text
    ips = re.findall(IPV4_REGEX, cleaned_text)
    domains = re.findall(DOMAIN_REGEX, cleaned_text)
    hashes = re.findall(HASH_REGEX, cleaned_text)
    
    return {
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "urls": list(set(urls)),
        "hashes": list(set(hashes))
    }

def extract_iocs_from_file(file_path):
    """Read a file line-by-line and extract IOCs."""
    all_iocs = {"ips": [], "domains": [], "urls": [], "hashes": []}
    
    with open(file_path, "r") as file:
        for line in file:
            iocs = extract_iocs_from_text(line)
            for key in all_iocs:
                all_iocs[key].extend(iocs[key])
    
    # Remove duplicates
    for key in all_iocs:
        all_iocs[key] = list(set(all_iocs[key]))
    
    return all_iocs
