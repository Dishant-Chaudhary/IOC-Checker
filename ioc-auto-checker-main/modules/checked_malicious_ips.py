import re

# def extract_from_virustotal(output_text):
#     """
#     Extract IPs marked as malicious from VirusTotal output.
#     """
#     malicious_ips = []
#     vt_pattern = re.compile(r"\[IP_ADDRESSES\] (\d+\.\d+\.\d+\.\d+) \u2192 Malicious: (\d+)")

#     for match in vt_pattern.finditer(output_text):
#         ip = match.group(1)
#         count = int(match.group(2))
#         if count > 0:
#             malicious_ips.append(ip)

#     return malicious_ips

def extract_from_virustotal(output_text):
    """
    Extract IPs marked as malicious from VirusTotal output.
    Only include IPs where 'Malicious' count is greater than 0.
    """
    malicious_ips = []

    # Match anything between the IP and "Malicious"
    vt_pattern = re.compile(
        r"\[IP_ADDRESSES\]\s+(\d{1,3}(?:\.\d{1,3}){3}).*?Malicious:\s+(\d+)"
    )

    for match in vt_pattern.finditer(output_text):
        ip = match.group(1)
        count = int(match.group(2))
        if count > 0:
            malicious_ips.append(ip)

    return malicious_ips


def extract_from_threatfox(output_text):
    """
    Extract IPs reported by ThreatFox (exclude if 'no_result').
    """
    malicious_ips = []
    lines = output_text.splitlines()

    for i, line in enumerate(lines):
        if line.startswith("[+] Querying ThreatFox for:"):
            ip = line.split(":")[-1].strip()
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if "Error: no_result" not in next_line:
                    malicious_ips.append(ip)

    return malicious_ips

def extract_malicious_ips_from_file(file_path):
    """
    Given a file path, read the file and extract malicious IPs using the
    extract_from_virustotal and extract_from_threatfox functions.
    """
    try:
        with open(file_path, "r") as f:
            output_data = f.read()

        # Extract malicious IPs from VirusTotal and ThreatFox
        vt_ips = extract_from_virustotal(output_data)
        tf_ips = extract_from_threatfox(output_data)

        # Combine and return unique malicious IPs
        final_ips = sorted(set(vt_ips + tf_ips))

        return final_ips

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

if __name__ == "__main__":
    # Example usage - it can be removed when the script is called by main.py
    malicious_ips = extract_malicious_ips_from_file("output_result.txt")
    print("[+] Malicious IPs Extracted:")
    for ip in malicious_ips:
        print(" -", ip)
