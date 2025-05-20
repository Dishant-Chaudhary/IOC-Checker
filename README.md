# IOC Auto Checker

## Description

The IOC Checker framework automatically extracts Indicators of Compromise (IOCs) like IPs, Domains, URLs, and hashes from log files, checks them against multiple Threat Intel sources (VirusTotal, Malware Bazaar, ThreatFox, URL Abuse), and generates firewall (UFW) and IDS (Snort) rules to block malicious IOCs. It also includes signature-based detection for tools like Nmap etc

![Alt Text](/Assets/Main%20script.png)

![Alt Text](/Assets/Main1%20script.png)


## Features

- **IOC Extraction**: Extracts IPs, URLs, hashes, and domains from various types of logs (e.g., DNS, HTTPS).
- **IOC Detection**: Checks extracted IOCs against 4 sources (VirusTotal, Malware Bazaar, ThreatFox, URL Abuse) to identify malicious indicators.
- **Signature-Based Detection**: Identifies known attack signatures, such as Nmap scans, and flags them.
- **Rule Generation**: Generates Snort and UFW rules to block detected malicious IOCs.
- **Output**: Displays malicious IOCs in the terminal and/or saves them to a file for later use.
- **Scalability**: Currently supports IP extraction and detection, with plans to extend support for URLs and hashes.


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Cyberpunk-010/ioc-auto-checker.git
   cd ioc-checker-blocker

2. Install required Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Ensure you have the necessary API keys for VirusTotal, Malware Bazaar, ThreatFox, and URL Abuse in the config.yaml file.

## Usage
1. Provide a log file containing potential IOCs
2. Run the main script 
    ```bash
    python main.py 
    ```
3. The script will automatically extract IOCs from the logs and check them against the Threat Intelligence sources.

4. If malicious IOCs are found, the tool will generate Snort and UFW rules to block them.

