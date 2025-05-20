def generate_ufw_rules(malicious_ips):
    """
    Generate UFW rules for a list of malicious IPs.
    """
    ufw_rules = []
    for ip in malicious_ips:
        ufw_rules.append(f"sudo ufw deny from {ip}")
    
    return ufw_rules  # Return the list of UFW rules

def generate_snort_rules(malicious_ips):
    """
    Generate Snort rules for a list of malicious IPs.
    """
    snort_rules = []
    sid_counter = 1000001  # Start from a basic SID number
    
    for ip in malicious_ips:
        rule = f'alert ip {ip} any -> any any (msg:"Malicious IP detected"; sid:{sid_counter}; rev:1;)'
        snort_rules.append(rule)
        sid_counter += 1  # Increment SID for each rule
    
    return snort_rules  # Return the list of Snort rules
