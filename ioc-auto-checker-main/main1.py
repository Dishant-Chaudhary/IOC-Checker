import os
from modules.checked_malicious_ips import extract_malicious_ips_from_file
from modules.rule_generator import generate_ufw_rules, generate_snort_rules

def show_malicious_ips(malicious_ips):
    print("\n===== Malicious IPs =====")
    if malicious_ips:
        for ip in sorted(malicious_ips):
            print(f" - {ip}")
    else:
        print("No malicious IPs found.")
    print("=" * 30)

def main():
    # Ask user for the result file 
    result_file = input("Enter the result filename (e.g., result.txt): ").strip()

    # Check if file exists and process
    if not os.path.exists(result_file):
        print(f"Error: {result_file} not found.")
        return

    # Extract malicious IPs from the provided file using the checked_malicious_ips module
    malicious_ips = extract_malicious_ips_from_file(result_file)

    # Show extracted malicious IPs
    show_malicious_ips(malicious_ips)

    if malicious_ips:
        # Ask if the user wants to generate rules
        rule_choice = input("Do you want to generate firewall/IDS rules from malicious IPs? (yes/no): ").strip().lower()

        if rule_choice in ['yes', 'y']:
            print("Select tool to generate rules:")
            print("1. UFW")
            print("2. Snort")
            print("3. Both")
            tool_choice = input("Enter choice (1/2/3): ").strip()
            rules_filename = input("Enter filename to save rules (e.g., rules.txt): ").strip()

            with open(rules_filename, 'w') as f:
                if tool_choice == '1':
                    rules_ufw = generate_ufw_rules(malicious_ips)
                    f.write("\n".join(rules_ufw))
                elif tool_choice == '2':
                    rules_snort = generate_snort_rules(malicious_ips)
                    f.write("\n".join(rules_snort))
                elif tool_choice == '3':
                    rules_ufw = generate_ufw_rules(malicious_ips)
                    rules_snort = generate_snort_rules(malicious_ips)
                    f.write("# UFW Rules\n" + "\n".join(rules_ufw) + "\n\n# Snort Rules\n" + "\n".join(rules_snort))

            print(f"Rules saved to {rules_filename}")
        else:
            print("No rules were generated.")
    else:
        print("No malicious IPs found, skipping rule generation.")

if __name__ == "__main__":
    main()
