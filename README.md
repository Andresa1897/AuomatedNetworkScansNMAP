# NMAP Automation Tool

Welcome to the NMAP Automation Tool repository! This Python script automates NMAP scans and outputs the results to a JSON file. Scan different types of scans based on your needs and save the results for analysis.

## Usage

### Prerequisites
Make sure you have Python installed on your system.

### How to Run
1. Clone the repository:
git clone [Repo_URL]

2. Navigate to the project directory:
cd NMAP-Automation-Tool

3. Run the script:
python nmap_automation.py

### Options
- **Option1 SYN ACK Scan:**
- Fast scan using SYN ACK.
- **Option 2 UDP Scan:**
- Scan for open UDP ports.
- **Option 3 Comprehensive Scan:**
- Detailed scan including service version detection, script scanning, OS detection, etc.

### Input Validation
The tool validates IP addresses and scan types to ensure accurate scanning.

## Output
The scan results are displayed in the console and saved to a `scan_results.json` file in the project directory.

## Example Usage
```bash
Enter the IP address you want to scan: 192.168.1.1
Please enter the type of scan you want to run:
1) SYN-ACK scan
2) UDP Scan
3) Comprehensive Scan
2
Scanning 192.168.1.1...
Scan completed.
{'scan': {'192.168.1.1': {'hostnames': [], 'addresses': {'ipv4': '192.168.1.1'}, 'vendor': {}, 'status': {'state': 'up', 'reason': 'user', 'reason_ttl': 0}, 'tcp': {22: {'product': '', 'name': 'ssh', 'extrainfo': '', 'version': ''}, 80: {'product': 'HTTP...}}}

Scan results are saved to `scan_results.json.`
