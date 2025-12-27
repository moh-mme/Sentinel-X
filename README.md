#Sentinel X - Global Intelligence IPS 🛡️🌍
Sentinel X is a high-performance, real-time Intrusion Prevention System (IPS) designed to protect Windows environments from network threats. It combines behavior analysis (DoS protection) with signature-based detection and global threat intelligence.

Key Features 🚀
Behavioral Protection: Automatically detects and blocks DoS/Flood attacks based on custom packet rate thresholds.

Signature Detection (DPI): Deep Packet Inspection to detect known malware signatures (e.g., Nimda Worm).

Global Intelligence (GeoIP): Real-time identification of attacker's Country, City, and ISP.

Team Integration: Instant alerts sent to Discord/Slack with Google Maps location links.

Persistent Logging: All attacks are logged into an SQLite database for forensic analysis.

Native Firewall Integration: Dynamically manages Windows Defender Firewall rules.

Screenshots 📸
[Place a screenshot of your Discord Alert here] [Place a screenshot of the CLI Dashboard here]

Installation & Setup 🛠️
Prerequisites:

Install Npcap (Required for packet sniffing).

Install Python 3.x.

Clone & Install Dependencies:

Bash

git clone https://github.com/moh-mme/Sentinel-X.git
cd Sentinel-X
pip install scapy requests win10toast
Configuration: Open main.py and replace DISCORD_WEBHOOK_URL with your team's webhook link.

Usage 💻
Run the application as Administrator:

Bash

python main.py
To compile as a standalone executable:

Bash

pyinstaller --onefile --uac-admin --icon=icon.ico main.py
Team Roles 👥
Security Analyst: Monitors sentinel_x_global.db for threat patterns.

Incident Responder: Reviews Discord alerts for immediate action.
