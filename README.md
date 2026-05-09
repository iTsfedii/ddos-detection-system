\# Real-Time DDoS Detection System



A complete DDoS detection and prevention system with three sprints.



\## What This Does



\- Captures network traffic in real-time

\- Detects DDoS attacks automatically

\- Alerts you immediately

\- Blocks malicious IPs automatically



\## Project Sprints



\### Sprint 1: Network Sniffer

\- Captures all network packets

\- Calculates statistics (RPS, unique IPs, ports)

\- Provides API endpoints



\### Sprint 2: Detector \& Dashboard

\- Analyzes traffic for anomalies

\- Detects RPS spikes, IP flooding, port scanning

\- Shows beautiful web dashboard

\- Sends alerts via Slack/logs



\### Sprint 3: IP Blocker

\- Automatically blocks malicious IPs

\- Integrates with Windows Firewall

\- Auto-unblocks after timeout



\## Setup



1\. Activate virtual environment:

&#x20;  venv\\Scripts\\activate



2\. Install dependencies:

&#x20;  pip install -r requirements.txt



3\. Create project folders:

&#x20;  mkdir sprint1 sprint2 sprint2\\templates sprint3 tests



4\. Run dashboard (as Administrator):

&#x20;  cd sprint2

&#x20;  python dashboard.py



5\. Open browser:

&#x20;  http://localhost:5000



\## Requirements



\- Python 3.8+

\- Windows 10/11

\- Administrator privileges (for packet capture)



\## Author



ifsfedii



\## Status



In Development (Sprint 1-3)

