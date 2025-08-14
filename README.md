# BlackIce
BlackIce Command is a cyberpunk-themed, all-in-one red team and reconnaissance toolkit inspired by NetWatch lore. It fuses OSINT, vulnerability scanning, network mapping, and covert operations into a single console, offering both API-based and API-free modules for maximum flexibility in offensive and defensive cyber operations.


[ NETWATCH CYBER INTELLIGENCE COMMAND SYSTEM ]  
  CODE-NAME: BLACKICE COMMAND  
  ACCESS LEVEL: ALPHA-PRIME  
  LOCATION: OPERATIONS NODE // TYCHO-07  
  STATUS: ONLINE – AUTHORIZED OPS CONSOLE  
──────────────────────────────────────────────  
UNAUTHORIZED ACCESS IS A VIOLATION OF NETWATCH  
STATUTES AND WILL TRIGGER BLACK ICE DEPLOYMENT  
──────────────────────────────────────────────  

## 📜 Overview

**BlackIce Command** is a cyberpunk-themed, all-in-one red team and reconnaissance toolkit inspired by NetWatch lore from Cyberpunk 2077.  
It fuses OSINT, vulnerability scanning, network mapping, and covert operations into a single console, offering both API-based and API-free modules for maximum flexibility in offensive and defensive cyber operations.

---

## ✨ Features

- **Dual-Mode Operation**: Works with or without API keys.
- **OSINT Intelligence Gathering**: API integrations + scraping fallbacks.
- **Vulnerability Scanning**: CVE lookups, exploit matching.
- **Network Mapping**: Nmap integration, service enumeration.
- **Offline Recon Tools**: WHOIS, ASN, IP geolocation, Shodan dorking (scrape mode).
- **Unified Output**: Generates HTML, Markdown, and PDF reports.
- **Cyberpunk UI**: ANSI art banner, neon-themed CLI, NetWatch-style commands.
- **Modular Design**: Drop in new tools without modifying the core.

---

## ⚙️ Installation

**Requirements:**
- Python 3.10+
- `git`, `pip`, `virtualenv`
- Optional: API keys for Shodan, Censys, FOFA, etc.

```bash
# Clone the repository
git clone https://github.com/wickednull/blackice-command.git
cd blackice-command

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Configure API keys
cp config.example.json config.json
nano config.json
```
Usage
```bash
# Activate virtual environment
source venv/bin/activate

# Run BlackIce Command
python blackice.py
```
Once running, select modules from the main menu.
If no API keys are detected, the toolkit automatically switches to offline recon mode.

⸻

🛠 Example Modules
	•	Shodan Search – Find assets & services online.
	•	Censys Recon – Infrastructure intel.
	•	Web Screenshot – Capture service UIs.
	•	CVE Finder – Match exploits to discovered services.
	•	Network Scan – Map hosts and open ports.
	•	Offline WHOIS – Domain/IP registry info.

⸻

⚖️ License

This toolkit is for authorized security testing only.
Use responsibly — you are solely responsible for compliance with all applicable laws.

⸻

👤 Credits

Created by Null_Lyfe.
Inspired by the NetWatch universe in Cyberpunk 2077.
