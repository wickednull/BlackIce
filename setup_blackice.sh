#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
# BLACKICE COMMAND — One-shot installer (Debian/Ubuntu + macOS)
# Installs Python venv + pip deps, plus key external CLIs.
# Non-destructive recon only. For authorized testing.
# ─────────────────────────────────────────────────────────────

REQ_TXT_CONTENT='
# Core UI
rich>=13.7.0

# Optional API/scan helpers used by some modules
requests>=2.31.0
beautifulsoup4>=4.12.3
lxml>=5.2.2
python-whois>=0.8.0
dnspython>=2.6.1
geoip2>=4.8.0
shodan>=1.31.0
sslyze>=5.2.0
pip-audit>=2.7.3
weasyprint>=60.2

# Reporting / data (optional, but handy)
Jinja2>=3.1.4
pandas>=2.2.2
openpyxl>=3.1.2
'

echo "[*] Detecting OS…"
OS="$(uname -s)"
if [[ "$OS" == "Darwin" ]]; then
  PLATFORM="macos"
elif [[ -f /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID_LIKE:-}" == *debian* || "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]]; then
    PLATFORM="debian"
  else
    echo "[!] Unsupported Linux distro (expected Debian/Ubuntu-like)."
    exit 1
  fi
else
  echo "[!] Unsupported platform."
  exit 1
fi
echo "[+] Platform: $PLATFORM"

echo "[*] Ensuring base tools (git, python, pip)…"
if [[ "$PLATFORM" == "debian" ]]; then
  sudo apt update
  sudo apt install -y git python3 python3-venv python3-pip curl ca-certificates
elif [[ "$PLATFORM" == "macos" ]]; then
  if ! command -v brew >/dev/null 2>&1; then
    echo "[!] Homebrew not found. Install from https://brew.sh and re-run."
    exit 1
  fi
  brew update
  brew install git python curl
fi

# Repo root (where this script lives)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "[*] Creating Python virtualenv (.venv)…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip wheel setuptools

echo "[*] Writing requirements.txt…"
echo "$REQ_TXT_CONTENT" > requirements.txt

echo "[*] Installing Python packages…"
pip install -r requirements.txt

echo "[*] Creating config and data folders…"
mkdir -p config blackice_dossier/{evidence,scans,reports,graphs,msf}
[[ ! -f config/api_keys.json ]] && cat > config/api_keys.json <<'JSON'
{
  "shodan": "",
  "censys_id": "",
  "censys_secret": "",
  "fofa_email": "",
  "fofa_key": "",
  "ipinfo": ""
}
JSON
[[ ! -f config/settings.json ]] && cat > config/settings.json <<'JSON'
{
  "screenshots_driver": "gowitness",
  "geoip_db": "config/GeoLite2-City.mmdb"
}
JSON

echo "[*] Installing external CLI tooling (non-Python)…"
if [[ "$PLATFORM" == "debian" ]]; then
  # Core CLIs used by modules
  sudo apt install -y \
    nmap dnsutils whois curl netcat-openbsd snmp snmp-mibs-downloader \
    whatweb gobuster testssl.sh pandoc npm golang-go

  # Chromium (try both names)
  sudo apt install -y chromium-browser || sudo apt install -y chromium || true

  # Optional: geoiplookup tool
  sudo apt install -y geoip-bin || true

  # ProjectDiscovery tools via Go (user-local bin)
  export PATH="$HOME/go/bin:$PATH"
  GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  GO111MODULE=on go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest

  # gowitness (screenshots)
  GO111MODULE=on go install github.com/sensepost/gowitness@latest

  # gitleaks
  curl -sSL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sudo bash -s -- -b /usr/local/bin

  # trivy (AquaSec repo)
  if ! command -v trivy >/dev/null 2>&1; then
    sudo apt install -y wget gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -cs) main" | \
      sudo tee /etc/apt/sources.list.d/trivy.list
    sudo apt update && sudo apt install -y trivy
  fi

  # syft & grype (Anchore)
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin

elif [[ "$PLATFORM" == "macos" ]]; then
  brew install nmap bind whois curl ncat net-snmp whatweb gobuster testssl pandoc \
               go node
  # Chromium/Chrome (any is fine)
  brew install --cask google-chrome || true
  brew install chromium || true

  # ProjectDiscovery tools
  export PATH="$HOME/go/bin:$PATH"
  GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  GO111MODULE=on go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest

  # gowitness
  GO111MODULE=on go install github.com/sensepost/gowitness@latest

  # gitleaks
  brew install gitleaks

  # trivy
  brew install trivy

  # syft & grype
  brew install anchore/syft/syft anchore/grype/grype || {
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
  }
fi

# Remind user to export Go bin path in their shell profile
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
  echo 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null || true
  echo 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
fi

echo
echo "────────────────────────────────────────────────────────────"
echo "  BlackIce Command • Setup complete"
echo "  Venv:        $(pwd)/.venv"
echo "  Config:      $(pwd)/config/{api_keys.json,settings.json}"
echo "  Data dir:    $(pwd)/blackice_dossier"
echo "────────────────────────────────────────────────────────────"
echo "Run:"
echo "  source .venv/bin/activate"
echo "  python3 blackice_command.py"
echo "────────────────────────────────────────────────────────────"