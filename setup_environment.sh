#!/bin/bash
# Evil Twin Project Setup Script
# Installs all dependencies and sets up the environment

echo "🔧 Evil Twin Project Setup Starting..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. This is normal for penetration testing tools."
fi

print_status "Updating package lists..."
sudo apt update

print_status "Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv python3-tk

print_status "Installing wireless tools..."
sudo apt install -y aircrack-ng hostapd dnsmasq iptables iw wireless-tools

print_status "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

print_status "Upgrading pip..."
pip install --upgrade pip

print_status "Installing Python dependencies..."
pip install -r requirements.txt

# Handle potential missing dependencies
print_status "Installing additional dependencies..."
pip install flask flask-login werkzeug jinja2
pip install pandas matplotlib numpy
pip install requests

print_status "Setting up project structure..."
# Create necessary directories
mkdir -p logs
mkdir -p output
mkdir -p evidence
mkdir -p uploads

print_status "Setting permissions..."
# Set appropriate permissions for script files
chmod +x scripts/*.sh
chmod +x start_gui.sh

print_status "Creating desktop launcher..."
cat > ~/Desktop/EvilTwin.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Evil Twin Attack Toolkit
Comment=WiFi Security Testing Tool
Exec=bash -c 'cd $(pwd) && sudo python3 gui/evil_twin_gui.py'
Icon=$(pwd)/image/icon.png
Terminal=true
Categories=Security;Network;
EOF

chmod +x ~/Desktop/EvilTwin.desktop

print_status "Running system diagnostics..."

# Check wireless interface
WIRELESS_INTERFACE=$(iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | head -1 | awk '{print $1}')
if [ -n "$WIRELESS_INTERFACE" ]; then
    print_success "Wireless interface detected: $WIRELESS_INTERFACE"
else
    print_warning "No wireless interface detected. Please check your WiFi adapter."
fi

# Check if monitor mode is supported
if which airmon-ng > /dev/null; then
    print_success "airmon-ng is available"
    airmon-ng --help > /dev/null 2>&1 && print_success "airmon-ng is working"
else
    print_error "airmon-ng not found. Please install aircrack-ng suite."
fi

# Check Python dependencies
print_status "Checking Python dependencies..."
python3 -c "
import sys
modules = ['tkinter', 'flask', 'pandas', 'matplotlib']
missing = []
for module in modules:
    try:
        __import__(module)
        print(f'✅ {module}')
    except ImportError:
        print(f'❌ {module}')
        missing.append(module)

if missing:
    print(f'Missing modules: {missing}')
    sys.exit(1)
else:
    print('All Python dependencies are available!')
"

print_success "Setup completed successfully!"
print_status "Usage instructions:"
echo "  1. GUI Mode: sudo python3 gui/evil_twin_gui.py"
echo "  2. CLI Mode: sudo ./scripts/start_evil_twin.sh"
echo "  3. Web Dashboard: python3 web_dashboard/app.py"
echo ""
print_warning "Remember: Use only for authorized security testing!"
print_warning "This tool is for educational and ethical purposes only."