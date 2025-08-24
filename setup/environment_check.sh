#!/bin/bash

# Evil Twin Saldırısı - Ortam Kontrol Scripti
# Bu script sistemin Evil Twin saldırısı için hazır olup olmadığını kontrol eder

echo "🔍 Evil Twin Projesi - Ortam Kontrolü"
echo "======================================"

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Kontrol sayaçları
PASSED=0
FAILED=0
WARNING=0

# Fonksiyonlar
check_pass() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED++))
}

check_fail() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠️ $1${NC}"
    ((WARNING++))
}

check_info() {
    echo -e "${BLUE}ℹ️ $1${NC}"
}

# Root yetkisi kontrolü
echo "🔐 Yetki Kontrolü"
echo "------------------"
if [ "$EUID" -eq 0 ]; then
    check_pass "Root yetkisi mevcut"
else
    check_fail "Root yetkisi gerekli (sudo ile çalıştırın)"
fi

# İşletim sistemi kontrolü
echo ""
echo "💻 İşletim Sistemi Kontrolü"
echo "----------------------------"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    check_info "İşletim Sistemi: $PRETTY_NAME"
    if [[ "$ID" == "kali" ]]; then
        check_pass "Kali Linux tespit edildi"
    elif [[ "$ID_LIKE" == *"debian"* ]]; then
        check_warn "Debian tabanlı sistem (Kali Linux önerilir)"
    else
        check_warn "Bilinmeyen sistem (Kali Linux önerilir)"
    fi
else
    check_warn "İşletim sistemi bilgisi alınamadı"
fi

# Kernel versiyonu
KERNEL_VERSION=$(uname -r)
check_info "Kernel Versiyonu: $KERNEL_VERSION"

# Gerekli araçların kontrolü
echo ""
echo "🛠️ Gerekli Araçlar Kontrolü"
echo "----------------------------"

# Temel araçlar
tools=("aircrack-ng" "airmon-ng" "airodump-ng" "aireplay-ng" "hostapd" "dnsmasq" "iptables" "iwconfig" "ifconfig" "macchanger")

for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        VERSION=$("$tool" --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        check_pass "$tool (v$VERSION) yüklü"
    else
        check_fail "$tool yüklü değil"
    fi
done

# Web sunucu kontrolü
echo ""
echo "🌐 Web Sunucu Kontrolü"
echo "----------------------"
web_servers=("lighttpd" "apache2" "nginx")
web_found=false

for server in "${web_servers[@]}"; do
    if command -v "$server" &> /dev/null; then
        check_pass "$server web sunucusu mevcut"
        web_found=true
        break
    fi
done

if [ "$web_found" = false ]; then
    check_fail "Hiçbir web sunucusu bulunamadı"
fi

# PHP kontrolü
if command -v "php" &> /dev/null; then
    PHP_VERSION=$(php -v | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    check_pass "PHP (v$PHP_VERSION) yüklü"
else
    check_fail "PHP yüklü değil"
fi

# Python kontrolü
echo ""
echo "🐍 Python Kontrolü"
echo "------------------"
if command -v "python3" &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    check_pass "Python3 (v$PYTHON_VERSION) yüklü"
    
    # Python kütüphaneleri
    python_libs=("scapy" "requests" "flask")
    for lib in "${python_libs[@]}"; do
        if python3 -c "import $lib" &> /dev/null; then
            check_pass "Python $lib kütüphanesi mevcut"
        else
            check_warn "Python $lib kütüphanesi eksik"
        fi
    done
else
    check_fail "Python3 yüklü değil"
fi

# Kablosuz arayüz kontrolü
echo ""
echo "📡 Kablosuz Arayüz Kontrolü"
echo "---------------------------"
WIRELESS_INTERFACES=$(iwconfig 2>/dev/null | grep -E "^wlan|^wlp" | cut -d' ' -f1)

if [ -z "$WIRELESS_INTERFACES" ]; then
    check_fail "Kablosuz arayüz bulunamadı"
    check_info "USB Wi-Fi adaptörü takılı olduğundan emin olun"
else
    for interface in $WIRELESS_INTERFACES; do
        check_pass "Kablosuz arayüz bulundu: $interface"
        
        # Arayüz durumu
        if ip link show "$interface" | grep -q "UP"; then
            check_info "$interface arayüzü aktif"
        else
            check_warn "$interface arayüzü pasif"
        fi
        
        # Monitor mode desteği
        if iw "$interface" info 2>/dev/null | grep -q "monitor"; then
            check_pass "$interface monitor mode destekliyor"
        else
            check_warn "$interface monitor mode desteği belirsiz"
        fi
        
        # Sürücü bilgisi
        DRIVER=$(readlink "/sys/class/net/$interface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "unknown")
        check_info "$interface sürücüsü: $DRIVER"
    done
fi

# USB Wi-Fi adaptör kontrolü
echo ""
echo "🔌 USB Wi-Fi Adaptör Kontrolü"
echo "-----------------------------"
USB_WIFI=$(lsusb | grep -i -E "wireless|wi-fi|802\.11|atheros|ralink|realtek|broadcom")
if [ -n "$USB_WIFI" ]; then
    check_pass "USB Wi-Fi adaptörü tespit edildi"
    echo "$USB_WIFI" | while read line; do
        check_info "$line"
    done
else
    check_warn "USB Wi-Fi adaptörü tespit edilemedi"
    check_info "Önerilen adaptörler: Alfa AWUS036ACS, TP-Link AC600"
fi

# Kernel modülleri kontrolü
echo ""
echo "🔧 Kernel Modülleri Kontrolü"
echo "----------------------------"
modules=("mac80211" "cfg80211" "ath9k_htc" "rt2800usb")

for module in "${modules[@]}"; do
    if lsmod | grep -q "$module"; then
        check_pass "$module modülü yüklü"
    else
        check_warn "$module modülü yüklü değil"
    fi
done

# Servis durumu kontrolü
echo ""
echo "⚙️ Servis Durumu Kontrolü"
echo "-------------------------"
services=("NetworkManager" "wpa_supplicant" "dhcpcd")

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        check_warn "$service servisi aktif (çakışma riski)"
    else
        check_pass "$service servisi pasif"
    fi
done

# Firewall kontrolü
echo ""
echo "🛡️ Firewall Kontrolü"
echo "--------------------"
if iptables -L | grep -q "Chain"; then
    RULE_COUNT=$(iptables -L | grep -c "^ACCEPT\|^DROP\|^REJECT")
    if [ "$RULE_COUNT" -gt 10 ]; then
        check_warn "Çok sayıda iptables kuralı mevcut ($RULE_COUNT)"
    else
        check_pass "Iptables kuralları normal ($RULE_COUNT)"
    fi
else
    check_fail "Iptables erişilemez"
fi

# Disk alanı kontrolü
echo ""
echo "💾 Disk Alanı Kontrolü"
echo "----------------------"
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -lt 80 ]; then
    check_pass "Disk kullanımı normal (%$DISK_USAGE)"
elif [ "$DISK_USAGE" -lt 90 ]; then
    check_warn "Disk kullanımı yüksek (%$DISK_USAGE)"
else
    check_fail "Disk alanı kritik (%$DISK_USAGE)"
fi

# Bellek kontrolü
echo ""
echo "🧠 Bellek Kontrolü"
echo "------------------"
MEM_TOTAL=$(free -m | awk 'NR==2{print $2}')
MEM_USED=$(free -m | awk 'NR==2{print $3}')
MEM_USAGE=$((MEM_USED * 100 / MEM_TOTAL))

if [ "$MEM_USAGE" -lt 70 ]; then
    check_pass "Bellek kullanımı normal (%$MEM_USAGE)"
elif [ "$MEM_USAGE" -lt 85 ]; then
    check_warn "Bellek kullanımı yüksek (%$MEM_USAGE)"
else
    check_fail "Bellek kullanımı kritik (%$MEM_USAGE)"
fi

check_info "Toplam bellek: ${MEM_TOTAL}MB"

# Proje dizinleri kontrolü
echo ""
echo "📁 Proje Dizinleri Kontrolü"
echo "---------------------------"
directories=("/var/log/evil-twin" "/tmp/evil-twin" "/var/www/evil-twin")

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        check_pass "$dir dizini mevcut"
    else
        check_warn "$dir dizini eksik"
    fi
done

# Özet rapor
echo ""
echo "📊 ÖZET RAPOR"
echo "=============="
echo -e "${GREEN}✅ Başarılı: $PASSED${NC}"
echo -e "${YELLOW}⚠️ Uyarı: $WARNING${NC}"
echo -e "${RED}❌ Hata: $FAILED${NC}"

echo ""
if [ "$FAILED" -eq 0 ]; then
    if [ "$WARNING" -eq 0 ]; then
        echo -e "${GREEN}🎉 Sistem Evil Twin saldırısı için tamamen hazır!${NC}"
    else
        echo -e "${YELLOW}⚠️ Sistem kullanılabilir ancak bazı uyarılar mevcut${NC}"
    fi
else
    echo -e "${RED}❌ Sistem hazır değil. Lütfen hataları düzeltin${NC}"
fi

echo ""
echo "📋 Öneriler:"
if [ "$FAILED" -gt 0 ]; then
    echo "1. ./install_tools.sh scriptini çalıştırın"
    echo "2. USB Wi-Fi adaptörünüzü kontrol edin"
    echo "3. Gerekli servisleri yeniden başlatın"
fi

if [ "$WARNING" -gt 0 ]; then
    echo "1. Çakışan servisleri durdurun"
    echo "2. Monitor mode desteğini test edin"
    echo "3. Sistem kaynaklarını optimize edin"
fi

echo ""
echo "🚀 Sonraki Adımlar:"
echo "1. Monitor mode'u test edin: sudo airmon-ng start wlan0"
echo "2. Ağ taraması yapın: sudo airodump-ng wlan0mon"
echo "3. Evil Twin saldırısını başlatın"
echo ""
echo "📚 Detaylı bilgi için README.md dosyasını okuyun"

# Log dosyası oluştur
echo "$(date): Ortam kontrolü tamamlandı - Başarılı: $PASSED, Uyarı: $WARNING, Hata: $FAILED" >> /var/log/evil-twin/environment_check.log 2>/dev/null || true