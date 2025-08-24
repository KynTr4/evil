#!/bin/bash

# Monitor Mode Aktivasyon Scripti
# Evil Twin Attack Toolkit

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "================================================"
echo "           Monitor Mode Aktivasyon"
echo "         Evil Twin Attack Toolkit"
echo "================================================"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[HATA] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo "Kullanım: sudo $0 <interface>"
   exit 1
fi

# Etik uyarı
echo -e "${YELLOW}[UYARI] Bu araç sadece eğitim ve güvenlik testleri içindir!${NC}"
echo -e "${YELLOW}[UYARI] Sadece kendi ağlarınızda veya izinli ortamlarda kullanın!${NC}"
echo -e "${YELLOW}[UYARI] Yasal sorumluluğu kullanıcıya aittir!${NC}"
echo
read -p "Devam etmek için ENTER'a basın veya CTRL+C ile çıkın..."
echo

# Parametre kontrolü
if [ $# -eq 0 ]; then
    echo -e "${RED}[HATA] Interface belirtilmedi!${NC}"
    echo "Kullanım: $0 <interface>"
    echo "Örnek: $0 wlan0"
    echo
    echo "Mevcut wireless interface'ler:"
    iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}'
    exit 1
fi

INTERFACE="$1"
MONITOR_INTERFACE="${INTERFACE}mon"

# Interface varlık kontrolü
if ! iwconfig "$INTERFACE" >/dev/null 2>&1; then
    echo -e "${RED}[HATA] Interface '$INTERFACE' bulunamadı!${NC}"
    echo "Mevcut wireless interface'ler:"
    iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}'
    exit 1
fi

# Gerekli araçları kontrol et
command -v airmon-ng >/dev/null 2>&1 || {
    echo -e "${RED}[HATA] airmon-ng bulunamadı! Aircrack-ng suite yükleyin.${NC}"
    exit 1
}

echo -e "${BLUE}[BİLGİ] Interface: $INTERFACE${NC}"
echo -e "${BLUE}[BİLGİ] Monitor Interface: $MONITOR_INTERFACE${NC}"
echo

# Mevcut monitor interface'i kontrol et
if iwconfig "$MONITOR_INTERFACE" >/dev/null 2>&1; then
    echo -e "${YELLOW}[UYARI] $MONITOR_INTERFACE zaten mevcut!${NC}"
    read -p "Yeniden oluşturmak istiyor musunuz? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[BİLGİ] Mevcut monitor interface kapatılıyor...${NC}"
        airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1
    else
        echo -e "${GREEN}[BAŞARILI] $MONITOR_INTERFACE zaten aktif!${NC}"
        exit 0
    fi
fi

# Çakışan süreçleri kontrol et ve durdur
echo -e "${BLUE}[BİLGİ] Çakışan süreçler kontrol ediliyor...${NC}"
KILL_PROCESSES=$(airmon-ng check 2>/dev/null | grep -E "PID|NetworkManager|wpa_supplicant|dhclient" | grep -v "PID" | awk '{print $2}')

if [ ! -z "$KILL_PROCESSES" ]; then
    echo -e "${YELLOW}[UYARI] Çakışan süreçler bulundu:${NC}"
    echo "$KILL_PROCESSES"
    read -p "Bu süreçleri durdurmak istiyor musunuz? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[BİLGİ] Çakışan süreçler durduruluyor...${NC}"
        airmon-ng check kill >/dev/null 2>&1
    fi
fi

# Interface'i down yap
echo -e "${BLUE}[BİLGİ] Interface kapatılıyor...${NC}"
ifconfig "$INTERFACE" down 2>/dev/null

# Monitor mode'u başlat
echo -e "${BLUE}[BİLGİ] Monitor mode başlatılıyor...${NC}"
airmon-ng start "$INTERFACE" >/dev/null 2>&1

# Başarı kontrolü
if iwconfig "$MONITOR_INTERFACE" >/dev/null 2>&1; then
    echo -e "${GREEN}[BAŞARILI] Monitor mode aktif: $MONITOR_INTERFACE${NC}"
    
    # Interface bilgilerini göster
    echo
    echo -e "${BLUE}[BİLGİ] Interface Durumu:${NC}"
    iwconfig "$MONITOR_INTERFACE" 2>/dev/null | grep -E "Mode|Frequency|Tx-Power"
    
    # Kullanım örnekleri
    echo
    echo -e "${GREEN}[BİLGİ] Kullanım Örnekleri:${NC}"
    echo "  Ağ tarama: sudo ./scripts/scan_networks.sh"
    echo "  Hedef analiz: sudo ./scripts/network_scanner.sh -i $MONITOR_INTERFACE"
    echo "  Evil Twin: sudo ./scripts/start_evil_twin.sh"
    echo "  Restore: sudo ./scripts/restore_interface.sh $INTERFACE"
    
else
    echo -e "${RED}[HATA] Monitor mode başlatılamadı!${NC}"
    echo "Olası nedenler:"
    echo "  - Driver desteği yok"
    echo "  - Interface kullanımda"
    echo "  - Yetki problemi"
    exit 1
fi

echo
echo -e "${GREEN}[TAMAMLANDI] Monitor mode başarıyla aktifleştirildi!${NC}"