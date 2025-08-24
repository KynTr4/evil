#!/bin/bash

# Cleanup Script - Evil Twin Attack Toolkit
# Bu script saldırı sonrası temizleme işlemlerini yapar

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[BİLGİ] Evil Twin temizlik işlemi başlatılıyor...${NC}"

# PID dosyalarını kontrol et ve süreçleri durdur
PID_DIR="./logs"

# Hostapd durdur
if [ -f "$PID_DIR/hostapd.pid" ]; then
    HOSTAPD_PID=$(cat "$PID_DIR/hostapd.pid")
    if ps -p $HOSTAPD_PID > /dev/null; then
        echo -e "${YELLOW}[BİLGİ] Hostapd durduruluyor (PID: $HOSTAPD_PID)...${NC}"
        kill -TERM $HOSTAPD_PID 2>/dev/null
        sleep 2
        kill -KILL $HOSTAPD_PID 2>/dev/null
    fi
    rm -f "$PID_DIR/hostapd.pid"
fi

# Dnsmasq durdur
if [ -f "$PID_DIR/dnsmasq.pid" ]; then
    DNSMASQ_PID=$(cat "$PID_DIR/dnsmasq.pid")
    if ps -p $DNSMASQ_PID > /dev/null; then
        echo -e "${YELLOW}[BİLGİ] Dnsmasq durduruluyor (PID: $DNSMASQ_PID)...${NC}"
        kill -TERM $DNSMASQ_PID 2>/dev/null
        sleep 2
        kill -KILL $DNSMASQ_PID 2>/dev/null
    fi
    rm -f "$PID_DIR/dnsmasq.pid"
fi

# SSLstrip durdur
if [ -f "$PID_DIR/sslstrip.pid" ]; then
    SSLSTRIP_PID=$(cat "$PID_DIR/sslstrip.pid")
    if ps -p $SSLSTRIP_PID > /dev/null; then
        echo -e "${YELLOW}[BİLGİ] SSLstrip durduruluyor (PID: $SSLSTRIP_PID)...${NC}"
        kill -TERM $SSLSTRIP_PID 2>/dev/null
        sleep 2
        kill -KILL $SSLSTRIP_PID 2>/dev/null
    fi
    rm -f "$PID_DIR/sslstrip.pid"
fi

# Deauth saldırısı durdur
if [ -f "$PID_DIR/deauth.pid" ]; then
    DEAUTH_PID=$(cat "$PID_DIR/deauth.pid")
    if ps -p $DEAUTH_PID > /dev/null; then
        echo -e "${YELLOW}[BİLGİ] Deauth saldırısı durduruluyor (PID: $DEAUTH_PID)...${NC}"
        kill -TERM $DEAUTH_PID 2>/dev/null
        sleep 2
        kill -KILL $DEAUTH_PID 2>/dev/null
    fi
    rm -f "$PID_DIR/deauth.pid"
fi

# İsimleri ile arama (backup yöntem)
echo -e "${BLUE}[BİLGİ] Kalan süreçler kontrol ediliyor...${NC}"

# Hostapd süreçleri
pkill -f "hostapd.*evil_twin" 2>/dev/null

# Dnsmasq süreçleri
pkill -f "dnsmasq.*evil_twin" 2>/dev/null

# SSLstrip süreçleri
pkill -f "sslstrip" 2>/dev/null

# Airodump/aireplay süreçleri
pkill -f "airodump-ng" 2>/dev/null
pkill -f "aireplay-ng" 2>/dev/null

# IPTables kurallarını temizle
echo -e "${BLUE}[BİLGİ] IPTables kuralları temizleniyor...${NC}"
iptables -t nat -F 2>/dev/null
iptables -F 2>/dev/null
iptables -X 2>/dev/null

# IP forwarding kapat
echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null

# Geçici dosyaları temizle
rm -f /tmp/evil_twin_* 2>/dev/null

echo -e "${GREEN}[BAŞARILI] Temizlik işlemi tamamlandı${NC}"