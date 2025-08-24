#!/bin/bash

# Evil Twin Attack - Monitor Mode Setup Script
# Bu script kablosuz arayüzü monitor mode'a geçirir
# Kullanım: ./setup_monitor.sh [interface_name]

# Renkli çıktı için ANSI kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
echo "═══════════════════════════════════════════════════════════════"
echo "                    EVIL TWIN ATTACK TOOLKIT                  "
echo "                   Monitor Mode Setup Script                  "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [interface_name]${NC}"
   exit 1
fi

# Etik uyarı
echo -e "${RED}"
echo "⚠️  ETİK UYARI ⚠️"
echo "Bu araç yalnızca eğitim amaçlı ve kendi ağlarınızda test için kullanılmalıdır."
echo "İzinsiz ağlara saldırı yapmak yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"
read -p "Devam etmek için 'KABUL' yazın: " consent
if [ "$consent" != "KABUL" ]; then
    echo -e "${RED}[!] İşlem iptal edildi.${NC}"
    exit 1
fi

# Parametreler
INTERFACE="$1"
MONITOR_INTERFACE=""
ORIGINAL_MAC=""
NEW_MAC=""

# Fonksiyonlar
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[⚠] $1${NC}"
}

# Mevcut kablosuz arayüzleri listele
list_interfaces() {
    print_status "Mevcut kablosuz arayüzler:"
    echo -e "${CYAN}"
    iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | while read line; do
        interface=$(echo $line | cut -d' ' -f1)
        if [[ $interface != "lo" && $interface != "eth"* ]]; then
            echo "  - $interface"
        fi
    done
    echo -e "${NC}"
}

# Arayüz seçimi
select_interface() {
    if [ -z "$INTERFACE" ]; then
        list_interfaces
        echo
        read -p "Monitor mode'a geçirilecek arayüzü seçin: " INTERFACE
    fi
    
    # Arayüz kontrolü
    if ! iwconfig "$INTERFACE" &>/dev/null; then
        print_error "Arayüz '$INTERFACE' bulunamadı!"
        list_interfaces
        exit 1
    fi
    
    print_success "Seçilen arayüz: $INTERFACE"
}

# Çakışan servisleri durdur
stop_conflicting_services() {
    print_status "Çakışan servisleri durduruluyor..."
    
    services=("NetworkManager" "wpa_supplicant" "dhcpcd" "avahi-daemon")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_status "$service durduruluyor..."
            systemctl stop "$service" 2>/dev/null
            if [ $? -eq 0 ]; then
                print_success "$service durduruldu"
            else
                print_warning "$service durdurulamadı (zaten durdurulmuş olabilir)"
            fi
        fi
    done
    
    # Çakışan süreçleri öldür
    print_status "Çakışan süreçler kontrol ediliyor..."
    pkill -f wpa_supplicant 2>/dev/null
    pkill -f dhclient 2>/dev/null
    
    sleep 2
}

# MAC adresini kaydet ve değiştir
change_mac_address() {
    print_status "MAC adresi değiştiriliyor..."
    
    # Orijinal MAC adresini kaydet
    ORIGINAL_MAC=$(cat /sys/class/net/$INTERFACE/address)
    print_status "Orijinal MAC: $ORIGINAL_MAC"
    
    # Arayüzü kapat
    ip link set $INTERFACE down
    
    # Yeni rastgele MAC adresi oluştur
    NEW_MAC=$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
    
    # MAC adresini değiştir
    ip link set dev $INTERFACE address $NEW_MAC
    
    if [ $? -eq 0 ]; then
        print_success "MAC adresi değiştirildi: $NEW_MAC"
        
        # MAC değişikliğini dosyaya kaydet
        echo "$INTERFACE:$ORIGINAL_MAC:$NEW_MAC:$(date)" >> /tmp/evil_twin_mac_backup.txt
    else
        print_error "MAC adresi değiştirilemedi!"
        return 1
    fi
    
    # Arayüzü aç
    ip link set $INTERFACE up
    sleep 1
}

# Monitor mode'a geçiş
setup_monitor_mode() {
    print_status "Monitor mode'a geçiliyor..."
    
    # Airmon-ng ile monitor mode'a geç
    airmon-ng start $INTERFACE > /tmp/airmon_output.txt 2>&1
    
    # Monitor arayüz adını bul
    MONITOR_INTERFACE=$(grep "monitor mode enabled" /tmp/airmon_output.txt | grep -oE '[a-zA-Z0-9]+mon|mon[0-9]+' | head -1)
    
    if [ -z "$MONITOR_INTERFACE" ]; then
        # Alternatif yöntem: manuel monitor mode
        print_warning "Airmon-ng ile monitor mode başarısız, manuel deneniyor..."
        
        # Arayüzü kapat
        ip link set $INTERFACE down
        
        # Monitor mode'a geç
        iw dev $INTERFACE set type monitor
        
        if [ $? -eq 0 ]; then
            # Arayüzü aç
            ip link set $INTERFACE up
            MONITOR_INTERFACE=$INTERFACE
            print_success "Manuel monitor mode başarılı: $MONITOR_INTERFACE"
        else
            print_error "Monitor mode'a geçilemedi!"
            return 1
        fi
    else
        print_success "Monitor mode başarılı: $MONITOR_INTERFACE"
    fi
    
    # Monitor mode kontrolü
    sleep 2
    if iwconfig $MONITOR_INTERFACE 2>/dev/null | grep -q "Mode:Monitor"; then
        print_success "Monitor mode doğrulandı"
    else
        print_error "Monitor mode doğrulanamadı!"
        return 1
    fi
}

# Kanal ayarlama
set_channel() {
    local channel="$1"
    
    if [ -n "$channel" ]; then
        print_status "Kanal $channel'a ayarlanıyor..."
        iwconfig $MONITOR_INTERFACE channel $channel
        
        if [ $? -eq 0 ]; then
            print_success "Kanal $channel'a ayarlandı"
        else
            print_warning "Kanal ayarlanamadı"
        fi
    fi
}

# Test fonksiyonu
test_monitor_mode() {
    print_status "Monitor mode testi yapılıyor..."
    
    # Kısa bir airodump-ng testi
    timeout 5 airodump-ng $MONITOR_INTERFACE > /tmp/airodump_test.txt 2>&1 &
    local test_pid=$!
    
    sleep 6
    
    if kill -0 $test_pid 2>/dev/null; then
        kill $test_pid 2>/dev/null
    fi
    
    if [ -s /tmp/airodump_test.txt ]; then
        print_success "Monitor mode testi başarılı"
        return 0
    else
        print_error "Monitor mode testi başarısız"
        return 1
    fi
}

# Bilgileri kaydet
save_interface_info() {
    local info_file="/tmp/evil_twin_interface_info.txt"
    
    cat > $info_file << EOF
# Evil Twin Attack - Interface Information
# Generated: $(date)

ORIGINAL_INTERFACE=$INTERFACE
MONITOR_INTERFACE=$MONITOR_INTERFACE
ORIGINAL_MAC=$ORIGINAL_MAC
NEW_MAC=$NEW_MAC
STATUS=ACTIVE
CREATED=$(date)
EOF
    
    print_success "Arayüz bilgileri kaydedildi: $info_file"
}

# Temizlik fonksiyonu
cleanup() {
    print_status "Temizlik yapılıyor..."
    rm -f /tmp/airmon_output.txt /tmp/airodump_test.txt
}

# Ana fonksiyon
main() {
    echo
    print_status "Monitor mode kurulumu başlatılıyor..."
    echo
    
    # Arayüz seçimi
    select_interface
    echo
    
    # Çakışan servisleri durdur
    stop_conflicting_services
    echo
    
    # MAC adresini değiştir
    if read -p "MAC adresini değiştirmek istiyor musunuz? (y/N): " -n 1 -r; then
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            change_mac_address
            echo
        fi
    else
        echo
    fi
    
    # Monitor mode'a geç
    setup_monitor_mode
    echo
    
    # Kanal ayarlama (opsiyonel)
    read -p "Belirli bir kanala ayarlamak istiyor musunuz? (1-14, boş bırakın): " channel
    if [ -n "$channel" ]; then
        set_channel $channel
        echo
    fi
    
    # Test
    test_monitor_mode
    echo
    
    # Bilgileri kaydet
    save_interface_info
    echo
    
    # Özet
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                        KURULUM TAMAMLANDI                    "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "${CYAN}Orijinal Arayüz:${NC} $INTERFACE"
    echo -e "${CYAN}Monitor Arayüz:${NC} $MONITOR_INTERFACE"
    if [ -n "$ORIGINAL_MAC" ]; then
        echo -e "${CYAN}Orijinal MAC:${NC} $ORIGINAL_MAC"
        echo -e "${CYAN}Yeni MAC:${NC} $NEW_MAC"
    fi
    echo
    echo -e "${YELLOW}Kullanım örnekleri:${NC}"
    echo -e "  ${CYAN}airodump-ng $MONITOR_INTERFACE${NC}                    # Ağları tara"
    echo -e "  ${CYAN}airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX $MONITOR_INTERFACE${NC}  # Belirli ağı izle"
    echo -e "  ${CYAN}aireplay-ng --deauth 10 -a XX:XX:XX:XX:XX:XX $MONITOR_INTERFACE${NC} # Deauth saldırısı"
    echo
    echo -e "${YELLOW}Monitor mode'u kapatmak için:${NC}"
    echo -e "  ${CYAN}./restore_interface.sh${NC}"
    echo
    
    # Temizlik
    cleanup
    
    print_success "Monitor mode kurulumu başarıyla tamamlandı!"
}

# Script başlangıcı
trap cleanup EXIT
main

# Son kontrol
echo
print_status "Son kontrol yapılıyor..."
if iwconfig $MONITOR_INTERFACE 2>/dev/null | grep -q "Mode:Monitor"; then
    print_success "Monitor mode aktif ve hazır!"
    exit 0
else
    print_error "Monitor mode kurulumunda sorun var!"
    exit 1
fi