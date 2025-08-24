#!/bin/bash

# Evil Twin Attack - Interface Restore Script
# Bu script kablosuz arayüzü normal mode'a geri döndürür
# Kullanım: ./restore_interface.sh [interface_name]

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
echo "                   Interface Restore Script                   "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [interface_name]${NC}"
   exit 1
fi

# Parametreler
INTERFACE="$1"
INFO_FILE="/tmp/evil_twin_interface_info.txt"
MAC_BACKUP_FILE="/tmp/evil_twin_mac_backup.txt"

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

# Aktif monitor arayüzleri listele
list_monitor_interfaces() {
    print_status "Aktif monitor arayüzler:"
    echo -e "${CYAN}"
    iwconfig 2>/dev/null | grep -B1 "Mode:Monitor" | grep -E "^[a-zA-Z0-9]+" | while read line; do
        interface=$(echo $line | cut -d' ' -f1)
        echo "  - $interface"
    done
    echo -e "${NC}"
}

# Kayıtlı bilgileri oku
read_saved_info() {
    if [ -f "$INFO_FILE" ]; then
        source "$INFO_FILE"
        print_success "Kayıtlı bilgiler bulundu:"
        echo -e "  ${CYAN}Orijinal Arayüz:${NC} $ORIGINAL_INTERFACE"
        echo -e "  ${CYAN}Monitor Arayüz:${NC} $MONITOR_INTERFACE"
        if [ -n "$ORIGINAL_MAC" ]; then
            echo -e "  ${CYAN}Orijinal MAC:${NC} $ORIGINAL_MAC"
        fi
        return 0
    else
        print_warning "Kayıtlı bilgi dosyası bulunamadı"
        return 1
    fi
}

# Arayüz seçimi
select_interface() {
    if [ -z "$INTERFACE" ]; then
        if read_saved_info; then
            INTERFACE="$MONITOR_INTERFACE"
            print_status "Kayıtlı monitor arayüz kullanılacak: $INTERFACE"
        else
            list_monitor_interfaces
            echo
            read -p "Restore edilecek monitor arayüzü seçin: " INTERFACE
        fi
    fi
    
    # Arayüz kontrolü
    if ! iwconfig "$INTERFACE" &>/dev/null; then
        print_error "Arayüz '$INTERFACE' bulunamadı!"
        list_monitor_interfaces
        exit 1
    fi
    
    print_success "Seçilen arayüz: $INTERFACE"
}

# Monitor mode'u durdur
stop_monitor_mode() {
    print_status "Monitor mode durduruluyor..."
    
    # Airmon-ng ile durdur
    airmon-ng stop $INTERFACE > /tmp/airmon_stop_output.txt 2>&1
    
    # Çıktıyı kontrol et
    if grep -q "monitor mode disabled" /tmp/airmon_stop_output.txt; then
        print_success "Airmon-ng ile monitor mode durduruldu"
        
        # Yeni arayüz adını bul
        NEW_INTERFACE=$(grep "monitor mode disabled" /tmp/airmon_stop_output.txt | grep -oE '[a-zA-Z0-9]+' | tail -1)
        if [ -n "$NEW_INTERFACE" ]; then
            INTERFACE="$NEW_INTERFACE"
            print_status "Yeni arayüz adı: $INTERFACE"
        fi
    else
        # Manuel yöntem
        print_warning "Airmon-ng ile durdurulamadı, manuel deneniyor..."
        
        # Arayüzü kapat
        ip link set $INTERFACE down
        
        # Managed mode'a geç
        iw dev $INTERFACE set type managed
        
        if [ $? -eq 0 ]; then
            # Arayüzü aç
            ip link set $INTERFACE up
            print_success "Manuel olarak managed mode'a geçildi"
        else
            print_error "Managed mode'a geçilemedi!"
            return 1
        fi
    fi
    
    sleep 2
}

# MAC adresini geri yükle
restore_mac_address() {
    if [ -n "$ORIGINAL_MAC" ]; then
        print_status "Orijinal MAC adresi geri yükleniyor..."
        
        # Arayüzü kapat
        ip link set $INTERFACE down
        
        # Orijinal MAC adresini geri yükle
        ip link set dev $INTERFACE address $ORIGINAL_MAC
        
        if [ $? -eq 0 ]; then
            print_success "MAC adresi geri yüklendi: $ORIGINAL_MAC"
        else
            print_error "MAC adresi geri yüklenemedi!"
        fi
        
        # Arayüzü aç
        ip link set $INTERFACE up
        sleep 1
    elif [ -f "$MAC_BACKUP_FILE" ]; then
        # Backup dosyasından MAC adresini bul
        print_status "MAC backup dosyasından aranıyor..."
        
        local mac_line=$(grep "$INTERFACE:" "$MAC_BACKUP_FILE" | tail -1)
        if [ -n "$mac_line" ]; then
            local original_mac=$(echo $mac_line | cut -d':' -f2-7 | cut -d':' -f1-6)
            
            print_status "Backup'tan MAC adresi bulundu: $original_mac"
            
            # Arayüzü kapat
            ip link set $INTERFACE down
            
            # MAC adresini geri yükle
            ip link set dev $INTERFACE address $original_mac
            
            if [ $? -eq 0 ]; then
                print_success "MAC adresi backup'tan geri yüklendi: $original_mac"
            else
                print_error "MAC adresi geri yüklenemedi!"
            fi
            
            # Arayüzü aç
            ip link set $INTERFACE up
            sleep 1
        else
            print_warning "Bu arayüz için MAC backup'ı bulunamadı"
        fi
    else
        print_warning "Orijinal MAC adresi bilgisi bulunamadı"
    fi
}

# Servisleri yeniden başlat
restart_services() {
    print_status "Ağ servislerini yeniden başlatılıyor..."
    
    services=("NetworkManager" "wpa_supplicant" "dhcpcd")
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            print_status "$service başlatılıyor..."
            systemctl start "$service" 2>/dev/null
            
            if systemctl is-active --quiet "$service"; then
                print_success "$service başlatıldı"
            else
                print_warning "$service başlatılamadı (normal olabilir)"
            fi
        fi
    done
    
    sleep 2
}

# Bağlantı testi
test_connection() {
    print_status "Bağlantı testi yapılıyor..."
    
    # Arayüz durumunu kontrol et
    if iwconfig $INTERFACE 2>/dev/null | grep -q "Mode:Managed"; then
        print_success "Arayüz managed mode'da"
    else
        print_warning "Arayüz managed mode'da değil"
    fi
    
    # Ağ taraması testi
    print_status "Ağ tarama testi..."
    timeout 10 iwlist $INTERFACE scan > /tmp/scan_test.txt 2>&1
    
    if [ -s /tmp/scan_test.txt ] && ! grep -q "Interface doesn't support scanning" /tmp/scan_test.txt; then
        local network_count=$(grep -c "ESSID:" /tmp/scan_test.txt)
        print_success "Ağ taraması başarılı ($network_count ağ bulundu)"
    else
        print_warning "Ağ taraması başarısız (normal olabilir)"
    fi
    
    rm -f /tmp/scan_test.txt
}

# Temizlik
cleanup_files() {
    print_status "Geçici dosyalar temizleniyor..."
    
    files_to_remove=(
        "/tmp/airmon_stop_output.txt"
        "/tmp/evil_twin_interface_info.txt"
        "/tmp/scan_test.txt"
    )
    
    for file in "${files_to_remove[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            print_status "Silindi: $file"
        fi
    done
    
    # MAC backup dosyasını güncelle
    if [ -f "$MAC_BACKUP_FILE" ]; then
        # Bu arayüz için kayıtları işaretle
        sed -i "s/^$INTERFACE:/# RESTORED - $INTERFACE:/g" "$MAC_BACKUP_FILE"
    fi
}

# Kullanım bilgisi
show_usage() {
    echo -e "${YELLOW}Kullanım:${NC}"
    echo -e "  ${CYAN}$0${NC}                    # Otomatik restore (kayıtlı bilgilerle)"
    echo -e "  ${CYAN}$0 wlan0mon${NC}          # Belirli arayüzü restore et"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0${NC}              # En son kullanılan arayüzü restore et"
    echo -e "  ${CYAN}sudo $0 wlan0mon${NC}     # wlan0mon arayüzünü restore et"
    echo
}

# Ana fonksiyon
main() {
    echo
    print_status "Interface restore işlemi başlatılıyor..."
    echo
    
    # Arayüz seçimi
    select_interface
    echo
    
    # Monitor mode'u durdur
    stop_monitor_mode
    echo
    
    # MAC adresini geri yükle
    restore_mac_address
    echo
    
    # Servisleri yeniden başlat
    restart_services
    echo
    
    # Bağlantı testi
    test_connection
    echo
    
    # Temizlik
    cleanup_files
    echo
    
    # Özet
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                        RESTORE TAMAMLANDI                    "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "${CYAN}Restore Edilen Arayüz:${NC} $INTERFACE"
    echo -e "${CYAN}Durum:${NC} Normal (Managed) Mode"
    if [ -n "$ORIGINAL_MAC" ]; then
        echo -e "${CYAN}MAC Adresi:${NC} $ORIGINAL_MAC (Geri Yüklendi)"
    fi
    echo
    echo -e "${YELLOW}Artık normal Wi-Fi bağlantısı kurabilirsiniz:${NC}"
    echo -e "  ${CYAN}nmcli device wifi list${NC}                    # Ağları listele"
    echo -e "  ${CYAN}nmcli device wifi connect SSID password PASS${NC}  # Ağa bağlan"
    echo -e "  ${CYAN}iwlist $INTERFACE scan${NC}                    # Manuel tarama"
    echo
    
    print_success "Interface restore işlemi başarıyla tamamlandı!"
}

# Yardım kontrolü
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_usage
    exit 0
fi

# Script başlangıcı
trap 'rm -f /tmp/airmon_stop_output.txt /tmp/scan_test.txt' EXIT
main

# Son kontrol
echo
print_status "Son kontrol yapılıyor..."
if iwconfig $INTERFACE 2>/dev/null | grep -q "Mode:Managed\|IEEE 802.11"; then
    print_success "Arayüz normal mode'da ve hazır!"
    exit 0
else
    print_warning "Arayüz durumu belirsiz, manuel kontrol gerekebilir"
    echo -e "${YELLOW}Manuel kontrol:${NC} iwconfig $INTERFACE"
    exit 1
fi