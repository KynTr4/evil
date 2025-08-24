#!/bin/bash

# Evil Twin Attack - MAC Address Changer Script
# Bu script kablosuz arayüzün MAC adresini değiştirir
# Kullanım: ./change_mac.sh [interface] [new_mac]

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
echo "                     MAC Address Changer                      "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [interface] [new_mac]${NC}"
   exit 1
fi

# Etik uyarı
echo -e "${RED}"
echo "⚠️  ETİK UYARI ⚠️"
echo "MAC adresi değiştirme yalnızca eğitim amaçlı ve kendi cihazlarınızda kullanılmalıdır."
echo "Bu aracı kötü niyetli amaçlarla kullanmak yasadışıdır."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
NEW_MAC="$2"
BACKUP_FILE="/tmp/evil_twin_mac_backup.txt"
LOG_FILE="/tmp/evil_twin_mac_changes.log"

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

# Mevcut ağ arayüzlerini listele
list_interfaces() {
    print_status "Mevcut ağ arayüzleri:"
    echo -e "${CYAN}"
    
    for interface in $(ls /sys/class/net/); do
        if [ "$interface" != "lo" ]; then
            local mac=$(cat /sys/class/net/$interface/address 2>/dev/null)
            local status=$(cat /sys/class/net/$interface/operstate 2>/dev/null)
            local type="unknown"
            
            # Arayüz tipini belirle
            if [ -d "/sys/class/net/$interface/wireless" ]; then
                type="wireless"
            elif [ -f "/sys/class/net/$interface/device/modalias" ]; then
                if grep -q "usb" /sys/class/net/$interface/device/modalias 2>/dev/null; then
                    type="usb"
                else
                    type="ethernet"
                fi
            fi
            
            printf "  %-12s %-18s %-8s %s\n" "$interface" "$mac" "$status" "($type)"
        fi
    done
    echo -e "${NC}"
}

# MAC adresi doğrulama
validate_mac() {
    local mac="$1"
    
    # MAC adresi formatını kontrol et (XX:XX:XX:XX:XX:XX)
    if [[ $mac =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        return 0
    else
        return 1
    fi
}

# Rastgele MAC adresi oluştur
generate_random_mac() {
    local vendor_prefix="$1"
    
    if [ -n "$vendor_prefix" ]; then
        # Belirli vendor prefix ile
        case $vendor_prefix in
            "apple")
                printf "04:0c:ce:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
                ;;
            "samsung")
                printf "08:00:28:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
                ;;
            "intel")
                printf "00:1b:77:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
                ;;
            "tp-link")
                printf "50:c7:bf:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
                ;;
            "cisco")
                printf "00:1a:a1:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
                ;;
            *)
                # Genel rastgele (locally administered)
                printf "02:%02x:%02x:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
                ;;
        esac
    else
        # Tamamen rastgele (locally administered)
        printf "02:%02x:%02x:%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
    fi
}

# Vendor bilgisi al
get_vendor_info() {
    local mac="$1"
    local oui=$(echo $mac | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
    
    # Bilinen vendor'lar
    case $oui in
        "00:1B:77"|"00:15:00"|"00:13:02") echo "Intel Corporation" ;;
        "04:0C:CE"|"00:03:93"|"00:16:CB") echo "Apple Inc." ;;
        "08:00:28"|"00:15:B9"|"00:1A:8A") echo "Samsung Electronics" ;;
        "50:C7:BF"|"00:27:19"|"F4:F2:6D") echo "TP-Link Technologies" ;;
        "00:1A:A1"|"00:0F:66"|"00:1C:0E") echo "Cisco Systems" ;;
        "00:50:56"|"00:0C:29"|"00:05:69") echo "VMware Inc." ;;
        "08:00:27") echo "Oracle VirtualBox" ;;
        "52:54:00") echo "QEMU Virtual NIC" ;;
        *) echo "Unknown Vendor" ;;
    esac
}

# Arayüz seçimi
select_interface() {
    if [ -z "$INTERFACE" ]; then
        list_interfaces
        echo
        read -p "MAC adresini değiştirilecek arayüzü seçin: " INTERFACE
    fi
    
    # Arayüz varlığını kontrol et
    if [ ! -d "/sys/class/net/$INTERFACE" ]; then
        print_error "Arayüz '$INTERFACE' bulunamadı!"
        list_interfaces
        exit 1
    fi
    
    print_success "Seçilen arayüz: $INTERFACE"
}

# Mevcut MAC adresini göster
show_current_mac() {
    local current_mac=$(cat /sys/class/net/$INTERFACE/address)
    local vendor=$(get_vendor_info $current_mac)
    
    print_status "Mevcut MAC adresi: $current_mac"
    print_status "Vendor: $vendor"
    
    # Arayüz durumunu göster
    local status=$(cat /sys/class/net/$INTERFACE/operstate 2>/dev/null)
    print_status "Arayüz durumu: $status"
    
    echo
}

# MAC adresi seçimi
select_mac() {
    if [ -z "$NEW_MAC" ]; then
        echo -e "${YELLOW}MAC adresi seçenekleri:${NC}"
        echo "1) Rastgele MAC adresi oluştur"
        echo "2) Belirli vendor ile rastgele MAC"
        echo "3) Manuel MAC adresi gir"
        echo "4) Önceki MAC adresini geri yükle"
        echo
        
        read -p "Seçiminizi yapın (1-4): " choice
        
        case $choice in
            1)
                NEW_MAC=$(generate_random_mac)
                print_status "Rastgele MAC oluşturuldu: $NEW_MAC"
                ;;
            2)
                echo
                echo "Vendor seçenekleri:"
                echo "1) Apple"
                echo "2) Samsung"
                echo "3) Intel"
                echo "4) TP-Link"
                echo "5) Cisco"
                echo
                read -p "Vendor seçin (1-5): " vendor_choice
                
                case $vendor_choice in
                    1) NEW_MAC=$(generate_random_mac "apple") ;;
                    2) NEW_MAC=$(generate_random_mac "samsung") ;;
                    3) NEW_MAC=$(generate_random_mac "intel") ;;
                    4) NEW_MAC=$(generate_random_mac "tp-link") ;;
                    5) NEW_MAC=$(generate_random_mac "cisco") ;;
                    *) NEW_MAC=$(generate_random_mac) ;;
                esac
                
                print_status "Vendor MAC oluşturuldu: $NEW_MAC"
                ;;
            3)
                read -p "Yeni MAC adresini girin (XX:XX:XX:XX:XX:XX): " NEW_MAC
                ;;
            4)
                restore_previous_mac
                return
                ;;
            *)
                print_error "Geçersiz seçim!"
                exit 1
                ;;
        esac
    fi
    
    # MAC adresini doğrula
    if ! validate_mac "$NEW_MAC"; then
        print_error "Geçersiz MAC adresi formatı: $NEW_MAC"
        print_status "Doğru format: XX:XX:XX:XX:XX:XX (örn: 02:1a:2b:3c:4d:5e)"
        exit 1
    fi
    
    # Vendor bilgisini göster
    local vendor=$(get_vendor_info $NEW_MAC)
    print_status "Yeni MAC vendor: $vendor"
}

# Önceki MAC adresini geri yükle
restore_previous_mac() {
    if [ ! -f "$BACKUP_FILE" ]; then
        print_error "Backup dosyası bulunamadı: $BACKUP_FILE"
        exit 1
    fi
    
    # Bu arayüz için son backup'ı bul
    local backup_line=$(grep "^$INTERFACE:" "$BACKUP_FILE" | tail -1)
    
    if [ -z "$backup_line" ]; then
        print_error "Bu arayüz için backup bulunamadı: $INTERFACE"
        exit 1
    fi
    
    # Orijinal MAC adresini çıkar
    local original_mac=$(echo $backup_line | cut -d: -f2-7)
    
    print_status "Backup'tan bulunan orijinal MAC: $original_mac"
    
    # MAC adresini geri yükle
    change_mac_address "$original_mac" "restore"
    
    print_success "MAC adresi başarıyla geri yüklendi!"
    exit 0
}

# MAC adresini değiştir
change_mac_address() {
    local new_mac="$1"
    local operation="${2:-change}"
    
    # Mevcut MAC adresini kaydet
    local current_mac=$(cat /sys/class/net/$INTERFACE/address)
    
    if [ "$operation" != "restore" ]; then
        # Backup oluştur
        echo "$INTERFACE:$current_mac:$new_mac:$(date)" >> "$BACKUP_FILE"
        print_status "MAC backup oluşturuldu"
    fi
    
    print_status "MAC adresi değiştiriliyor..."
    
    # Arayüzü kapat
    print_status "Arayüz kapatılıyor..."
    ip link set $INTERFACE down
    
    if [ $? -ne 0 ]; then
        print_error "Arayüz kapatılamadı!"
        return 1
    fi
    
    sleep 1
    
    # MAC adresini değiştir
    print_status "MAC adresi ayarlanıyor..."
    ip link set dev $INTERFACE address $new_mac
    
    if [ $? -ne 0 ]; then
        print_error "MAC adresi değiştirilemedi!"
        
        # Arayüzü tekrar aç
        ip link set $INTERFACE up
        return 1
    fi
    
    sleep 1
    
    # Arayüzü aç
    print_status "Arayüz açılıyor..."
    ip link set $INTERFACE up
    
    if [ $? -ne 0 ]; then
        print_error "Arayüz açılamadı!"
        return 1
    fi
    
    sleep 2
    
    # Değişikliği doğrula
    local actual_mac=$(cat /sys/class/net/$INTERFACE/address)
    
    if [ "$actual_mac" = "$new_mac" ]; then
        print_success "MAC adresi başarıyla değiştirildi!"
        
        # Log'a kaydet
        echo "$(date): $INTERFACE: $current_mac -> $new_mac ($operation)" >> "$LOG_FILE"
        
        return 0
    else
        print_error "MAC adresi değişikliği doğrulanamadı!"
        print_error "Beklenen: $new_mac"
        print_error "Mevcut: $actual_mac"
        return 1
    fi
}

# Değişiklik geçmişini göster
show_history() {
    if [ -f "$LOG_FILE" ]; then
        print_status "MAC değişiklik geçmişi:"
        echo -e "${CYAN}"
        cat "$LOG_FILE" | tail -10
        echo -e "${NC}"
    else
        print_warning "Henüz değişiklik geçmişi yok"
    fi
}

# Backup'ları göster
show_backups() {
    if [ -f "$BACKUP_FILE" ]; then
        print_status "MAC backup'ları:"
        echo -e "${CYAN}"
        echo "Interface    Original MAC      New MAC           Date"
        echo "─────────────────────────────────────────────────────────────"
        
        while IFS=':' read -r interface orig_mac1 orig_mac2 orig_mac3 orig_mac4 orig_mac5 orig_mac6 new_mac1 new_mac2 new_mac3 new_mac4 new_mac5 new_mac6 date_info; do
            local orig_mac="$orig_mac1:$orig_mac2:$orig_mac3:$orig_mac4:$orig_mac5:$orig_mac6"
            local new_mac="$new_mac1:$new_mac2:$new_mac3:$new_mac4:$new_mac5:$new_mac6"
            printf "%-12s %-17s %-17s %s\n" "$interface" "$orig_mac" "$new_mac" "$date_info"
        done < "$BACKUP_FILE"
        
        echo -e "${NC}"
    else
        print_warning "Henüz backup yok"
    fi
}

# Kullanım bilgisi
show_usage() {
    echo -e "${YELLOW}Kullanım:${NC}"
    echo -e "  ${CYAN}$0${NC}                              # İnteraktif mod"
    echo -e "  ${CYAN}$0 wlan0${NC}                       # Belirli arayüz için"
    echo -e "  ${CYAN}$0 wlan0 02:1a:2b:3c:4d:5e${NC}     # Arayüz ve MAC belirt"
    echo -e "  ${CYAN}$0 --history${NC}                   # Değişiklik geçmişi"
    echo -e "  ${CYAN}$0 --backups${NC}                   # Backup'ları göster"
    echo -e "  ${CYAN}$0 --restore wlan0${NC}             # MAC'i geri yükle"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0${NC}                        # Arayüz seç ve MAC değiştir"
    echo -e "  ${CYAN}sudo $0 wlan0${NC}                  # wlan0 için rastgele MAC"
    echo -e "  ${CYAN}sudo $0 --restore wlan0${NC}        # wlan0 MAC'ini geri yükle"
    echo
}

# Ana fonksiyon
main() {
    echo
    print_status "MAC adresi değiştirme işlemi başlatılıyor..."
    echo
    
    # Arayüz seçimi
    select_interface
    echo
    
    # Mevcut MAC adresini göster
    show_current_mac
    
    # Yeni MAC adresi seçimi
    select_mac
    echo
    
    # Onay al
    local current_mac=$(cat /sys/class/net/$INTERFACE/address)
    echo -e "${YELLOW}Değişiklik özeti:${NC}"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}Mevcut MAC:${NC} $current_mac"
    echo -e "  ${CYAN}Yeni MAC:${NC} $NEW_MAC"
    echo
    
    read -p "Bu değişikliği yapmak istediğinizden emin misiniz? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "İşlem iptal edildi"
        exit 0
    fi
    
    # MAC adresini değiştir
    if change_mac_address "$NEW_MAC"; then
        echo
        
        # Sonuç özeti
        echo -e "${GREEN}"
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    MAC DEĞİŞİKLİĞİ TAMAMLANDI                "
        echo "═══════════════════════════════════════════════════════════════"
        echo -e "${NC}"
        
        local final_mac=$(cat /sys/class/net/$INTERFACE/address)
        local vendor=$(get_vendor_info $final_mac)
        
        echo -e "${CYAN}Arayüz:${NC} $INTERFACE"
        echo -e "${CYAN}Eski MAC:${NC} $current_mac"
        echo -e "${CYAN}Yeni MAC:${NC} $final_mac"
        echo -e "${CYAN}Vendor:${NC} $vendor"
        echo
        
        print_success "MAC adresi başarıyla değiştirildi!"
        echo
        
        echo -e "${YELLOW}Geri yüklemek için:${NC}"
        echo -e "  ${CYAN}sudo $0 --restore $INTERFACE${NC}"
        echo
    else
        print_error "MAC adresi değiştirilemedi!"
        exit 1
    fi
}

# Komut satırı argümanlarını işle
case "$1" in
    "-h"|"--help")
        show_usage
        exit 0
        ;;
    "--history")
        show_history
        exit 0
        ;;
    "--backups")
        show_backups
        exit 0
        ;;
    "--restore")
        INTERFACE="$2"
        if [ -z "$INTERFACE" ]; then
            print_error "Restore için arayüz belirtmelisiniz!"
            echo "Kullanım: $0 --restore <interface>"
            exit 1
        fi
        restore_previous_mac
        ;;
    *)
        # Normal işlem
        main
        ;;
esac