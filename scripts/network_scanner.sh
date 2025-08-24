#!/bin/bash

# Evil Twin Attack - Network Scanner Script
# Bu script hedef ağları tarar ve analiz eder
# Kullanım: ./network_scanner.sh [interface] [options]

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
echo "                      Network Scanner                         "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [interface] [options]${NC}"
   exit 1
fi

# Etik uyarı
echo -e "${RED}"
echo "⚠️  ETİK UYARI ⚠️"
echo "Bu araç yalnızca eğitim amaçlı ve kendi ağlarınızda test için kullanılmalıdır."
echo "İzinsiz ağları taramak yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
SCAN_TIME="30"
OUTPUT_DIR="/tmp/evil_twin_scans"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCAN_FILE="$OUTPUT_DIR/scan_$TIMESTAMP.csv"
LOG_FILE="$OUTPUT_DIR/scan_log_$TIMESTAMP.txt"
TARGET_CHANNEL=""
TARGET_BSSID=""
MONITOR_MODE=false
VERBOSE=false
CONTINUOUS=false

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
    echo -e "  ${CYAN}$0 [interface] [options]${NC}"
    echo
    echo -e "${YELLOW}Seçenekler:${NC}"
    echo -e "  ${CYAN}-t, --time <seconds>${NC}     Tarama süresi (varsayılan: 30)"
    echo -e "  ${CYAN}-c, --channel <channel>${NC}  Belirli kanal tara (1-14)"
    echo -e "  ${CYAN}-b, --bssid <bssid>${NC}     Belirli BSSID'yi izle"
    echo -e "  ${CYAN}-o, --output <dir>${NC}      Çıktı dizini"
    echo -e "  ${CYAN}-m, --monitor${NC}           Monitor mode'a otomatik geç"
    echo -e "  ${CYAN}-v, --verbose${NC}           Detaylı çıktı"
    echo -e "  ${CYAN}-C, --continuous${NC}        Sürekli tarama"
    echo -e "  ${CYAN}-h, --help${NC}              Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon${NC}                    # Temel tarama"
    echo -e "  ${CYAN}sudo $0 wlan0mon -t 60 -v${NC}           # 60 saniye detaylı tarama"
    echo -e "  ${CYAN}sudo $0 wlan0 -m -c 6${NC}               # Kanal 6'yı tara (monitor mode)"
    echo -e "  ${CYAN}sudo $0 wlan0mon -b AA:BB:CC:DD:EE:FF${NC} # Belirli BSSID'yi izle"
    echo
}

# Komut satırı argümanlarını işle
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--time)
                SCAN_TIME="$2"
                shift 2
                ;;
            -c|--channel)
                TARGET_CHANNEL="$2"
                shift 2
                ;;
            -b|--bssid)
                TARGET_BSSID="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -m|--monitor)
                MONITOR_MODE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -C|--continuous)
                CONTINUOUS=true
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
                if [ -z "$INTERFACE" ]; then
                    INTERFACE="$1"
                fi
                shift
                ;;
        esac
    done
}

# Monitor arayüzleri listele
list_monitor_interfaces() {
    print_status "Mevcut monitor arayüzler:"
    echo -e "${CYAN}"
    iwconfig 2>/dev/null | grep -B1 "Mode:Monitor" | grep -E "^[a-zA-Z0-9]+" | while read line; do
        interface=$(echo $line | cut -d' ' -f1)
        echo "  - $interface"
    done
    echo -e "${NC}"
}

# Arayüz seçimi ve kontrolü
setup_interface() {
    if [ -z "$INTERFACE" ]; then
        list_monitor_interfaces
        echo
        read -p "Tarama için arayüz seçin: " INTERFACE
    fi
    
    # Arayüz varlığını kontrol et
    if ! iwconfig "$INTERFACE" &>/dev/null; then
        print_error "Arayüz '$INTERFACE' bulunamadı!"
        list_monitor_interfaces
        exit 1
    fi
    
    # Monitor mode kontrolü
    if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
        if [ "$MONITOR_MODE" = true ]; then
            print_status "Monitor mode'a geçiliyor..."
            
            # Monitor mode'a geç
            airmon-ng start "$INTERFACE" > /tmp/airmon_output.txt 2>&1
            
            # Yeni arayüz adını bul
            NEW_INTERFACE=$(grep "monitor mode enabled" /tmp/airmon_output.txt | grep -oE '[a-zA-Z0-9]+mon|mon[0-9]+' | head -1)
            
            if [ -n "$NEW_INTERFACE" ]; then
                INTERFACE="$NEW_INTERFACE"
                print_success "Monitor mode aktif: $INTERFACE"
            else
                print_error "Monitor mode'a geçilemedi!"
                exit 1
            fi
        else
            print_error "Arayüz monitor mode'da değil!"
            print_status "Monitor mode için: $0 -m seçeneğini kullanın"
            exit 1
        fi
    else
        print_success "Monitor mode aktif: $INTERFACE"
    fi
}

# Çıktı dizinini hazırla
setup_output_directory() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        print_status "Çıktı dizini oluşturuldu: $OUTPUT_DIR"
    fi
    
    # Dosya yollarını güncelle
    SCAN_FILE="$OUTPUT_DIR/scan_$TIMESTAMP.csv"
    LOG_FILE="$OUTPUT_DIR/scan_log_$TIMESTAMP.txt"
    
    print_status "Tarama dosyası: $SCAN_FILE"
    print_status "Log dosyası: $LOG_FILE"
}

# Kanal ayarlama
set_channel() {
    if [ -n "$TARGET_CHANNEL" ]; then
        print_status "Kanal $TARGET_CHANNEL'a ayarlanıyor..."
        iwconfig "$INTERFACE" channel "$TARGET_CHANNEL"
        
        if [ $? -eq 0 ]; then
            print_success "Kanal $TARGET_CHANNEL'a ayarlandı"
        else
            print_warning "Kanal ayarlanamadı"
        fi
    fi
}

# Temel ağ taraması
basic_scan() {
    print_status "Temel ağ taraması başlatılıyor..."
    print_status "Süre: $SCAN_TIME saniye"
    
    local airodump_cmd="airodump-ng"
    
    # Kanal belirtilmişse
    if [ -n "$TARGET_CHANNEL" ]; then
        airodump_cmd="$airodump_cmd -c $TARGET_CHANNEL"
    fi
    
    # BSSID belirtilmişse
    if [ -n "$TARGET_BSSID" ]; then
        airodump_cmd="$airodump_cmd --bssid $TARGET_BSSID"
    fi
    
    # Çıktı dosyası
    airodump_cmd="$airodump_cmd -w $OUTPUT_DIR/scan_$TIMESTAMP --output-format csv $INTERFACE"
    
    print_status "Komut: $airodump_cmd"
    
    # Taramayı başlat
    timeout "$SCAN_TIME" $airodump_cmd > /dev/null 2>&1 &
    local scan_pid=$!
    
    # İlerleme göstergesi
    local counter=0
    while [ $counter -lt $SCAN_TIME ] && kill -0 $scan_pid 2>/dev/null; do
        printf "\r${BLUE}[*] Tarama devam ediyor... %d/%d saniye${NC}" $counter $SCAN_TIME
        sleep 1
        ((counter++))
    done
    
    printf "\n"
    
    # Süreci sonlandır
    if kill -0 $scan_pid 2>/dev/null; then
        kill $scan_pid 2>/dev/null
        wait $scan_pid 2>/dev/null
    fi
    
    print_success "Tarama tamamlandı"
}

# Tarama sonuçlarını analiz et
analyze_results() {
    local csv_file="$OUTPUT_DIR/scan_$TIMESTAMP-01.csv"
    
    if [ ! -f "$csv_file" ]; then
        print_error "Tarama sonuç dosyası bulunamadı: $csv_file"
        return 1
    fi
    
    print_status "Tarama sonuçları analiz ediliyor..."
    
    # CSV dosyasını işle
    local ap_count=0
    local client_count=0
    local wep_count=0
    local wpa_count=0
    local open_count=0
    
    # Access Point'leri say
    ap_count=$(grep -c "^[0-9A-Fa-f:]*," "$csv_file" 2>/dev/null || echo "0")
    
    # Güvenlik türlerini say
    if [ -f "$csv_file" ]; then
        wep_count=$(grep "WEP" "$csv_file" | wc -l)
        wpa_count=$(grep "WPA" "$csv_file" | wc -l)
        open_count=$(grep ",OPN," "$csv_file" | wc -l)
    fi
    
    # Özet rapor
    echo
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                        TARAMA ÖZETİ                          "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    echo -e "${CYAN}Toplam Access Point:${NC} $ap_count"
    echo -e "${CYAN}Açık Ağlar (OPN):${NC} $open_count"
    echo -e "${CYAN}WEP Korumalı:${NC} $wep_count"
    echo -e "${CYAN}WPA/WPA2 Korumalı:${NC} $wpa_count"
    echo -e "${CYAN}Tarama Süresi:${NC} $SCAN_TIME saniye"
    echo -e "${CYAN}Kanal:${NC} ${TARGET_CHANNEL:-"Tümü"}"
    echo
    
    # En güçlü sinyaller
    show_strongest_signals "$csv_file"
    
    # Açık ağları göster
    show_open_networks "$csv_file"
    
    # Hedef önerileri
    suggest_targets "$csv_file"
}

# En güçlü sinyalleri göster
show_strongest_signals() {
    local csv_file="$1"
    
    print_status "En güçlü 10 sinyal:"
    echo -e "${CYAN}"
    echo "BSSID             PWR  CH  ESSID"
    echo "─────────────────────────────────────────────────"
    
    # CSV'den güçlü sinyalleri çıkar ve sırala
    awk -F',' '/^[0-9A-Fa-f:]*,/ { 
        if ($4 != "") {
            gsub(/^ +| +$/, "", $1)  # BSSID
            gsub(/^ +| +$/, "", $4)  # Power
            gsub(/^ +| +$/, "", $6)  # Channel
            gsub(/^ +| +$/, "", $14) # ESSID
            if ($4 > -100 && $4 != "") {
                printf "%-17s %-4s %-3s %s\n", $1, $4, $6, $14
            }
        }
    }' "$csv_file" 2>/dev/null | sort -k2 -nr | head -10
    
    echo -e "${NC}"
}

# Açık ağları göster
show_open_networks() {
    local csv_file="$1"
    
    print_status "Açık ağlar (Güvenlik yok):"
    echo -e "${YELLOW}"
    echo "BSSID             PWR  CH  ESSID"
    echo "─────────────────────────────────────────────────"
    
    # Açık ağları filtrele
    awk -F',' '/^[0-9A-Fa-f:]*,/ { 
        if ($6 ~ /OPN/ || $7 == "" || $7 ~ /^[ ]*$/) {
            gsub(/^ +| +$/, "", $1)  # BSSID
            gsub(/^ +| +$/, "", $4)  # Power
            gsub(/^ +| +$/, "", $6)  # Channel
            gsub(/^ +| +$/, "", $14) # ESSID
            if ($4 > -100 && $4 != "") {
                printf "%-17s %-4s %-3s %s\n", $1, $4, $6, $14
            }
        }
    }' "$csv_file" 2>/dev/null | sort -k2 -nr
    
    echo -e "${NC}"
}

# Hedef önerileri
suggest_targets() {
    local csv_file="$1"
    
    print_status "Evil Twin saldırısı için önerilen hedefler:"
    echo -e "${GREEN}"
    echo "BSSID             PWR  CH  SEC   ESSID"
    echo "───────────────────────────────────────────────────────"
    
    # İyi hedefleri filtrele (güçlü sinyal, popüler isimler)
    awk -F',' '/^[0-9A-Fa-f:]*,/ { 
        gsub(/^ +| +$/, "", $1)  # BSSID
        gsub(/^ +| +$/, "", $4)  # Power
        gsub(/^ +| +$/, "", $6)  # Channel
        gsub(/^ +| +$/, "", $7)  # Security
        gsub(/^ +| +$/, "", $14) # ESSID
        
        # Güçlü sinyal ve popüler isimler
        if ($4 > -70 && $4 != "" && $14 != "") {
            # Popüler ağ isimleri
            if ($14 ~ /WiFi|Free|Guest|Public|Cafe|Hotel|Airport|Mall/) {
                printf "%-17s %-4s %-3s %-5s %s [POPÜLER]\n", $1, $4, $6, $7, $14
            }
            # Açık ağlar
            else if ($7 == "" || $7 ~ /OPN/) {
                printf "%-17s %-4s %-3s %-5s %s [AÇIK]\n", $1, $4, $6, $7, $14
            }
            # Güçlü sinyal
            else if ($4 > -50) {
                printf "%-17s %-4s %-3s %-5s %s [GÜÇLÜ]\n", $1, $4, $6, $7, $14
            }
        }
    }' "$csv_file" 2>/dev/null | sort -k2 -nr | head -10
    
    echo -e "${NC}"
}

# Detaylı ağ bilgisi
show_detailed_info() {
    local bssid="$1"
    local csv_file="$OUTPUT_DIR/scan_$TIMESTAMP-01.csv"
    
    if [ ! -f "$csv_file" ]; then
        print_error "Tarama sonuç dosyası bulunamadı"
        return 1
    fi
    
    print_status "Detaylı ağ bilgisi: $bssid"
    
    # BSSID'yi CSV'de ara
    local network_info=$(grep "^$bssid," "$csv_file")
    
    if [ -z "$network_info" ]; then
        print_error "BSSID bulunamadı: $bssid"
        return 1
    fi
    
    # Bilgileri çıkar
    IFS=',' read -ra INFO <<< "$network_info"
    
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                        AĞ DETAYLARI                          "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    echo -e "${CYAN}BSSID:${NC} ${INFO[0]}"
    echo -e "${CYAN}İlk Görülme:${NC} ${INFO[1]}"
    echo -e "${CYAN}Son Görülme:${NC} ${INFO[2]}"
    echo -e "${CYAN}Kanal:${NC} ${INFO[3]}"
    echo -e "${CYAN}Hız:${NC} ${INFO[4]}"
    echo -e "${CYAN}Güvenlik:${NC} ${INFO[5]}"
    echo -e "${CYAN}Şifreleme:${NC} ${INFO[6]}"
    echo -e "${CYAN}Güç:${NC} ${INFO[8]} dBm"
    echo -e "${CYAN}Beacon Sayısı:${NC} ${INFO[9]}"
    echo -e "${CYAN}IV Sayısı:${NC} ${INFO[10]}"
    echo -e "${CYAN}LAN IP:${NC} ${INFO[11]}"
    echo -e "${CYAN}ID Uzunluğu:${NC} ${INFO[12]}"
    echo -e "${CYAN}ESSID:${NC} ${INFO[13]}"
    echo
}

# Sürekli tarama
continuous_scan() {
    print_status "Sürekli tarama modu başlatılıyor..."
    print_warning "Durdurmak için Ctrl+C tuşlayın"
    
    local scan_count=1
    
    while true; do
        echo
        print_status "Tarama #$scan_count başlatılıyor..."
        
        # Yeni timestamp
        TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
        
        # Tarama yap
        basic_scan
        
        # Kısa analiz
        local csv_file="$OUTPUT_DIR/scan_$TIMESTAMP-01.csv"
        if [ -f "$csv_file" ]; then
            local ap_count=$(grep -c "^[0-9A-Fa-f:]*," "$csv_file" 2>/dev/null || echo "0")
            print_success "Tarama #$scan_count tamamlandı - $ap_count AP bulundu"
        fi
        
        ((scan_count++))
        
        # 10 saniye bekle
        print_status "10 saniye bekleniyor..."
        sleep 10
    done
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Arka plan süreçlerini sonlandır
    pkill -f "airodump-ng.*$INTERFACE" 2>/dev/null
    
    # Geçici dosyaları temizle
    rm -f /tmp/airmon_output.txt
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "Network scanner başlatılıyor..."
    echo
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # Arayüzü hazırla
    setup_interface
    
    # Kanal ayarla
    set_channel
    
    echo
    print_status "Tarama parametreleri:"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}Süre:${NC} $SCAN_TIME saniye"
    echo -e "  ${CYAN}Kanal:${NC} ${TARGET_CHANNEL:-"Tümü"}"
    echo -e "  ${CYAN}BSSID:${NC} ${TARGET_BSSID:-"Tümü"}"
    echo -e "  ${CYAN}Çıktı:${NC} $OUTPUT_DIR"
    echo
    
    # Sürekli tarama kontrolü
    if [ "$CONTINUOUS" = true ]; then
        continuous_scan
    else
        # Tek tarama
        basic_scan
        
        # Sonuçları analiz et
        analyze_results
        
        # Detaylı bilgi seçeneği
        echo
        read -p "Belirli bir ağ hakkında detaylı bilgi almak istiyor musunuz? (y/N): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "BSSID girin (XX:XX:XX:XX:XX:XX): " target_bssid
            if [ -n "$target_bssid" ]; then
                show_detailed_info "$target_bssid"
            fi
        fi
    fi
    
    echo
    print_success "Network scanner tamamlandı!"
    echo -e "${YELLOW}Sonuç dosyaları:${NC}"
    echo -e "  ${CYAN}CSV:${NC} $OUTPUT_DIR/scan_$TIMESTAMP-01.csv"
    echo -e "  ${CYAN}Log:${NC} $LOG_FILE"
    echo
}

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main