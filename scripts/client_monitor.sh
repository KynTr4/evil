#!/bin/bash

# Evil Twin Attack - Client Monitoring Script
# Bu script hedef ağdaki istemcileri izler ve saldırı etkisini analiz eder
# Kullanım: ./client_monitor.sh [interface] [bssid] [options]

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
echo "                     Client Monitor                           "
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
echo "İzinsiz ağ izleme yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
TARGET_BSSID="$2"
TARGET_CHANNEL=""
MONITOR_DURATION="300"  # 5 dakika
OUTPUT_DIR="/tmp/evil_twin_monitor"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$OUTPUT_DIR/client_monitor_$TIMESTAMP.txt"
CSV_FILE="$OUTPUT_DIR/client_data_$TIMESTAMP.csv"
REPORT_FILE="$OUTPUT_DIR/monitor_report_$TIMESTAMP.html"
AUTO_CHANNEL=false
REAL_TIME=false
TRACK_HANDSHAKES=false
TRACK_PROBES=false
ALERT_THRESHOLD=5
VERBOSE=false
CONTINUOUS=false
EXPORT_JSON=false
SHOW_STATS=true
UPDATE_INTERVAL=5

# Global değişkenler
declare -A CLIENT_DATA
declare -A CLIENT_HISTORY
declare -A PROBE_REQUESTS
declare -A HANDSHAKE_COUNT
START_TIME=$(date +%s)
TOTAL_CLIENTS=0
ACTIVE_CLIENTS=0
DISCONNECTED_CLIENTS=0

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

print_alert() {
    echo -e "${RED}[🚨] $1${NC}"
    echo "$(date): [ALERT] $1" >> "$LOG_FILE"
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
    echo -e "  ${CYAN}-ch, --channel <num>${NC}    Hedef kanal (otomatik tespit için -a)"
    echo -e "  ${CYAN}-d, --duration <sec>${NC}    İzleme süresi (varsayılan: 300)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}      Çıktı dizini"
    echo -e "  ${CYAN}-a, --auto-channel${NC}      Otomatik kanal tespiti"
    echo -e "  ${CYAN}-r, --real-time${NC}         Gerçek zamanlı görüntü"
    echo -e "  ${CYAN}-H, --handshakes${NC}        Handshake'leri izle"
    echo -e "  ${CYAN}-p, --probes${NC}            Probe request'leri izle"
    echo -e "  ${CYAN}-t, --threshold <num>${NC}   Uyarı eşiği (varsayılan: 5)"
    echo -e "  ${CYAN}-u, --update <sec>${NC}      Güncelleme aralığı (varsayılan: 5)"
    echo -e "  ${CYAN}-j, --json${NC}              JSON formatında export"
    echo -e "  ${CYAN}-s, --stats${NC}             İstatistikleri göster"
    echo -e "  ${CYAN}-C, --continuous${NC}        Sürekli izleme"
    echo -e "  ${CYAN}-v, --verbose${NC}           Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}              Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF -r -H -p${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF -a -d 600 -j${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon AA:BB:CC:DD:EE:FF -C -t 10${NC}"
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
            -ch|--channel)
                TARGET_CHANNEL="$2"
                shift 2
                ;;
            -d|--duration)
                MONITOR_DURATION="$2"
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
            -r|--real-time)
                REAL_TIME=true
                shift
                ;;
            -H|--handshakes)
                TRACK_HANDSHAKES=true
                shift
                ;;
            -p|--probes)
                TRACK_PROBES=true
                shift
                ;;
            -t|--threshold)
                ALERT_THRESHOLD="$2"
                shift 2
                ;;
            -u|--update)
                UPDATE_INTERVAL="$2"
                shift 2
                ;;
            -j|--json)
                EXPORT_JSON=true
                shift
                ;;
            -s|--stats)
                SHOW_STATS=true
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
    
    # Dosya yollarını güncelle
    LOG_FILE="$OUTPUT_DIR/client_monitor_$TIMESTAMP.txt"
    CSV_FILE="$OUTPUT_DIR/client_data_$TIMESTAMP.csv"
    REPORT_FILE="$OUTPUT_DIR/monitor_report_$TIMESTAMP.html"
    
    print_status "Log dosyası: $LOG_FILE"
    print_status "CSV dosyası: $CSV_FILE"
    print_status "Rapor dosyası: $REPORT_FILE"
    
    # CSV başlığı
    echo "Timestamp,MAC,Signal,Packets,First_Seen,Last_Seen,Status,Vendor" > "$CSV_FILE"
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
}

# MAC vendor tespiti
get_vendor() {
    local mac="$1"
    local oui=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
    
    case "$oui" in
        "00:50:56"|"00:0C:29"|"00:05:69") echo "VMware" ;;
        "08:00:27") echo "VirtualBox" ;;
        "00:16:3E") echo "Xen" ;;
        "52:54:00") echo "QEMU" ;;
        "AC:DE:48"|"28:CF:E9"|"A4:83:E7") echo "Apple" ;;
        "00:1B:44"|"00:25:00"|"00:50:F2") echo "Microsoft" ;;
        "00:23:24"|"00:26:08"|"D8:50:E6") echo "Samsung" ;;
        "B8:27:EB"|"DC:A6:32") echo "Raspberry Pi" ;;
        "00:E0:4C"|"00:90:A9"|"00:A0:F8") echo "Realtek" ;;
        "00:13:02"|"00:40:05"|"00:E0:91") echo "Cisco" ;;
        *) echo "Unknown" ;;
    esac
}

# İstemci verilerini güncelle
update_client_data() {
    local mac="$1"
    local signal="$2"
    local packets="$3"
    local current_time=$(date +%s)
    
    # İlk görülme zamanı
    if [ -z "${CLIENT_DATA[$mac,first_seen]}" ]; then
        CLIENT_DATA["$mac,first_seen"]="$current_time"
        CLIENT_DATA["$mac,vendor"]=$(get_vendor "$mac")
        ((TOTAL_CLIENTS++))
        
        if [ "$VERBOSE" = true ]; then
            print_status "Yeni istemci tespit edildi: $mac (${CLIENT_DATA[$mac,vendor]})"
        fi
    fi
    
    # Son görülme zamanı
    CLIENT_DATA["$mac,last_seen"]="$current_time"
    CLIENT_DATA["$mac,signal"]="$signal"
    CLIENT_DATA["$mac,packets"]="$packets"
    
    # Durum belirleme
    local time_diff=$((current_time - ${CLIENT_DATA[$mac,last_seen]:-$current_time}))
    if [ "$time_diff" -lt 30 ]; then
        CLIENT_DATA["$mac,status"]="Active"
    elif [ "$time_diff" -lt 120 ]; then
        CLIENT_DATA["$mac,status"]="Idle"
    else
        CLIENT_DATA["$mac,status"]="Disconnected"
    fi
    
    # CSV'ye kaydet
    echo "$(date '+%Y-%m-%d %H:%M:%S'),$mac,$signal,$packets,$(date -d @${CLIENT_DATA[$mac,first_seen]} '+%Y-%m-%d %H:%M:%S'),$(date -d @${CLIENT_DATA[$mac,last_seen]} '+%Y-%m-%d %H:%M:%S'),${CLIENT_DATA[$mac,status]},${CLIENT_DATA[$mac,vendor]}" >> "$CSV_FILE"
}

# Gerçek zamanlı görüntü
show_real_time_display() {
    clear
    
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    CLIENT MONITOR - REAL TIME                "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    local current_time=$(date +%s)
    local elapsed=$((current_time - START_TIME))
    
    echo -e "${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
    echo -e "${CYAN}Kanal:${NC} $TARGET_CHANNEL"
    echo -e "${CYAN}Geçen Süre:${NC} ${elapsed}s / ${MONITOR_DURATION}s"
    echo -e "${CYAN}Güncelleme:${NC} $(date '+%H:%M:%S')"
    echo
    
    # İstatistikler
    local active_count=0
    local idle_count=0
    local disconnected_count=0
    
    for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1 | sort -u); do
        case "${CLIENT_DATA[$mac,status]}" in
            "Active") ((active_count++)) ;;
            "Idle") ((idle_count++)) ;;
            "Disconnected") ((disconnected_count++)) ;;
        esac
    done
    
    echo -e "${GREEN}📊 İSTATİSTİKLER${NC}"
    echo -e "  ${CYAN}Toplam İstemci:${NC} $TOTAL_CLIENTS"
    echo -e "  ${GREEN}Aktif:${NC} $active_count"
    echo -e "  ${YELLOW}Boşta:${NC} $idle_count"
    echo -e "  ${RED}Bağlantı Kesildi:${NC} $disconnected_count"
    echo
    
    # İstemci listesi
    echo -e "${GREEN}👥 İSTEMCİLER${NC}"
    printf "%-18s %-8s %-8s %-12s %-10s %s\n" "MAC Address" "Signal" "Packets" "Status" "Vendor" "Duration"
    echo "────────────────────────────────────────────────────────────────────────────"
    
    for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1 | sort); do
        local signal="${CLIENT_DATA[$mac,signal]:-"N/A"}"
        local packets="${CLIENT_DATA[$mac,packets]:-"0"}"
        local status="${CLIENT_DATA[$mac,status]:-"Unknown"}"
        local vendor="${CLIENT_DATA[$mac,vendor]:-"Unknown"}"
        local first_seen="${CLIENT_DATA[$mac,first_seen]:-$current_time}"
        local duration=$((current_time - first_seen))
        
        # Renk kodlaması
        local color="$NC"
        case "$status" in
            "Active") color="$GREEN" ;;
            "Idle") color="$YELLOW" ;;
            "Disconnected") color="$RED" ;;
        esac
        
        printf "${color}%-18s %-8s %-8s %-12s %-10s %ds${NC}\n" "$mac" "$signal" "$packets" "$status" "$vendor" "$duration"
    done
    
    echo
    
    # Handshake bilgileri
    if [ "$TRACK_HANDSHAKES" = true ]; then
        echo -e "${GREEN}🤝 HANDSHAKES${NC}"
        local total_handshakes=0
        for mac in "${!HANDSHAKE_COUNT[@]}"; do
            echo -e "  ${CYAN}$mac:${NC} ${HANDSHAKE_COUNT[$mac]} handshake"
            ((total_handshakes += ${HANDSHAKE_COUNT[$mac]}))
        done
        echo -e "  ${CYAN}Toplam:${NC} $total_handshakes handshake"
        echo
    fi
    
    # Probe request bilgileri
    if [ "$TRACK_PROBES" = true ]; then
        echo -e "${GREEN}📡 PROBE REQUESTS${NC}"
        for ssid in "${!PROBE_REQUESTS[@]}"; do
            echo -e "  ${CYAN}$ssid:${NC} ${PROBE_REQUESTS[$ssid]} probe"
        done
        echo
    fi
    
    echo -e "${YELLOW}Durdurmak için Ctrl+C tuşlayın${NC}"
}

# İstemcileri izle
monitor_clients() {
    print_status "İstemci izleme başlatılıyor..."
    
    local monitor_file="/tmp/client_monitor_$TIMESTAMP"
    local end_time=$(($(date +%s) + MONITOR_DURATION))
    
    # Airodump-ng başlat
    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$monitor_file" --output-format csv "$INTERFACE" > /dev/null 2>&1 &
    local airodump_pid=$!
    
    print_status "Airodump-ng başlatıldı (PID: $airodump_pid)"
    
    # Handshake izleme
    if [ "$TRACK_HANDSHAKES" = true ]; then
        tshark -i "$INTERFACE" -f "wlan type mgt subtype auth or wlan type mgt subtype assoc-req or wlan type mgt subtype assoc-resp" -T fields -e wlan.sa -e wlan.da -e wlan.fc.type_subtype > /tmp/handshake_monitor_$TIMESTAMP.txt 2>/dev/null &
        local tshark_pid=$!
        print_status "Handshake izleme başlatıldı (PID: $tshark_pid)"
    fi
    
    # Probe request izleme
    if [ "$TRACK_PROBES" = true ]; then
        tshark -i "$INTERFACE" -f "wlan type mgt subtype probe-req" -T fields -e wlan.sa -e wlan_mgt.ssid > /tmp/probe_monitor_$TIMESTAMP.txt 2>/dev/null &
        local probe_pid=$!
        print_status "Probe request izleme başlatıldı (PID: $probe_pid)"
    fi
    
    # İzleme döngüsü
    while [ $(date +%s) -lt $end_time ]; do
        # CSV dosyasını kontrol et
        local csv_file="${monitor_file}-01.csv"
        
        if [ -f "$csv_file" ]; then
            # İstemci verilerini işle
            while IFS=',' read -r bssid first_seen last_seen power packets lan_ip id_length essid key; do
                # Boş satırları atla
                [ -z "$bssid" ] && continue
                
                # BSSID satırlarını atla
                [[ "$bssid" =~ ^[0-9A-Fa-f:]+$ ]] && [ "$essid" != "" ] && continue
                
                # İstemci satırlarını işle
                if [[ "$bssid" =~ ^[0-9A-Fa-f:]+$ ]] && [ -n "$last_seen" ]; then
                    update_client_data "$bssid" "$power" "$packets"
                fi
            done < <(tail -n +2 "$csv_file")
        fi
        
        # Handshake verilerini işle
        if [ "$TRACK_HANDSHAKES" = true ] && [ -f "/tmp/handshake_monitor_$TIMESTAMP.txt" ]; then
            while read -r sa da subtype; do
                [ -n "$sa" ] && [ -n "$da" ] && {
                    HANDSHAKE_COUNT["$sa"]=$((${HANDSHAKE_COUNT[$sa]:-0} + 1))
                }
            done < <(tail -n +1 "/tmp/handshake_monitor_$TIMESTAMP.txt")
        fi
        
        # Probe request verilerini işle
        if [ "$TRACK_PROBES" = true ] && [ -f "/tmp/probe_monitor_$TIMESTAMP.txt" ]; then
            while read -r sa ssid; do
                [ -n "$ssid" ] && [ "$ssid" != "" ] && {
                    PROBE_REQUESTS["$ssid"]=$((${PROBE_REQUESTS[$ssid]:-0} + 1))
                }
            done < <(tail -n +1 "/tmp/probe_monitor_$TIMESTAMP.txt")
        fi
        
        # Gerçek zamanlı görüntü
        if [ "$REAL_TIME" = true ]; then
            show_real_time_display
        fi
        
        # Uyarı kontrolü
        check_alerts
        
        sleep "$UPDATE_INTERVAL"
        
        # Sürekli mod kontrolü
        if [ "$CONTINUOUS" = true ] && [ $(date +%s) -ge $end_time ]; then
            end_time=$(($(date +%s) + MONITOR_DURATION))
        fi
    done
    
    # Süreçleri sonlandır
    kill $airodump_pid 2>/dev/null
    [ -n "$tshark_pid" ] && kill $tshark_pid 2>/dev/null
    [ -n "$probe_pid" ] && kill $probe_pid 2>/dev/null
    
    wait $airodump_pid 2>/dev/null
    [ -n "$tshark_pid" ] && wait $tshark_pid 2>/dev/null
    [ -n "$probe_pid" ] && wait $probe_pid 2>/dev/null
    
    print_success "İstemci izleme tamamlandı"
}

# Uyarı kontrolü
check_alerts() {
    local current_time=$(date +%s)
    local recent_disconnects=0
    
    # Son 60 saniyede bağlantısı kesilen istemci sayısı
    for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1); do
        if [ "${CLIENT_DATA[$mac,status]}" = "Disconnected" ]; then
            local last_seen="${CLIENT_DATA[$mac,last_seen]:-0}"
            if [ $((current_time - last_seen)) -lt 60 ]; then
                ((recent_disconnects++))
            fi
        fi
    done
    
    # Uyarı eşiği kontrolü
    if [ "$recent_disconnects" -ge "$ALERT_THRESHOLD" ]; then
        print_alert "Son 60 saniyede $recent_disconnects istemci bağlantısı kesildi! (Eşik: $ALERT_THRESHOLD)"
    fi
}

# Rapor oluştur
generate_report() {
    print_status "Rapor oluşturuluyor..."
    
    local current_time=$(date +%s)
    local total_duration=$((current_time - START_TIME))
    
    # HTML raporu
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Evil Twin Client Monitor Report</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
        .client-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .client-table th, .client-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .client-table th { background: #34495e; color: white; }
        .active { background: #d5f4e6; }
        .idle { background: #fef9e7; }
        .disconnected { background: #fadbd8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Evil Twin Client Monitor Report</h1>
        <p>Generated: $(date)</p>
        <p>Target BSSID: $TARGET_BSSID | Channel: $TARGET_CHANNEL</p>
        <p>Duration: ${total_duration}s</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>$TOTAL_CLIENTS</h3>
            <p>Total Clients</p>
        </div>
        <div class="stat-box">
            <h3>$(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1 | while read mac; do [ "${CLIENT_DATA[$mac,status]}" = "Active" ] && echo 1; done | wc -l)</h3>
            <p>Active Clients</p>
        </div>
        <div class="stat-box">
            <h3>$(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1 | while read mac; do [ "${CLIENT_DATA[$mac,status]}" = "Disconnected" ] && echo 1; done | wc -l)</h3>
            <p>Disconnected</p>
        </div>
    </div>
    
    <table class="client-table">
        <tr>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Signal (dBm)</th>
            <th>Packets</th>
            <th>Status</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Duration</th>
        </tr>
EOF
    
    # İstemci verilerini tabloya ekle
    for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1 | sort); do
        local signal="${CLIENT_DATA[$mac,signal]:-"N/A"}"
        local packets="${CLIENT_DATA[$mac,packets]:-"0"}"
        local status="${CLIENT_DATA[$mac,status]:-"Unknown"}"
        local vendor="${CLIENT_DATA[$mac,vendor]:-"Unknown"}"
        local first_seen="${CLIENT_DATA[$mac,first_seen]:-$current_time}"
        local last_seen="${CLIENT_DATA[$mac,last_seen]:-$current_time}"
        local duration=$((current_time - first_seen))
        
        local css_class=""
        case "$status" in
            "Active") css_class="active" ;;
            "Idle") css_class="idle" ;;
            "Disconnected") css_class="disconnected" ;;
        esac
        
        cat >> "$REPORT_FILE" << EOF
        <tr class="$css_class">
            <td>$mac</td>
            <td>$vendor</td>
            <td>$signal</td>
            <td>$packets</td>
            <td>$status</td>
            <td>$(date -d @$first_seen '+%Y-%m-%d %H:%M:%S')</td>
            <td>$(date -d @$last_seen '+%Y-%m-%d %H:%M:%S')</td>
            <td>${duration}s</td>
        </tr>
EOF
    done
    
    cat >> "$REPORT_FILE" << EOF
    </table>
</body>
</html>
EOF
    
    print_success "HTML raporu oluşturuldu: $REPORT_FILE"
    
    # JSON export
    if [ "$EXPORT_JSON" = true ]; then
        local json_file="$OUTPUT_DIR/client_data_$TIMESTAMP.json"
        
        echo "{" > "$json_file"
        echo "  \"report_info\": {" >> "$json_file"
        echo "    \"timestamp\": \"$(date -Iseconds)\"," >> "$json_file"
        echo "    \"target_bssid\": \"$TARGET_BSSID\"," >> "$json_file"
        echo "    \"channel\": $TARGET_CHANNEL," >> "$json_file"
        echo "    \"duration\": $total_duration," >> "$json_file"
        echo "    \"total_clients\": $TOTAL_CLIENTS" >> "$json_file"
        echo "  }," >> "$json_file"
        echo "  \"clients\": [" >> "$json_file"
        
        local first=true
        for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1 | sort); do
            [ "$first" = false ] && echo "," >> "$json_file"
            first=false
            
            cat >> "$json_file" << EOF
    {
      "mac": "$mac",
      "vendor": "${CLIENT_DATA[$mac,vendor]:-"Unknown"}",
      "signal": "${CLIENT_DATA[$mac,signal]:-"N/A"}",
      "packets": "${CLIENT_DATA[$mac,packets]:-"0"}",
      "status": "${CLIENT_DATA[$mac,status]:-"Unknown"}",
      "first_seen": ${CLIENT_DATA[$mac,first_seen]:-$current_time},
      "last_seen": ${CLIENT_DATA[$mac,last_seen]:-$current_time},
      "duration": $((current_time - ${CLIENT_DATA[$mac,first_seen]:-$current_time}))
    }EOF
        done
        
        echo "" >> "$json_file"
        echo "  ]" >> "$json_file"
        echo "}" >> "$json_file"
        
        print_success "JSON raporu oluşturuldu: $json_file"
    fi
}

# Özet göster
show_summary() {
    local current_time=$(date +%s)
    local total_duration=$((current_time - START_TIME))
    
    echo
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                      İZLEME SONUÇLARI                        "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    echo -e "${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
    echo -e "${CYAN}Hedef Kanal:${NC} $TARGET_CHANNEL"
    echo -e "${CYAN}İzleme Süresi:${NC} ${total_duration} saniye"
    echo -e "${CYAN}Toplam İstemci:${NC} $TOTAL_CLIENTS"
    
    # Durum istatistikleri
    local active_count=0
    local idle_count=0
    local disconnected_count=0
    
    for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',status$' | cut -d, -f1); do
        case "${CLIENT_DATA[$mac,status]}" in
            "Active") ((active_count++)) ;;
            "Idle") ((idle_count++)) ;;
            "Disconnected") ((disconnected_count++)) ;;
        esac
    done
    
    echo -e "${GREEN}Aktif İstemci:${NC} $active_count"
    echo -e "${YELLOW}Boşta İstemci:${NC} $idle_count"
    echo -e "${RED}Bağlantısı Kesilen:${NC} $disconnected_count"
    
    # Vendor istatistikleri
    echo
    echo -e "${CYAN}Vendor Dağılımı:${NC}"
    declare -A vendor_count
    for mac in $(printf '%s\n' "${!CLIENT_DATA[@]}" | grep ',vendor$' | cut -d, -f1); do
        local vendor="${CLIENT_DATA[$mac,vendor]}"
        vendor_count["$vendor"]=$((${vendor_count[$vendor]:-0} + 1))
    done
    
    for vendor in "${!vendor_count[@]}"; do
        echo -e "  ${CYAN}$vendor:${NC} ${vendor_count[$vendor]}"
    done
    
    echo
    echo -e "${YELLOW}Dosyalar:${NC}"
    echo -e "  ${CYAN}Log:${NC} $LOG_FILE"
    echo -e "  ${CYAN}CSV:${NC} $CSV_FILE"
    echo -e "  ${CYAN}Rapor:${NC} $REPORT_FILE"
    
    if [ "$EXPORT_JSON" = true ]; then
        echo -e "  ${CYAN}JSON:${NC} $OUTPUT_DIR/client_data_$TIMESTAMP.json"
    fi
    
    echo
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Arka plan süreçlerini sonlandır
    pkill -f "airodump-ng.*$INTERFACE" 2>/dev/null
    pkill -f "tshark.*$INTERFACE" 2>/dev/null
    
    # Geçici dosyaları temizle
    rm -f /tmp/channel_detect* /tmp/client_monitor_* /tmp/handshake_monitor_*.txt /tmp/probe_monitor_*.txt
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "Client monitor başlatılıyor..."
    echo
    
    # Parametreleri kontrol et
    validate_parameters
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # Hedef kanal tespit et
    detect_target_channel
    
    # Arayüzü hazırla
    setup_interface
    
    echo
    
    # İzleme parametrelerini göster
    print_status "İzleme parametreleri:"
    echo -e "  ${CYAN}Hedef BSSID:${NC} $TARGET_BSSID"
    echo -e "  ${CYAN}Kanal:${NC} $TARGET_CHANNEL"
    echo -e "  ${CYAN}Süre:${NC} $MONITOR_DURATION saniye"
    echo -e "  ${CYAN}Güncelleme Aralığı:${NC} $UPDATE_INTERVAL saniye"
    echo -e "  ${CYAN}Gerçek Zamanlı:${NC} $([ "$REAL_TIME" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Handshake İzleme:${NC} $([ "$TRACK_HANDSHAKES" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Probe İzleme:${NC} $([ "$TRACK_PROBES" = true ] && echo "Evet" || echo "Hayır")"
    echo
    
    # İzleme başlat
    monitor_clients
    
    # Rapor oluştur
    generate_report
    
    # Özet göster
    show_summary
    
    print_success "Client monitor tamamlandı!"
}

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main