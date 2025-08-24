#!/bin/bash

# Evil Twin Attack - Traffic Monitor Script
# Bu script ağ trafiğini izler ve analiz eder
# Kullanım: ./traffic_monitor.sh [interface] [options]

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
echo "                      Traffic Monitor                         "
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
echo "İzinsiz trafik izleme yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
MONITOR_TIME="60"
OUTPUT_DIR="/tmp/evil_twin_traffic"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CAPTURE_FILE="$OUTPUT_DIR/traffic_$TIMESTAMP.pcap"
LOG_FILE="$OUTPUT_DIR/monitor_log_$TIMESTAMP.txt"
STATS_FILE="$OUTPUT_DIR/stats_$TIMESTAMP.txt"
FILTER_BSSID=""
FILTER_CHANNEL=""
REAL_TIME=false
SAVE_CREDENTIALS=false
ANALYZE_PROTOCOLS=false
VERBOSE=false
CONTINUOUS=false
MAX_FILE_SIZE="100M"
ROTATE_FILES=false

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
    echo -e "  ${CYAN}-t, --time <seconds>${NC}     İzleme süresi (varsayılan: 60)"
    echo -e "  ${CYAN}-b, --bssid <bssid>${NC}     Belirli BSSID'yi filtrele"
    echo -e "  ${CYAN}-c, --channel <channel>${NC}  Belirli kanal izle (1-14)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}      Çıktı dizini"
    echo -e "  ${CYAN}-s, --size <size>${NC}       Maksimum dosya boyutu (örn: 100M)"
    echo -e "  ${CYAN}-r, --realtime${NC}          Gerçek zamanlı analiz"
    echo -e "  ${CYAN}-p, --protocols${NC}         Protokol analizi"
    echo -e "  ${CYAN}-C, --continuous${NC}        Sürekli izleme"
    echo -e "  ${CYAN}-R, --rotate${NC}            Dosya rotasyonu"
    echo -e "  ${CYAN}-v, --verbose${NC}           Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}              Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0mon${NC}                    # Temel trafik izleme"
    echo -e "  ${CYAN}sudo $0 wlan0mon -t 300 -r${NC}          # 5 dakika gerçek zamanlı"
    echo -e "  ${CYAN}sudo $0 wlan0mon -b AA:BB:CC:DD:EE:FF${NC} # Belirli AP'yi izle"
    echo -e "  ${CYAN}sudo $0 wlan0mon -c 6 -p${NC}            # Kanal 6 protokol analizi"
    echo
}

# Komut satırı argümanlarını işle
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--time)
                MONITOR_TIME="$2"
                shift 2
                ;;
            -b|--bssid)
                FILTER_BSSID="$2"
                shift 2
                ;;
            -c|--channel)
                FILTER_CHANNEL="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -s|--size)
                MAX_FILE_SIZE="$2"
                shift 2
                ;;
            -r|--realtime)
                REAL_TIME=true
                shift
                ;;
            -p|--protocols)
                ANALYZE_PROTOCOLS=true
                shift
                ;;
            -C|--continuous)
                CONTINUOUS=true
                shift
                ;;
            -R|--rotate)
                ROTATE_FILES=true
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
                if [ -z "$INTERFACE" ]; then
                    INTERFACE="$1"
                fi
                shift
                ;;
        esac
    done
}

# Arayüz kontrolü
validate_interface() {
    if [ -z "$INTERFACE" ]; then
        print_error "Arayüz belirtilmedi!"
        show_usage
        exit 1
    fi
    
    # Arayüz varlığını kontrol et
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
    
    print_success "Arayüz geçerli: $INTERFACE"
}

# Çıktı dizinini hazırla
setup_output_directory() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        print_status "Çıktı dizini oluşturuldu: $OUTPUT_DIR"
    fi
    
    # Dosya yollarını güncelle
    CAPTURE_FILE="$OUTPUT_DIR/traffic_$TIMESTAMP.pcap"
    LOG_FILE="$OUTPUT_DIR/monitor_log_$TIMESTAMP.txt"
    STATS_FILE="$OUTPUT_DIR/stats_$TIMESTAMP.txt"
    
    print_status "Yakalama dosyası: $CAPTURE_FILE"
    print_status "Log dosyası: $LOG_FILE"
    print_status "İstatistik dosyası: $STATS_FILE"
}

# Arayüzü hazırla
setup_interface() {
    print_status "Arayüz hazırlanıyor: $INTERFACE"
    
    # Kanal ayarla
    if [ -n "$FILTER_CHANNEL" ]; then
        print_status "Kanal $FILTER_CHANNEL'a ayarlanıyor..."
        iwconfig "$INTERFACE" channel "$FILTER_CHANNEL"
        
        if [ $? -eq 0 ]; then
            print_success "Kanal $FILTER_CHANNEL'a ayarlandı"
        else
            print_warning "Kanal ayarlanamadı"
        fi
    fi
    
    # Arayüz durumunu göster
    local current_channel=$(iwconfig "$INTERFACE" 2>/dev/null | grep -oP 'Channel[=:]\K[0-9]+' | head -1)
    print_status "Mevcut kanal: ${current_channel:-"Bilinmiyor"}"
}

# Trafik yakalama
start_traffic_capture() {
    print_status "Trafik yakalama başlatılıyor..."
    print_status "Süre: $MONITOR_TIME saniye"
    
    # tcpdump komutu oluştur
    local tcpdump_cmd="tcpdump -i $INTERFACE -w $CAPTURE_FILE"
    
    # Dosya boyutu sınırı
    if [ -n "$MAX_FILE_SIZE" ]; then
        tcpdump_cmd="$tcpdump_cmd -C ${MAX_FILE_SIZE//[^0-9]/}"
    fi
    
    # BSSID filtresi
    if [ -n "$FILTER_BSSID" ]; then
        tcpdump_cmd="$tcpdump_cmd ether host $FILTER_BSSID"
    fi
    
    # Dosya rotasyonu
    if [ "$ROTATE_FILES" = true ]; then
        tcpdump_cmd="$tcpdump_cmd -W 10"
    fi
    
    print_status "Komut: $tcpdump_cmd"
    
    # Yakalamayı başlat
    timeout "$MONITOR_TIME" $tcpdump_cmd > /dev/null 2>&1 &
    local capture_pid=$!
    
    print_success "Yakalama başlatıldı (PID: $capture_pid)"
    
    # Gerçek zamanlı analiz
    if [ "$REAL_TIME" = true ]; then
        start_realtime_analysis &
        local analysis_pid=$!
        print_status "Gerçek zamanlı analiz başlatıldı (PID: $analysis_pid)"
    fi
    
    # İlerleme takibi
    local counter=0
    
    while [ $counter -lt $MONITOR_TIME ] && kill -0 $capture_pid 2>/dev/null; do
        printf "\r${BLUE}[*] Trafik izleniyor... %d/%d saniye${NC}" $counter $MONITOR_TIME
        
        # Dosya boyutu kontrolü (her 10 saniyede)
        if [ $((counter % 10)) -eq 0 ] && [ $counter -gt 0 ]; then
            if [ -f "$CAPTURE_FILE" ]; then
                local file_size=$(du -h "$CAPTURE_FILE" 2>/dev/null | cut -f1 || echo "0")
                if [ "$VERBOSE" = true ]; then
                    printf "\n${CYAN}[*] Dosya boyutu: $file_size${NC}\n"
                fi
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
    
    if [ "$REAL_TIME" = true ] && [ -n "$analysis_pid" ]; then
        kill $analysis_pid 2>/dev/null
        wait $analysis_pid 2>/dev/null
    fi
    
    print_success "Trafik yakalama tamamlandı"
}

# Gerçek zamanlı analiz
start_realtime_analysis() {
    local temp_file="/tmp/realtime_analysis_$TIMESTAMP.txt"
    
    while true; do
        if [ -f "$CAPTURE_FILE" ]; then
            # Son 10 saniyedeki paketleri analiz et
            tshark -r "$CAPTURE_FILE" -T fields -e frame.time -e wlan.sa -e wlan.da -e wlan.fc.type_subtype -e frame.len 2>/dev/null | tail -20 > "$temp_file"
            
            if [ -s "$temp_file" ]; then
                echo -e "\n${CYAN}[Gerçek Zamanlı] Son paketler:${NC}"
                echo "Zaman                 Kaynak            Hedef             Tür    Boyut"
                echo "─────────────────────────────────────────────────────────────────────────"
                
                while IFS=$'\t' read -r time src dst type size; do
                    if [ -n "$time" ]; then
                        printf "%-20s %-17s %-17s %-6s %s\n" "${time:11:8}" "$src" "$dst" "$type" "$size"
                    fi
                done < "$temp_file"
            fi
        fi
        
        sleep 10
    done
    
    rm -f "$temp_file"
}

# Trafik analizi
analyze_traffic() {
    if [ ! -f "$CAPTURE_FILE" ]; then
        print_error "Yakalama dosyası bulunamadı: $CAPTURE_FILE"
        return 1
    fi
    
    print_status "Trafik analizi başlatılıyor..."
    
    # Dosya bilgileri
    local file_size=$(du -h "$CAPTURE_FILE" | cut -f1)
    local packet_count=$(capinfos "$CAPTURE_FILE" 2>/dev/null | grep "Number of packets" | awk '{print $4}' || echo "Bilinmiyor")
    
    print_status "Dosya boyutu: $file_size"
    print_status "Toplam paket: $packet_count"
    
    # Temel istatistikler
    generate_basic_stats
    
    # Protokol analizi
    if [ "$ANALYZE_PROTOCOLS" = true ]; then
        analyze_protocols
    fi
    
    # Access Point analizi
    analyze_access_points
    
    # İstemci analizi
    analyze_clients
    
    # Güvenlik analizi
    analyze_security
    
    # Özet rapor
    generate_summary_report
}

# Temel istatistikler
generate_basic_stats() {
    print_status "Temel istatistikler oluşturuluyor..."
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "                        TRAFİK İSTATİSTİKLERİ                  "
        echo "═══════════════════════════════════════════════════════════════"
        echo
        echo "Yakalama Bilgileri:"
        echo "- Dosya: $CAPTURE_FILE"
        echo "- Boyut: $(du -h "$CAPTURE_FILE" | cut -f1)"
        echo "- Süre: $MONITOR_TIME saniye"
        echo "- Zaman: $(date)"
        echo
        
        # Paket türleri
        echo "Paket Türleri:"
        tshark -r "$CAPTURE_FILE" -T fields -e wlan.fc.type_subtype 2>/dev/null | sort | uniq -c | sort -nr | head -10 | while read count type; do
            case $type in
                "0") echo "- Beacon: $count" ;;
                "1") echo "- Probe Request: $count" ;;
                "5") echo "- Probe Response: $count" ;;
                "8") echo "- Data: $count" ;;
                "12") echo "- Deauth: $count" ;;
                "10") echo "- Disassoc: $count" ;;
                *) echo "- Tür $type: $count" ;;
            esac
        done
        echo
        
        # En aktif MAC adresleri
        echo "En Aktif Cihazlar (Kaynak):"
        tshark -r "$CAPTURE_FILE" -T fields -e wlan.sa 2>/dev/null | grep -v "^$" | sort | uniq -c | sort -nr | head -10 | while read count mac; do
            echo "- $mac: $count paket"
        done
        echo
        
    } > "$STATS_FILE"
    
    print_success "İstatistikler kaydedildi: $STATS_FILE"
}

# Protokol analizi
analyze_protocols() {
    print_status "Protokol analizi yapılıyor..."
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "                        PROTOKOL ANALİZİ                      "
        echo "═══════════════════════════════════════════════════════════════"
        echo
        
        # 802.11 frame türleri
        echo "802.11 Frame Türleri:"
        tshark -r "$CAPTURE_FILE" -T fields -e wlan.fc.type 2>/dev/null | sort | uniq -c | sort -nr | while read count type; do
            case $type in
                "0") echo "- Management: $count" ;;
                "1") echo "- Control: $count" ;;
                "2") echo "- Data: $count" ;;
                *) echo "- Bilinmeyen ($type): $count" ;;
            esac
        done
        echo
        
        # Şifreleme türleri
        echo "Şifreleme Türleri:"
        tshark -r "$CAPTURE_FILE" -T fields -e wlan.fc.protected 2>/dev/null | sort | uniq -c | sort -nr | while read count protected; do
            case $protected in
                "0") echo "- Şifrelenmemiş: $count" ;;
                "1") echo "- Şifrelenmiş: $count" ;;
            esac
        done
        echo
        
        # Üst katman protokoller
        echo "Üst Katman Protokoller:"
        tshark -r "$CAPTURE_FILE" -T fields -e _ws.col.Protocol 2>/dev/null | grep -v "^$" | sort | uniq -c | sort -nr | head -10 | while read count protocol; do
            echo "- $protocol: $count"
        done
        echo
        
    } >> "$STATS_FILE"
    
    print_success "Protokol analizi tamamlandı"
}

# Access Point analizi
analyze_access_points() {
    print_status "Access Point analizi yapılıyor..."
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "                      ACCESS POINT ANALİZİ                    "
        echo "═══════════════════════════════════════════════════════════════"
        echo
        
        # Beacon frame'lerden AP'leri çıkar
        echo "Tespit Edilen Access Point'ler:"
        tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.bssid -e wlan_mgt.ssid -e wlan_mgt.ds.current_channel 2>/dev/null | sort -u | while IFS=$'\t' read -r bssid ssid channel; do
            if [ -n "$bssid" ]; then
                echo "- BSSID: $bssid"
                echo "  SSID: ${ssid:-"(Gizli)"}"
                echo "  Kanal: ${channel:-"Bilinmiyor"}"
                echo
            fi
        done
        
        # En aktif AP'ler
        echo "En Aktif Access Point'ler:"
        tshark -r "$CAPTURE_FILE" -T fields -e wlan.bssid 2>/dev/null | grep -v "^$" | sort | uniq -c | sort -nr | head -10 | while read count bssid; do
            echo "- $bssid: $count paket"
        done
        echo
        
    } >> "$STATS_FILE"
    
    print_success "Access Point analizi tamamlandı"
}

# İstemci analizi
analyze_clients() {
    print_status "İstemci analizi yapılıyor..."
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "                        İSTEMCİ ANALİZİ                       "
        echo "═══════════════════════════════════════════════════════════════"
        echo
        
        # Probe request'lerden istemcileri çıkar
        echo "Aktif İstemciler (Probe Request):"
        tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 4" -T fields -e wlan.sa -e wlan_mgt.ssid 2>/dev/null | sort -u | while IFS=$'\t' read -r client ssid; do
            if [ -n "$client" ]; then
                echo "- İstemci: $client"
                echo "  Aranan SSID: ${ssid:-"(Broadcast)"}"
                echo
            fi
        done
        
        # En aktif istemciler
        echo "En Aktif İstemciler:"
        tshark -r "$CAPTURE_FILE" -T fields -e wlan.sa 2>/dev/null | grep -v "^$" | sort | uniq -c | sort -nr | head -10 | while read count client; do
            echo "- $client: $count paket"
        done
        echo
        
    } >> "$STATS_FILE"
    
    print_success "İstemci analizi tamamlandı"
}

# Güvenlik analizi
analyze_security() {
    print_status "Güvenlik analizi yapılıyor..."
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "                        GÜVENLİK ANALİZİ                      "
        echo "═══════════════════════════════════════════════════════════════"
        echo
        
        # Deauth saldırıları
        local deauth_count=$(tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 12" 2>/dev/null | wc -l)
        echo "Deauthentication Saldırıları: $deauth_count"
        
        if [ "$deauth_count" -gt 0 ]; then
            echo "Deauth Hedefleri:"
            tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 12" -T fields -e wlan.da 2>/dev/null | sort | uniq -c | sort -nr | head -5 | while read count target; do
                echo "- $target: $count saldırı"
            done
        fi
        echo
        
        # WPS saldırıları
        local wps_count=$(tshark -r "$CAPTURE_FILE" -Y "eapol" 2>/dev/null | wc -l)
        echo "WPS/EAPOL Paketleri: $wps_count"
        echo
        
        # Açık ağlar
        echo "Güvenlik Uyarıları:"
        tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.bssid -e wlan_mgt.ssid -e wlan.rsn.version 2>/dev/null | while IFS=$'\t' read -r bssid ssid rsn; do
            if [ -n "$bssid" ] && [ -z "$rsn" ]; then
                echo "- Açık ağ tespit edildi: $bssid (${ssid:-"Gizli"})"
            fi
        done
        echo
        
    } >> "$STATS_FILE"
    
    print_success "Güvenlik analizi tamamlandı"
}

# Özet rapor
generate_summary_report() {
    print_status "Özet rapor oluşturuluyor..."
    
    echo
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "                        TRAFİK ÖZETİ                          "
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    if [ -f "$CAPTURE_FILE" ]; then
        local file_size=$(du -h "$CAPTURE_FILE" | cut -f1)
        local packet_count=$(capinfos "$CAPTURE_FILE" 2>/dev/null | grep "Number of packets" | awk '{print $4}' || echo "Bilinmiyor")
        local ap_count=$(tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.bssid 2>/dev/null | sort -u | wc -l)
        local client_count=$(tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 4" -T fields -e wlan.sa 2>/dev/null | sort -u | wc -l)
        local deauth_count=$(tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 12" 2>/dev/null | wc -l)
        
        echo -e "${CYAN}Yakalama Dosyası:${NC} $CAPTURE_FILE"
        echo -e "${CYAN}Dosya Boyutu:${NC} $file_size"
        echo -e "${CYAN}Toplam Paket:${NC} $packet_count"
        echo -e "${CYAN}Access Point Sayısı:${NC} $ap_count"
        echo -e "${CYAN}İstemci Sayısı:${NC} $client_count"
        echo -e "${CYAN}Deauth Saldırısı:${NC} $deauth_count"
        echo -e "${CYAN}İzleme Süresi:${NC} $MONITOR_TIME saniye"
        echo -e "${CYAN}Filtre BSSID:${NC} ${FILTER_BSSID:-"Yok"}"
        echo -e "${CYAN}Filtre Kanal:${NC} ${FILTER_CHANNEL:-"Yok"}"
    else
        print_error "Yakalama dosyası bulunamadı"
    fi
    
    echo
    print_status "Analiz dosyaları:"
    echo -e "  ${CYAN}PCAP:${NC} $CAPTURE_FILE"
    echo -e "  ${CYAN}İstatistik:${NC} $STATS_FILE"
    echo -e "  ${CYAN}Log:${NC} $LOG_FILE"
    echo
}

# Sürekli izleme
continuous_monitoring() {
    print_status "Sürekli izleme modu başlatılıyor..."
    print_warning "Durdurmak için Ctrl+C tuşlayın"
    
    local session=1
    
    while true; do
        echo
        print_status "İzleme oturumu #$session"
        
        # Yeni timestamp
        TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
        CAPTURE_FILE="$OUTPUT_DIR/traffic_$TIMESTAMP.pcap"
        STATS_FILE="$OUTPUT_DIR/stats_$TIMESTAMP.txt"
        
        # Trafik yakala
        start_traffic_capture
        
        # Hızlı analiz
        if [ -f "$CAPTURE_FILE" ]; then
            local packet_count=$(capinfos "$CAPTURE_FILE" 2>/dev/null | grep "Number of packets" | awk '{print $4}' || echo "0")
            print_success "Oturum #$session tamamlandı - $packet_count paket yakalandı"
        fi
        
        ((session++))
        
        # 30 saniye bekle
        print_status "30 saniye bekleniyor..."
        sleep 30
    done
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Arka plan süreçlerini sonlandır
    pkill -f "tcpdump.*$INTERFACE" 2>/dev/null
    pkill -f "tshark.*$INTERFACE" 2>/dev/null
    
    # Geçici dosyaları temizle
    rm -f /tmp/realtime_analysis_*.txt
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "Traffic monitor başlatılıyor..."
    echo
    
    # Arayüzü kontrol et
    validate_interface
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # Arayüzü hazırla
    setup_interface
    
    echo
    print_status "İzleme parametreleri:"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}Süre:${NC} $MONITOR_TIME saniye"
    echo -e "  ${CYAN}BSSID Filtresi:${NC} ${FILTER_BSSID:-"Yok"}"
    echo -e "  ${CYAN}Kanal Filtresi:${NC} ${FILTER_CHANNEL:-"Yok"}"
    echo -e "  ${CYAN}Gerçek Zamanlı:${NC} $([ "$REAL_TIME" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Protokol Analizi:${NC} $([ "$ANALYZE_PROTOCOLS" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Çıktı:${NC} $OUTPUT_DIR"
    echo
    
    # Sürekli izleme kontrolü
    if [ "$CONTINUOUS" = true ]; then
        continuous_monitoring
    else
        # Tek oturum
        start_traffic_capture
        
        # Analiz yap
        analyze_traffic
    fi
    
    echo
    print_success "Traffic monitor tamamlandı!"
}

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main