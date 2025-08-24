#!/bin/bash

# Ağ Tarama Scripti
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
echo -e "${BLUE}"
echo "================================================"
echo "              Ağ Tarama Aracı"
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
echo -e "${YELLOW}[UYARI] Bu araç sadece eğitim ve güvenlik testleri içindir!${NC}"
echo -e "${YELLOW}[UYARI] Sadece kendi ağlarınızda veya izinli ortamlarda kullanın!${NC}"
echo -e "${YELLOW}[UYARI] Yasal sorumluluğu kullanıcıya aittir!${NC}"
echo

# Varsayılan değerler
SCAN_TIME=30
CHANNEL=""
INTERFACE=""
OUTPUT_DIR="./scan_results"
VERBOSE=false
SAVE_RESULTS=true
SHOW_CLIENTS=false
FILTER_OPEN=false
FILTER_WPS=false

# Yardım fonksiyonu
show_help() {
    echo "Kullanım: $0 [SEÇENEKLER]"
    echo
    echo "SEÇENEKLER:"
    echo "  -i, --interface INTERFACE    Monitor mode interface (otomatik tespit)"
    echo "  -t, --time SANIYE           Tarama süresi (varsayılan: 30)"
    echo "  -c, --channel KANAL         Belirli kanal taraması"
    echo "  -o, --output DIZIN          Çıktı dizini (varsayılan: ./scan_results)"
    echo "  -v, --verbose               Detaylı çıktı"
    echo "  -n, --no-save               Sonuçları kaydetme"
    echo "  -s, --show-clients          İstemcileri de göster"
    echo "  -O, --open-only             Sadece açık ağları göster"
    echo "  -w, --wps-only              Sadece WPS aktif ağları göster"
    echo "  -h, --help                  Bu yardım mesajını göster"
    echo
    echo "ÖRNEKLER:"
    echo "  $0                          # Temel tarama"
    echo "  $0 -t 60 -v                # 60 saniye detaylı tarama"
    echo "  $0 -c 6 -s                 # Kanal 6'da istemcilerle tarama"
    echo "  $0 -O -w                   # Sadece açık ve WPS ağları"
}

# Parametre işleme
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -t|--time)
            SCAN_TIME="$2"
            shift 2
            ;;
        -c|--channel)
            CHANNEL="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -n|--no-save)
            SAVE_RESULTS=false
            shift
            ;;
        -s|--show-clients)
            SHOW_CLIENTS=true
            shift
            ;;
        -O|--open-only)
            FILTER_OPEN=true
            shift
            ;;
        -w|--wps-only)
            FILTER_WPS=true
            shift
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

# Monitor interface otomatik tespiti
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}' | head -n1)
    if [ -z "$INTERFACE" ]; then
        echo -e "${RED}[HATA] Monitor mode interface bulunamadı!${NC}"
        echo "Önce monitor mode'u aktifleştirin:"
        echo "  sudo ./scripts/monitor_mode.sh wlan0"
        exit 1
    fi
fi

# Interface kontrolü
if ! iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
    echo -e "${RED}[HATA] '$INTERFACE' monitor mode'da değil!${NC}"
    echo "Monitor mode'u aktifleştirin:"
    echo "  sudo ./scripts/monitor_mode.sh ${INTERFACE%mon}"
    exit 1
fi

# Gerekli araçları kontrol et
for tool in airodump-ng wash; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo -e "${RED}[HATA] $tool bulunamadı! Aircrack-ng suite yükleyin.${NC}"
        exit 1
    fi
done

# Çıktı dizini oluştur
if [ "$SAVE_RESULTS" = true ]; then
    mkdir -p "$OUTPUT_DIR"
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    SCAN_FILE="$OUTPUT_DIR/scan_$TIMESTAMP"
fi

echo -e "${BLUE}[BİLGİ] Interface: $INTERFACE${NC}"
echo -e "${BLUE}[BİLGİ] Tarama süresi: $SCAN_TIME saniye${NC}"
if [ ! -z "$CHANNEL" ]; then
    echo -e "${BLUE}[BİLGİ] Kanal: $CHANNEL${NC}"
fi
if [ "$SAVE_RESULTS" = true ]; then
    echo -e "${BLUE}[BİLGİ] Çıktı: $SCAN_FILE${NC}"
fi
echo

# Kanal ayarla
if [ ! -z "$CHANNEL" ]; then
    echo -e "${BLUE}[BİLGİ] Kanal $CHANNEL ayarlanıyor...${NC}"
    iwconfig "$INTERFACE" channel "$CHANNEL" 2>/dev/null
fi

# Tarama başlat
echo -e "${GREEN}[BAŞLAT] Ağ taraması başlatılıyor...${NC}"
echo -e "${YELLOW}[BİLGİ] Taramayı durdurmak için CTRL+C kullanın${NC}"
echo

# Cleanup fonksiyonu
cleanup() {
    echo
    echo -e "${YELLOW}[BİLGİ] Tarama durduruluyor...${NC}"
    
    # Arka plan süreçlerini durdur
    pkill -f "airodump-ng.*$INTERFACE" 2>/dev/null
    pkill -f "wash.*$INTERFACE" 2>/dev/null
    
    # Sonuçları analiz et
    if [ "$SAVE_RESULTS" = true ] && [ -f "${SCAN_FILE}-01.csv" ]; then
        analyze_results
    fi
    
    echo -e "${GREEN}[TAMAMLANDI] Tarama tamamlandı!${NC}"
    exit 0
}

# SIGINT yakalama
trap cleanup SIGINT

# Airodump-ng parametreleri
AIRODUMP_PARAMS="-i $INTERFACE"
if [ ! -z "$CHANNEL" ]; then
    AIRODUMP_PARAMS="$AIRODUMP_PARAMS -c $CHANNEL"
fi
if [ "$SAVE_RESULTS" = true ]; then
    AIRODUMP_PARAMS="$AIRODUMP_PARAMS -w $SCAN_FILE --output-format csv"
fi

# WPS taraması için wash başlat
if [ "$FILTER_WPS" = true ] || [ "$VERBOSE" = true ]; then
    echo -e "${BLUE}[BİLGİ] WPS taraması başlatılıyor...${NC}"
    if [ "$SAVE_RESULTS" = true ]; then
        wash -i "$INTERFACE" > "${SCAN_FILE}_wps.txt" 2>/dev/null &
    else
        wash -i "$INTERFACE" > /tmp/wps_scan.txt 2>/dev/null &
    fi
    WASH_PID=$!
fi

# Ana tarama
if [ "$VERBOSE" = true ]; then
    # Detaylı mod - terminal çıktısı
    timeout "$SCAN_TIME" airodump-ng $AIRODUMP_PARAMS
else
    # Sessiz mod - arka planda çalıştır
    timeout "$SCAN_TIME" airodump-ng $AIRODUMP_PARAMS >/dev/null 2>&1
    
    # İlerleme göstergesi
    for ((i=1; i<=SCAN_TIME; i++)); do
        printf "\r${BLUE}[TARAMA] İlerleme: %d/%d saniye${NC}" "$i" "$SCAN_TIME"
        sleep 1
    done
    echo
fi

# WPS taramasını durdur
if [ ! -z "$WASH_PID" ]; then
    kill "$WASH_PID" 2>/dev/null
fi

# Sonuçları analiz et
analyze_results() {
    echo
    echo -e "${CYAN}[ANALİZ] Tarama sonuçları analiz ediliyor...${NC}"
    
    CSV_FILE="${SCAN_FILE}-01.csv"
    if [ ! -f "$CSV_FILE" ]; then
        echo -e "${RED}[HATA] Tarama dosyası bulunamadı: $CSV_FILE${NC}"
        return 1
    fi
    
    # CSV dosyasını analiz et
    echo -e "${GREEN}[SONUÇLAR] Bulunan Ağlar:${NC}"
    echo "================================================"
    
    # Başlık
    printf "%-3s %-20s %-18s %-8s %-12s %-8s %s\n" "No" "SSID" "BSSID" "Kanal" "Güvenlik" "Sinyal" "Vendor"
    echo "--------------------------------------------------------------------"
    
    # Ağları işle
    local count=0
    declare -a network_list=()
    while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_length essid key; do
        # Başlık satırını atla
        if [[ "$bssid" == "BSSID" ]]; then
            continue
        fi
        
        # Boş satırları atla
        if [[ -z "$bssid" || "$bssid" == "Station MAC" ]]; then
            break
        fi
        
        # Temizle
        essid=$(echo "$essid" | tr -d '\r\n' | sed 's/^ *//;s/ *$//')
        bssid=$(echo "$bssid" | tr -d '\r\n')
        channel=$(echo "$channel" | tr -d '\r\n' | sed 's/^ *//;s/ *$//')
        privacy=$(echo "$privacy" | tr -d '\r\n')
        power=$(echo "$power" | tr -d '\r\n' | sed 's/^ *//;s/ *$//')
        
        # Filtreler
        if [ "$FILTER_OPEN" = true ] && [ "$privacy" != " OPN" ]; then
            continue
        fi
        
        # ESSID boşsa atla
        if [ -z "$essid" ] || [ "$essid" = " " ]; then
            essid="<Hidden>"
        fi
        
        # Güvenlik türü
        if [ "$privacy" = " OPN" ]; then
            security="${RED}AÇIK${NC}"
        elif [[ "$privacy" == *"WPA3"* ]]; then
            security="${GREEN}WPA3${NC}"
        elif [[ "$privacy" == *"WPA2"* ]]; then
            security="${YELLOW}WPA2${NC}"
        elif [[ "$privacy" == *"WPA"* ]]; then
            security="${YELLOW}WPA${NC}"
        elif [[ "$privacy" == *"WEP"* ]]; then
            security="${RED}WEP${NC}"
        else
            security="$privacy"
        fi
        
        # Sinyal gücü renklendirme
        if [[ "$power" =~ ^-[0-9]+$ ]]; then
            if [ "$power" -gt -50 ]; then
                signal="${GREEN}$power dBm${NC}"
            elif [ "$power" -gt -70 ]; then
                signal="${YELLOW}$power dBm${NC}"
            else
                signal="${RED}$power dBm${NC}"
            fi
        else
            signal="$power"
        fi
        
        # Vendor bilgisi (MAC'in ilk 3 byte'ı)
        vendor=$(echo "$bssid" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
        
        # Ağı listeye ekle
        network_list[count]="$bssid|$essid|$channel|$privacy"
        
        # Çıktı
        printf "%-3s %-20s %-18s %-8s %-20s %-15s %s\n" \
            "$((count+1))" "${essid:0:20}" "$bssid" "$channel" "$security" "$signal" "$vendor"
        
        ((count++))
    done < "$CSV_FILE"
    
    echo "------------------------------------------------"
    echo -e "${GREEN}Toplam $count ağ bulundu${NC}"
    
    # WPS sonuçları
    local wps_file
    if [ "$SAVE_RESULTS" = true ]; then
        wps_file="${SCAN_FILE}_wps.txt"
    else
        wps_file="/tmp/wps_scan.txt"
    fi
    
    if [ -f "$wps_file" ] && [ -s "$wps_file" ]; then
        echo
        echo -e "${PURPLE}[WPS] WPS Aktif Ağlar:${NC}"
        echo "================================================"
        grep -v "^Wash" "$wps_file" | head -20
    fi
    
    # İstemci bilgileri
    if [ "$SHOW_CLIENTS" = true ]; then
        echo
        echo -e "${CYAN}[İSTEMCİLER] Tespit Edilen İstemciler:${NC}"
        echo "================================================"
        
        # İstemci verilerini oku
        local in_clients=false
        while IFS=',' read -r line; do
            if [[ "$line" == "Station MAC"* ]]; then
                in_clients=true
                continue
            fi
            
            if [ "$in_clients" = true ] && [ ! -z "$line" ]; then
                client_mac=$(echo "$line" | cut -d',' -f1 | tr -d '\r\n')
                associated_bssid=$(echo "$line" | cut -d',' -f6 | tr -d '\r\n')
                
                if [ ! -z "$client_mac" ] && [ "$client_mac" != " " ]; then
                    printf "%-18s -> %-18s\n" "$client_mac" "$associated_bssid"
                fi
            fi
        done < "$CSV_FILE"
    fi
    
    # Öneriler
    echo
    echo -e "${BLUE}[ÖNERİLER] Evil Twin Hedefleri:${NC}"
    echo "================================================"
    echo "1. Yüksek sinyal gücüne sahip ağlar (-50 dBm üzeri)"
    echo "2. Açık ağlar (güvenlik yok)"
    echo "3. WPS aktif ağlar"
    echo "4. Popüler SSID isimleri (misafir, guest, free-wifi)"
    # İnteraktif seçim
    if [ $count -gt 0 ]; then
        echo
        echo -e "${CYAN}[SEÇİM] Hedef ağ seçmek ister misiniz? (y/n):${NC}"
        read -r choice
        
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Hedef ağın numarasını girin (1-$count):${NC}"
            read -r selection
            
            if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "$count" ]; then
                # Seçilen ağın bilgilerini al
                selected_network="${network_list[$((selection-1))]}"
                selected_bssid=$(echo "$selected_network" | cut -d'|' -f1)
                selected_essid=$(echo "$selected_network" | cut -d'|' -f2)
                selected_channel=$(echo "$selected_network" | cut -d'|' -f3)
                
                echo
                echo -e "${GREEN}[SEÇİLDİ] Hedef Ağ:${NC}"
                echo "  SSID: $selected_essid"
                echo "  BSSID: $selected_bssid"
                echo "  Kanal: $selected_channel"
                echo
                echo -e "${YELLOW}[SONRAKI ADIMLAR]${NC}"
                echo "  Evil Twin başlat:"
                echo "    sudo ./scripts/start_evil_twin.sh -b $selected_bssid -c $selected_channel"
                echo "  Hedef analiz:"
                echo "    sudo ./scripts/network_scanner.sh -b $selected_bssid"
                echo "  Deauth saldırı:"
                echo "    sudo ./scripts/deauth_attack.sh -b $selected_bssid"
                
                # Seçilen bilgileri dosyaya kaydet
                if [ "$SAVE_RESULTS" = true ]; then
                    echo "$selected_bssid|$selected_essid|$selected_channel" > "${SCAN_FILE}_selected.txt"
                    echo -e "${GREEN}[KAYIT] Seçilen hedef ${SCAN_FILE}_selected.txt dosyasına kaydedildi${NC}"
                fi
            else
                echo -e "${RED}[HATA] Geçersiz seçim: $selection${NC}"
            fi
        fi
    fi
    
    echo
    echo -e "${YELLOW}[GENEL KOMUTLAR]${NC}"
    echo "  Evil Twin başlat: sudo ./scripts/start_evil_twin.sh"
    echo "  Hedef analiz: sudo ./scripts/network_scanner.sh -b <BSSID>"
    echo "  Deauth saldırı: sudo ./scripts/deauth_attack.sh -b <BSSID>"
}

# Otomatik cleanup
cleanup