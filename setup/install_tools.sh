#!/bin/bash

# Evil Twin Saldırısı - Araç Kurulum Scripti
# Bu script gerekli tüm araçları Kali Linux'a yükler

echo "🔧 Evil Twin Projesi - Araç Kurulum Başlıyor..."
echo "================================================"

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "❌ Bu script root yetkisiyle çalıştırılmalıdır!"
    echo "Kullanım: sudo ./install_tools.sh"
    exit 1
fi

# Sistem güncellemesi
echo "📦 Sistem paketleri güncelleniyor..."
apt update && apt upgrade -y

# Temel araçlar
echo "🛠️ Temel araçlar yükleniyor..."
apt install -y \
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    net-tools \
    iproute2 \
    iptables \
    build-essential

# Kablosuz ağ araçları
echo "📡 Kablosuz ağ araçları yükleniyor..."
apt install -y \
    aircrack-ng \
    airmon-ng \
    airodump-ng \
    aireplay-ng \
    airbase-ng \
    wireless-tools \
    iw \
    iwconfig \
    rfkill

# Ağ servisleri
echo "🌐 Ağ servisleri yükleniyor..."
apt install -y \
    hostapd \
    dnsmasq \
    dhcp-helper \
    bridge-utils

# Web sunucu ve PHP
echo "🖥️ Web sunucu bileşenleri yükleniyor..."
apt install -y \
    lighttpd \
    apache2 \
    nginx \
    php \
    php-fpm \
    php-cli \
    php-common \
    php-curl \
    php-json

# Trafik analizi araçları
echo "🔍 Trafik analizi araçları yükleniyor..."
apt install -y \
    wireshark \
    tshark \
    tcpdump \
    nmap \
    netcat \
    socat

# MITM ve SSL araçları
echo "🔐 MITM ve SSL araçları yükleniyor..."
apt install -y \
    ettercap-text-only \
    ettercap-graphical \
    sslstrip \
    mitmproxy \
    bettercap

# MAC adresi değiştirme
echo "🎭 MAC adresi araçları yükleniyor..."
apt install -y \
    macchanger \
    sipcalc

# Python araçları
echo "🐍 Python araçları yükleniyor..."
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools

# Python kütüphaneleri
echo "📚 Python kütüphaneleri yükleniyor..."
pip3 install \
    scapy \
    netfilterqueue \
    requests \
    beautifulsoup4 \
    flask \
    colorama

# Ek güvenlik araçları
echo "🛡️ Ek güvenlik araçları yükleniyor..."
apt install -y \
    john \
    hashcat \
    hydra \
    medusa \
    crunch

# Kablosuz sürücüler ve firmware
echo "📻 Kablosuz sürücüler yükleniyor..."
apt install -y \
    firmware-atheros \
    firmware-ralink \
    firmware-realtek \
    firmware-misc-nonfree

# Servisleri durdur (çakışma önleme)
echo "⏹️ Çakışan servisler durduruluyor..."
systemctl stop NetworkManager
systemctl stop wpa_supplicant
systemctl stop dhcpcd
systemctl stop networking

# Gerekli dizinleri oluştur
echo "📁 Proje dizinleri oluşturuluyor..."
mkdir -p /var/log/evil-twin
mkdir -p /tmp/evil-twin
mkdir -p /var/www/evil-twin

# İzinleri ayarla
echo "🔑 Dosya izinleri ayarlanıyor..."
chmod 755 /var/log/evil-twin
chmod 755 /tmp/evil-twin
chmod 755 /var/www/evil-twin

# Hostapd yapılandırması
echo "⚙️ Hostapd yapılandırması kontrol ediliyor..."
if [ ! -f /etc/hostapd/hostapd.conf.backup ]; then
    cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.backup 2>/dev/null || true
fi

# Dnsmasq yapılandırması
echo "⚙️ Dnsmasq yapılandırması kontrol ediliyor..."
if [ ! -f /etc/dnsmasq.conf.backup ]; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup 2>/dev/null || true
fi

# Iptables kurallarını temizle
echo "🧹 Iptables kuralları temizleniyor..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Kernel modüllerini yükle
echo "🔧 Kernel modülleri yükleniyor..."
modprobe mac80211
modprobe cfg80211

# USB Wi-Fi adaptör kontrolü
echo "📡 USB Wi-Fi adaptörleri kontrol ediliyor..."
lsusb | grep -i wireless || echo "⚠️ USB Wi-Fi adaptörü bulunamadı"
iwconfig 2>/dev/null | grep -E "^wlan|^wlp" || echo "⚠️ Kablosuz arayüz bulunamadı"

# Monitor mode testi
echo "🔍 Monitor mode desteği kontrol ediliyor..."
for interface in $(iwconfig 2>/dev/null | grep -E "^wlan|^wlp" | cut -d' ' -f1); do
    echo "Interface: $interface"
    iw $interface info 2>/dev/null | grep -q "monitor" && echo "✅ Monitor mode destekleniyor" || echo "❌ Monitor mode desteklenmiyor"
done

# Kurulum tamamlandı
echo ""
echo "🎉 Kurulum Tamamlandı!"
echo "================================================"
echo "✅ Tüm araçlar başarıyla yüklendi"
echo "✅ Proje dizinleri oluşturuldu"
echo "✅ Servis yapılandırmaları hazırlandı"
echo ""
echo "📋 Sonraki Adımlar:"
echo "1. USB Wi-Fi adaptörünüzü takın"
echo "2. ./environment_check.sh ile ortamı kontrol edin"
echo "3. Monitor mode'u test edin"
echo "4. Evil Twin saldırısını başlatın"
echo ""
echo "⚠️ Önemli Notlar:"
echo "- Bu araçları yalnızca etik test için kullanın"
echo "- Kendi ağlarınızda veya izin aldığınız sistemlerde test edin"
echo "- Yasal sorumluluğu kabul ettiğinizden emin olun"
echo ""
echo "📚 Dokümantasyon: README.md dosyasını okuyun"
echo "🆘 Destek: GitHub Issues bölümünü kullanın"
echo ""
echo "🔧 Kurulum Logları: /var/log/evil-twin/ dizininde"

# Log dosyası oluştur
echo "$(date): Evil Twin araçları başarıyla yüklendi" >> /var/log/evil-twin/install.log

echo "Kurulum tamamlandı. Sistemi yeniden başlatmanız önerilir."