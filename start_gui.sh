#!/bin/bash

# Evil Twin GUI Başlatıcı
# GUI uygulamasını başlatmak için kullanın

# Renkli çıktı
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "================================================"
echo "     Evil Twin Attack Toolkit - GUI Launcher"
echo "================================================"
echo -e "${NC}"

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[HATA] Bu uygulama root yetkileri ile çalıştırılmalıdır!${NC}"
   echo "Kullanım: sudo $0"
   exit 1
fi

# Python kontrolü
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[HATA] Python3 bulunamadı!${NC}"
    echo "Python3'ü yüklemek için: sudo apt install python3"
    exit 1
fi

# Tkinter kontrolü
if ! python3 -c "import tkinter" &> /dev/null; then
    echo -e "${YELLOW}[UYARI] Tkinter bulunamadı, yükleniyor...${NC}"
    apt update
    apt install -y python3-tk
fi

# Gerekli Python modüllerini kontrol et
echo -e "${BLUE}[BİLGİ] Python modülleri kontrol ediliyor...${NC}"

required_modules=("tkinter" "subprocess" "threading" "json")
missing_modules=()

for module in "${required_modules[@]}"; do
    if ! python3 -c "import $module" &> /dev/null; then
        missing_modules+=("$module")
    fi
done

if [ ${#missing_modules[@]} -ne 0 ]; then
    echo -e "${RED}[HATA] Eksik Python modülleri: ${missing_modules[*]}${NC}"
    exit 1
fi

# GUI dizinini oluştur
if [ ! -d "gui" ]; then
    mkdir -p gui
fi

# Log dizinini oluştur
if [ ! -d "logs" ]; then
    mkdir -p logs
fi

# Etik uyarı
echo -e "${RED}[UYARI] Bu araç sadece eğitim ve güvenlik testleri içindir!${NC}"
echo -e "${RED}[UYARI] Sadece kendi ağlarınızda veya izinli ortamlarda kullanın!${NC}"
echo -e "${RED}[UYARI] Yasal sorumluluğu kullanıcıya aittir!${NC}"
echo
read -p "Devam etmek için 'KABUL EDIYORUM' yazın: " confirmation
if [ "$confirmation" != "KABUL EDIYORUM" ]; then
    echo -e "${YELLOW}[BİLGİ] İşlem iptal edildi.${NC}"
    exit 0
fi

# GUI'yi başlat
echo -e "${GREEN}[BİLGİ] GUI başlatılıyor...${NC}"
echo -e "${BLUE}[BİLGİ] GUI'yi kapatmak için pencereyi kapatın veya Ctrl+C kullanın${NC}"
echo

# DISPLAY değişkenini ayarla (SSH X11 forwarding için)
if [ -z "$DISPLAY" ]; then
    export DISPLAY=:0
fi

# GUI'yi başlat
cd "$(dirname "$0")"
python3 gui/evil_twin_gui.py

echo -e "${GREEN}[BİLGİ] GUI kapatıldı${NC}"