# 🔒 Evil Twin Saldırısı - Eğitim Projesi

## ⚠️ ETİK UYARI VE YASAL SORUMLULUK

**🚨 ÖNEMLİ: Bu proje yalnızca eğitim, araştırma ve etik test amaçları için geliştirilmiştir.**

### Yasal Uyarı:
- Bu araçları **yalnızca kendi ağlarınızda** veya **yazılı izin aldığınız sistemlerde** kullanın
- İzinsiz ağlara erişim **Türkiye Ceza Kanunu 243. madde** kapsamında suçtur
- KVKK (Kişisel Verilerin Korunması Kanunu) ihlali riski taşır
- Kullanıcı tüm yasal sorumluluğu kabul eder

### Etik Kullanım Kuralları:
✅ **İZİN VERİLEN KULLANIM:**
- Kendi laboratuvar ortamınızda test
- Eğitim amaçlı simülasyon
- Penetrasyon testi (yazılı izinle)
- Siber güvenlik farkındalığı eğitimi

❌ **YASAK KULLANIM:**
- Başkalarının ağlarına izinsiz erişim
- Kişisel veri çalma
- Ticari amaçlı kötüye kullanım
- Zarar verme niyetiyle kullanım

---

## 📖 Evil Twin Saldırısı Nedir?

**Evil Twin (Kötü İkiz)** saldırısı, saldırganın meşru bir Wi-Fi erişim noktasını taklit ederek sahte bir erişim noktası oluşturduğu bir **Man-in-the-Middle (MITM)** saldırı türüdür.

### 🔍 Saldırının Çalışma Prensibi:

1. **Keşif Aşaması**: Hedef ağın SSID, kanal ve güvenlik ayarları tespit edilir
2. **Sahte AP Oluşturma**: Aynı SSID ile sahte erişim noktası kurulur
3. **Deauthentication**: Meşru ağdaki kullanıcılar zorla bağlantıdan koparılır
4. **Yönlendirme**: Kullanıcılar sahte ağa bağlanmaya yönlendirilir
5. **Veri Toplama**: Tüm trafik saldırgan üzerinden geçer
6. **Credential Harvesting**: Captive portal ile kimlik bilgileri toplanır

### 🎯 Saldırının Hedefleri:
- Wi-Fi şifrelerini ele geçirme
- Kullanıcı kimlik bilgilerini çalma
- Web trafiğini izleme
- Hassas verilere erişim
- Session hijacking

### ⚡ Teknik Bileşenler:
- **hostapd**: Sahte erişim noktası oluşturma
- **dnsmasq**: DHCP ve DNS servisleri
- **aircrack-ng**: Kablosuz ağ analizi ve saldırı
- **iptables**: Trafik yönlendirme
- **sslstrip**: HTTPS'i HTTP'ye dönüştürme
- **Captive Portal**: Sahte giriş sayfası

---

## 🛡️ Neden Bu Saldırı Tehlikeli?

### Kullanıcı Perspektifi:
- Kullanıcı sahte ağı fark etmez
- Tüm internet trafiği saldırgan üzerinden geçer
- Şifreler, e-postalar, bankacılık bilgileri risk altında
- HTTPS bile sslstrip ile bypass edilebilir

### Kurumsal Perspektif:
- Çalışan kimlik bilgileri ele geçirilebilir
- Kurumsal ağa sızma riski
- Veri sızıntısı ve KVKK ihlali
- İtibar kaybı

---

## 🎓 Eğitim Amaçları

Bu proje ile öğrenecekleriniz:

### Teknik Beceriler:
- Linux ağ yapılandırması
- Kablosuz ağ protokolleri (802.11)
- MITM saldırı teknikleri
- Web sunucu yapılandırması
- Trafik analizi ve paket yakalama

### Güvenlik Farkındalığı:
- Wi-Fi güvenlik açıkları
- Sosyal mühendislik teknikleri
- Ağ güvenliği best practices
- Incident response

### Savunma Stratejileri:
- Evil Twin tespiti
- WPA3 ve 802.1X implementasyonu
- Kullanıcı eğitimi
- Monitoring ve alerting

---

## 🏗️ Proje Yapısı

```
evil-twin/
├── README.md                 # Bu dosya
├── start_gui.sh             # GUI başlatıcı
├── setup/
│   ├── install_tools.sh      # Gerekli araçları yükleme
│   └── environment_check.sh  # Ortam kontrolü
├── config/
│   ├── hostapd.conf         # AP yapılandırması
│   ├── dnsmasq.conf         # DHCP/DNS yapılandırması
│   └── iptables_rules.sh    # Firewall kuralları
├── scripts/
│   ├── monitor_mode.sh      # Monitor mode aktivasyonu
│   ├── scan_networks.sh     # Ağ tarama (interaktif)
│   ├── start_evil_twin.sh   # Ana saldırı scripti
│   ├── deauth_attack.sh     # Deauth saldırısı
│   └── cleanup.sh           # Temizlik scripti
├── gui/
│   ├── evil_twin_gui.py     # Ana GUI uygulaması
│   ├── requirements.txt     # Python gereksinimleri
│   ├── icon.svg             # Uygulama ikonu
│   └── evil-twin-gui.desktop # Desktop entry
├── web/
│   ├── index.html           # Captive portal ana sayfa
│   ├── login.html           # Giriş formu
│   ├── capture.php          # Veri yakalama
│   ├── style.css            # Stil dosyası
│   └── logs/                # Log dosyaları
├── analysis/
│   ├── wireshark_filters.txt # Wireshark filtreleri
│   └── traffic_analysis.py   # Trafik analiz scripti
└── docs/
    ├── lab_setup.md         # Laboratuvar kurulumu
    ├── defense_guide.md     # Savunma rehberi
    └── legal_compliance.md  # Yasal uyumluluk
```

---

## 🚀 Hızlı Başlangıç

### Ön Gereksinimler:
- Kali Linux (sanal makine önerili)
- Monitor mode destekleyen USB Wi-Fi adaptörü
- Root yetkisi
- Etik test ortamı

### Kurulum:
```bash
# Projeyi klonla
git clone <repo-url>
cd evil-twin

# Gerekli araçları yükle
sudo ./setup/install_tools.sh

# Ortamı kontrol et
./setup/environment_check.sh
```

### Kullanım:

#### Temel Kullanım (Önerilen):
```bash
# 1. Monitor mode'u aktifleştir
sudo ./scripts/monitor_mode.sh wlan0

# 2. Ağları tara ve interaktif seçim yap
sudo ./scripts/scan_networks.sh
# Script size numaralı liste gösterecek ve hedef seçmenizi isteyecek

# 3. Seçilen hedefle Evil Twin'i başlat
sudo ./scripts/start_evil_twin.sh
# Kaydedilen hedef otomatik olarak yüklenecek
```

#### Manuel Kullanım:
```bash
# Belirli bir SSID ile
sudo ./scripts/start_evil_twin.sh -s "HedefSSID" -c 6

# Belirli bir BSSID ile
sudo ./scripts/start_evil_twin.sh -b aa:bb:cc:dd:ee:ff -c 6

# Gelişmiş seçeneklerle
sudo ./scripts/start_evil_twin.sh -s "Guest" -d -S -D
```

#### GUI Uygulaması (Yeni!):
```bash
# Masaüstü uygulamasını başlat
sudo ./start_gui.sh
```

#### Komut Satırı Kullanımı:
```bash
# Temel kullanım (önerilen)
sudo ./scripts/scan_networks.sh
sudo ./scripts/start_evil_twin.sh
```

#### Yeni Özellikler:
- **🖥️ Grafik Kullanıcı Arayüzü**: Tkinter tabanlı modern masaüstü uygulaması
- **📊 Görsel Ağ Tarama**: Ağlar tablo halinde renk kodlu gösterilir
- **⚔️ İnteraktif Saldırı Yönetimi**: Tüm saldırı seçenekleri GUI'den kontrol edilebilir
- **📈 Gerçek Zamanlı İzleme**: Bağlı istemciler ve yakalanan veriler canlı görüntülenir
- **📝 Entegre Log Yönetimi**: Tüm loglar tek arayüzde görüntülenebilir
- **🔧 Otomatik Araç Kontrolü**: Eksik araçlar otomatik tespit edilir ve yüklenebilir
- **💾 Sonuç Kaydetme**: Tarama sonuçları ve loglar kolayca kaydedilebilir
- **🎯 İnteraktif Hedef Seçimi**: Ağ taraması sonrası sayılarla hedef seçebilirsiniz
- **🔄 Otomatik Hedef Yükleme**: Son seçilen hedef otomatik olarak kaydedilir ve yüklenir

---

## 📚 Öğrenme Kaynakları

### Kitaplar:
- "The Web Application Hacker's Handbook" - Dafydd Stuttard
- "Wireless Networks Security" - Ido Dubrawsky
- "Penetration Testing" - Georgia Weidman

### Online Kaynaklar:
- OWASP Wireless Security Testing Guide
- NIST Cybersecurity Framework
- Kali Linux Documentation

### Sertifikasyonlar:
- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Professional)
- CISSP (Certified Information Systems Security Professional)

---

## 🤝 Katkıda Bulunma

Bu eğitim projesi açık kaynaklıdır. Katkılarınızı bekliyoruz:

1. Fork yapın
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Pull request gönderin

### Katkı Kuralları:
- Etik kullanım ilkelerine uygun olmalı
- Eğitim amaçlı içerik olmalı
- Güvenlik açığı yaratmamalı
- Dokümantasyon eksiksiz olmalı

---

## 📞 İletişim ve Destek

- **Eğitim Amaçlı Sorular**: GitHub Issues
- **Güvenlik Açığı Bildirimi**: security@example.com
- **Yasal Konular**: legal@example.com

---

## 📄 Lisans

Bu proje MIT lisansı altında yayınlanmıştır. Detaylar için `LICENSE` dosyasına bakınız.

---

**⚖️ Son Uyarı**: Bu araçları kullanmadan önce yerel yasaları kontrol edin ve etik kurallara uyun. Bilgi güvenliği alanında çalışanlar olarak sorumluluğumuz, bu bilgileri yalnızca savunma amaçlı kullanmaktır.

**🎯 Hedefimiz**: Daha güvenli bir dijital dünya için farkındalık yaratmak ve savunma kapasitelerini geliştirmektir.