import sys
import os
import time
import subprocess
import psutil
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QTableWidget, QTableWidgetItem, QHeaderView, QLabel)
    from PyQt6.QtCore import QTimer
    from PyQt6.QtGui import QColor, QKeySequence, QShortcut
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]
SUSPICIOUS_PORTS = [4444, 1337, 9001, 8888, 5555]

class ProcSentinelCore:
    def __init__(self):
        self.seen_pids = set()
        self.alerted_pids = set()
        self.is_initial_scan = True

    def check_threats(self, proc):
        try:
            exe_path = proc.exe()
            for s_dir in SUSPICIOUS_DIRS:
                if exe_path.startswith(s_dir):
                    return "ANOMALY"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in SUSPICIOUS_PORTS:
                        return "CRITICAL"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return "CLEAN"

    def send_bus_notification(self, threat_status, proc_name, pid):
        if threat_status == "CRITICAL":
            title = "🚨 KRİTİK GÜVENLİK ALARMI"
            msg = f"Tersine Kabuk (Reverse Shell) tespiti!\nSüreç: {proc_name}\nPID: {pid}"
            urgency = "critical"
            icon = "dialog-error"
            timeout = 0
        else:
            title = "⚠️ ŞÜPHELİ HAREKET"
            msg = f"Geçici dizinden süreç tetiklendi!\nSüreç: {proc_name}"
            urgency = "normal"
            icon = "dialog-warning"
            timeout = 5000

        try:
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                uid = subprocess.check_output(['id', '-u', sudo_user]).decode('utf-8').strip()
                dbus_address = f"unix:path=/run/user/{uid}/bus"
                cmd = f"sudo -u {sudo_user} DBUS_SESSION_BUS_ADDRESS={dbus_address} notify-send -u {urgency} -t {timeout} -i {icon} '{title}' '{msg}'"
                subprocess.Popen(cmd, shell=True)
            else:
                subprocess.Popen(['notify-send', '-u', urgency, '-t', str(timeout), '-i', icon, title, msg])
        except Exception as e:
            print(f"D-Bus Bildirim Hatası: {e}")

    def update_and_scan(self, event_callback):
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)
                cmd_line = " ".join(info['cmdline']) if info['cmdline'] else info['name']
                threat_status = self.check_threats(proc)

                if threat_status != "CLEAN" and pid not in self.alerted_pids and not self.is_initial_scan:
                    self.send_bus_notification(threat_status, info['name'], pid)
                    self.alerted_pids.add(pid)

                is_new = pid not in self.seen_pids
                if self.is_initial_scan:
                    event_callback(pid, info['username'], cmd_line, threat_status, is_new=False, is_initial=True)
                elif is_new or threat_status != "CLEAN":
                    event_callback(pid, info['username'], cmd_line, threat_status, is_new=is_new, is_initial=False)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        self.seen_pids = current_pids
        if self.is_initial_scan:
            self.is_initial_scan = False

class ProcSentinelGUI(QMainWindow):
    def __init__(self, core_engine):
        super().__init__()
        self.core = core_engine
        self.setWindowTitle("ProcSentinel v1.0 - EDR Dashboard")
        self.setGeometry(200, 200, 1000, 600)
        self.setup_ui()
        
        # Klavyeden Kapatma Kısayolu Entegrasyonu (Ctrl+Q)
        self.shortcut_close = QShortcut(QKeySequence("Ctrl+Q"), self)
        self.shortcut_close.activated.connect(self.close)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.trigger_core_scan)
        self.timer.start(2000)

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        self.setStyleSheet("QWidget { background-color: #0c0f12; color: #FFFFFF; font-family: 'Segoe UI', Arial; }\nQTableWidget { background-color: #13171c; gridline-color: #242b35; border: 1px solid #242b35; }\nQHeaderView::section { background-color: #1a202c; padding: 5px; border: 1px solid #242b35; font-weight: bold; }\nQLabel { font-size: 14px; font-weight: bold; color: #00FFCC; margin-bottom: 5px; }")
        
        # Arayüze kısayol bilgisini de ekledik ki kullanıcı görsün
        self.status_label = QLabel("⏳ Sistem verileri çekirdekten alınıyor... (Kapatmak için: Ctrl+Q)")
        layout.addWidget(self.status_label)
        
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Zaman", "PID", "Kullanıcı", "Tehdit Durumu", "Süreç / Komut Satırı"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

    def process_event_handler(self, pid, username, cmd_line, threat_status, is_new, is_initial):
        if is_initial and threat_status == "CLEAN" and pid >= 500 and "python" not in cmd_line:
            return
        self.table.insertRow(0)
        time_str = datetime.now().strftime("%H:%M:%S")
        status_map = {"CLEAN": "✅ Temiz", "ANOMALY": "⚠️ ANOMALY", "CRITICAL": "🚨 CRITICAL"}
        items = [QTableWidgetItem(time_str), QTableWidgetItem(str(pid)), QTableWidgetItem(str(username)), QTableWidgetItem(status_map.get(threat_status, "Bilinmiyor")), QTableWidgetItem(str(cmd_line))]
        color = QColor("#FF3333") if threat_status == "CRITICAL" else QColor("#FF9900") if threat_status == "ANOMALY" else QColor("#00FF00") if is_new else QColor("#888888")
        for col, item in enumerate(items):
            item.setForeground(color)
            self.table.setItem(0, col, item)

    def trigger_core_scan(self):
        self.core.update_and_scan(event_callback=self.process_event_handler)
        self.status_label.setText("🟢 ProcSentinel GUI Aktif. Çıkış için Ctrl+Q kullanabilirsiniz.")

class ProcSentinelCLI:
    def __init__(self, core_engine):
        self.core = core_engine

    def process_event_handler(self, pid, username, cmd_line, threat_status, is_new, is_initial):
        # İlk açılışta terminal ekranını boğmamak için sadece şüpheli süreçleri filtrele
        if is_initial and threat_status == "CLEAN" and "python" not in cmd_line:
            return

        base_text = f"PID: {pid:<6} | User: {username:<10} | Cmd: {cmd_line}"
        
        if threat_status == "CRITICAL":
            # Riskli Süreçler: Kırmızı + Başında/Sonunda Yıldızlar
            print(f"{Fore.RED}** [CRITICAL] {base_text} **")
        elif threat_status == "ANOMALY":
            # Şüpheli Süreçler: Sarı / Turuncu
            print(f"{Fore.YELLOW}[SUSPICIOUS] {base_text}")
        elif is_new:
            # Yeni Normal Süreçler: Canlı Yeşil
            print(f"{Fore.GREEN}[PROCESS] {base_text}")
        else:
            # Genel akış logları
            print(f"[PROCESS] {base_text}")
    def start_loop(self):
        print(f"{Fore.CYAN}[INFO] ProcSentinel CLI Modu Başlatıldı.\n" + "-"*75)
        try:
            while True:
                self.core.update_and_scan(event_callback=self.process_event_handler)
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[WARNING] CLI Motoru güvenli şekilde sonlandırıldı.")

def main():
    wants_gui = False
    if "-ui" in sys.argv or "--ui" in sys.argv:
        wants_gui = True
        if "-ui" in sys.argv: sys.argv.remove("-ui")
        if "--ui" in sys.argv: sys.argv.remove("--ui")

    core_engine = ProcSentinelCore()

    if wants_gui:
        if not PYQT_AVAILABLE:
            print("[HATA] PyQt6 kütüphanesi eksik!")
            sys.exit(1)
        app = QApplication(sys.argv)
        gui_app = ProcSentinelGUI(core_engine)
        gui_app.show()
        sys.exit(app.exec())
    else:
        cli_app = ProcSentinelCLI(core_engine)
        cli_app.start_loop()

if __name__ == "__main__":
    main()