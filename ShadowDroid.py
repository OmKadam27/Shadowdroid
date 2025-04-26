# === IMPORTS ===
import sys
import subprocess
import requests
import os
import re
import json
import nvdlib
from datetime import datetime, timedelta
from pyExploitDb import PyExploitDb
from bs4 import BeautifulSoup
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit,
    QLabel, QFileDialog, QHBoxLayout, QFrame, QMessageBox, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer
from fpdf import FPDF

# === CONFIG ===
VIRUSTOTAL_API_KEY = "fccb7b45c0e075227dba0231954ecd95d9f88d9d73e8572fa0c0a3ab8687c5de"
VULNERS_API_KEY = "JWTPAV108GY5DMYREFUJ360WV3C6Z8R9TUQGHZD54XQIWXKTKFC9OQLELCHU4S7U"

# === SPLASH SCREEN ===
class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowDroid Loading...")
        self.setGeometry(400, 200, 500, 300)
        layout = QVBoxLayout()
        label = QLabel("ShadowDroid - Android Pentest Toolkit")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("font-size: 24px; font-weight: bold; color: #00FF00; background-color: #111; padding: 30px; border-radius: 10px;")
        layout.addWidget(label)
        self.setLayout(layout)
        self.setStyleSheet("background-color: black;")

# === MAIN APP ===
class ShadowDroid(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSquad - ShadowDroid Pentest Toolkit")
        self.setGeometry(200, 200, 1100, 750)
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("background-color: #1e1e1e; color: #c8c8c8; font-family: Consolas; font-size: 12pt;")
        main_layout = QHBoxLayout()
        sidebar = QFrame()
        sidebar.setFixedWidth(280)
        sidebar.setStyleSheet("background-color: #2d2d2d; border-right: 1px solid #444;")
        sidebar_layout = QVBoxLayout()
        label = QLabel("☠️  ShadowDroid")
        label.setStyleSheet("color: #ffffff; font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        sidebar_layout.addWidget(label)

        buttons = [
            ("Root Check", self.root_check),
            ("Get Installed Apps", self.get_installed_apps),
            ("IMEI Number",self.get_android_imei),
            ("Check App Permissions", self.get_app_permissions),
            ("Get Device Info", self.get_device_info),
            ("Check Call Forwarding", self.check_call_forwarding),
            ("Check Accessibility Services", self.check_accessibility),
            ("VirusTotal APK Scan", self.virustotal_apk_scan),
            ("Check IP Reputation", self.check_ip_reputation),
            ("Network Configuration", self.network_configuration),
            ("Security Config Assessment", self.security_configuration_assessment),
            ("Patch Analyzer + CVE Check", self.scan_android_patch_vulners),
            ("Generate PDF Report", self.generate_pdf_report)
        ]

        for btn_text, btn_func in buttons:
            btn = QPushButton(btn_text)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #3b8bba;
                    color: white;
                    padding: 8px;
                    border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #005a9e;
                }
            """)
            btn.clicked.connect(btn_func)
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("background-color: #111; color: #00ff00; font-family: monospace;")

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.output_text)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)

    def check_device_connection(self):
        try:
            result = subprocess.check_output("adb get-state", shell=True, stderr=subprocess.STDOUT, text=True)
            return "device" in result
        except subprocess.CalledProcessError:
            return False

    def run_adb_command(self, command):
        if not self.check_device_connection():
            return "Error: No device connected."
        try:
            result = subprocess.check_output(f"adb shell {command}", shell=True, stderr=subprocess.STDOUT, text=True)
            return result.strip()
        except subprocess.CalledProcessError as e:
            return f"Error: {e.output.strip()}"

    def root_check(self):
        output = self.run_adb_command("which su")
        result = "[+] Root access detected." if "/su" in output or "/bin/su" in output else "[-] No root access detected."
        self.output_text.append("\n\n[+] Root Check Result:\n" + result)

    def get_device_info(self):
        props = ["ro.product.model", "ro.build.version.release", "ro.build.version.security_patch"]
        info = [f"{prop}: {self.run_adb_command(f'getprop {prop}')}" for prop in props]
        self.output_text.append("\n\n[+] Device Info:\n" + "\n".join(info))

    def calculate_risk_score(self, permissions, apk_size_kb, last_update_days=None, review_score=None):
        score = 0
        dangerous_keywords = [
            "READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "READ_CONTACTS",
            "ACCESS_FINE_LOCATION", "READ_PHONE_STATE", "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW"
        ]
        danger_hits = sum(1 for perm in permissions if any(d in perm for d in dangerous_keywords))
        if danger_hits >= 5:
            score += 4
        elif danger_hits >= 3:
            score += 3
        elif danger_hits >= 1:
            score += 2

        if apk_size_kb and apk_size_kb < 1000:
            score += 2
        if last_update_days and last_update_days > 180:
            score += 2
        if review_score and review_score < 2.5:
            score += 1

        return min(score, 10)

    def get_installed_apps(self):
        output = self.run_adb_command("pm list packages")
        self.output_text.append("\n\n[+] Installed Apps:\n" + output)

    def get_app_permissions(self):
        self.output_text.append("\n\n[+] App Permissions & Risk Score:\n")
        packages_output = self.run_adb_command("pm list packages")
        if "Error" in packages_output:
            self.output_text.append(packages_output)
            return

        packages = [line.replace("package:", "") for line in packages_output.splitlines()]
        for pkg in packages[:30]:
            output = self.run_adb_command(f"dumpsys package {pkg}")
            if not output or "requested permissions:" not in output:
                continue

            granted = [line.strip() for line in output.splitlines() if "granted=true" in line]

            path_output = self.run_adb_command(f"pm path {pkg}")
            apk_path = path_output.split(":")[-1] if path_output.startswith("package:") else None
            size_kb = None
            if apk_path:
                size_cmd = self.run_adb_command(f"ls -la {apk_path}")
                size_kb = int(size_cmd.split()[4]) // 1024 if size_cmd and len(size_cmd.split()) > 4 else None

            risk_score = self.calculate_risk_score(granted, size_kb)

            if risk_score >= 7:
                label = "High"
            elif risk_score >= 4:
                label = "Medium"
            else:
                label = "Low"

            self.output_text.append(f"\nApp: {pkg}")
            self.output_text.append(f"  Granted Permissions: {len(granted)}")
            self.output_text.append(f"  APK Size: {size_kb} KB" if size_kb else "  APK Size: Unknown")
            self.output_text.append(f"  Risk Score: {risk_score}/10 ({label})")

    def virustotal_apk_scan(self):
        apk_path, _ = QFileDialog.getOpenFileName(self, "Select APK", "", "APK Files (*.apk)")
        if not apk_path:
            return
        with open(apk_path, "rb") as f:
            files = {"file": (os.path.basename(apk_path), f)}
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
            if response.status_code == 200:
                self.output_text.append("[+] Submitted to VirusTotal.")
            else:
                self.output_text.append(f"[-] Failed to submit APK. {response.text}")

    def check_call_forwarding(self):
        output = self.run_adb_command("dumpsys telephony.registry")
        status = "Enabled" if "mCallForwarding=true" in output else "Disabled"
        self.output_text.append(f"\n\n[+] Call Forwarding Status: {status}")

    def check_accessibility(self):
        output = self.run_adb_command("settings get secure enabled_accessibility_services")
        self.output_text.append("\n\n[+] Accessibility Services:\n" + output)

    def check_ip_reputation(self):
        ip = requests.get("https://api.ipify.org").text
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        self.output_text.append(f"\n\n[+] Public IP: {ip}\n[+] IP Info: {response.text}")

    def network_configuration(self):
        ip_info = self.run_adb_command("ip addr show wlan0")
        ipv4 = [line for line in ip_info.splitlines() if 'inet ' in line]
        ipv4 = ipv4[0].split()[1] if ipv4 else "Not connected"
        wifi_dump = self.run_adb_command("dumpsys wifi")
        ssids = set()
        for line in wifi_dump.splitlines():
            if 'SSID:' in line:
                part = line.split("SSID:")
                if len(part) > 1:
                    ssids.add(part[1].split('"')[1] if '"' in part[1] else part[1].strip())
        self.output_text.append(f"\n\n[+] IP Address: {ipv4}\nPrevious Wi-Fi Networks:")
        self.output_text.append("\n".join(ssids) if ssids else "No data.")

    def security_configuration_assessment(self):
        screen_lock = self.run_adb_command("settings get secure lock_screen_lock")
        encryption = self.run_adb_command("getprop ro.crypto.state")
        play_protect = self.run_adb_command("pm get-app-op com.android.vending android:request_install_packages")
        self.output_text.append("\n\n[+] Security Config Check:")
        self.output_text.append(f"Screen Lock: {'Safe' if screen_lock else 'Unsafe'}")
        self.output_text.append(f"Encryption: {'Safe' if encryption == 'encrypted' else 'Unsafe'}")
        self.output_text.append(f"Play Protect: {'Safe' if play_protect == '0' else 'Unsafe'}")

    def scan_android_patch_vulners(self):
        import vulners
        from datetime import datetime

        # Step 1: Get Android version and patch
        version = self.run_adb_command("getprop ro.build.version.release")
        patch = self.run_adb_command("getprop ro.build.version.security_patch")

        self.output_text.append("\n[+] Scanning for vulnerabilities using Vulners API")
        self.output_text.append(f"Android Version: {version}")
        self.output_text.append(f"Security Patch: {patch}")

        if not version or not patch or "Error" in version or "Error" in patch:
            self.output_text.append("[-] Could not retrieve Android version or patch level.")
            return

      
        try:
            patch_month = datetime.strptime(patch.strip(), "%Y-%m-%d").strftime("%Y-%m")
        except ValueError:
            self.output_text.append(f"[-] Patch format invalid: {patch}")
            return

        try:
            
            vulners_api = vulners.Vulners(api_key=VULNERS_API_KEY)
            query = f"android {patch_month} type:cve"
            results = vulners_api.search(query)

            self.output_text.append(f"\n[+] Found {len(results)} related vulnerabilities for {patch_month}:\n")

            if not results:
                self.output_text.append("[+] No CVEs found for this patch level.")
                return

            for cve in results[:10]: 
                cve_id = cve.get("id", "N/A")
                title = cve.get("title", "No title provided")
                description = cve.get("description", title)  
                cvss_data = cve.get("cvss", {})

                if isinstance(cvss_data, dict):
                    score = f"{cvss_data.get('score', 'N/A')} ({cvss_data.get('severity', 'N/A')})"
                    vector = cvss_data.get("vector", "N/A")
                else:
                    score = "N/A"
                    vector = "N/A"

                # Final formatted output
                self.output_text.append(f"🛡 CVE ID: {cve_id}")
                self.output_text.append(f"📈 CVSS: {score}")
                self.output_text.append(f"📊 Vector: {vector}")
                self.output_text.append(f"📝 Description: {description}\n")

        except Exception as e:
            self.output_text.append(f"[-] Error during Vulners query: {str(e)}")

    def get_android_imei(self):
        try:
            if not self.check_device_connection():
                self.output_text.append("[-] No device connected.")
                return "Unavailable"

            # Try first method
            output = self.run_adb_command("service call iphonesubinfo 1")
            if "Result:" in output:
                hex_matches = re.findall(r'0x[0-9a-f]+', output)
                if hex_matches:
                    imei = ''.join([bytes.fromhex(h[2:]).decode('utf-16-be', errors='ignore') for h in hex_matches])
                    imei_clean = ''.join(filter(str.isdigit, imei))
                    if imei_clean:
                        return imei_clean

    
            alt_output = self.run_adb_command("dumpsys iphonesubinfo")
            imei_match = re.search(r'Device ID = (\d+)', alt_output)
            if imei_match:
                return imei_match.group(1)

           
            prop_imei = self.run_adb_command("getprop persist.radio.imei")
            if prop_imei and prop_imei.isdigit():
                return prop_imei

            self.output_text.append("[-] IMEI not found using available methods.")
            return "Unavailable"

        except Exception as e:
            self.output_text.append(f"[-] Exception during IMEI retrieval: {str(e)}")
            return "Unavailable"


   
    def generate_pdf_report(self):
        try:
            from fpdf import FPDF
            filename = f"ShadowDroid_Report_.pdf"

            pdf = FPDF()
            pdf.add_page()

            # Heading 1: Main Title
            pdf.set_font("Helvetica", 'B', 20)
            pdf.cell(0, 12, "ShadowDroid Android Pentest Report", ln=True, align="C")

            # Subheading
            pdf.set_font("Helvetica", size=12)
            pdf.ln(10)
            pdf.cell(0, 10, "Generated Report", ln=True)

            pdf.ln(5)
            pdf.set_font("Helvetica", size=10)
            lines = self.output_text.toPlainText().split("\n")

            for line in lines:
            
                clean_line = line.encode('ascii', 'ignore').decode()

                if "[+]" in line or "[!]" in line:
                    pdf.set_font("Helvetica", 'B', 10)
                elif "[-]" in line:
                    pdf.set_font("Helvetica", 'B', 10)
                else:
                    pdf.set_font("Helvetica", size=10)

                pdf.multi_cell(0, 8, clean_line)

            pdf.output(filename)
            self.output_text.append(f"\n[+] PDF saved: {filename}")
            QMessageBox.information(self, "PDF Saved", f"Report saved as {filename}")

        except Exception as e:
            error_msg = f"\n[-] Failed to generate PDF: {str(e)}"
            self.output_text.append(error_msg)
            QMessageBox.critical(self, "PDF Error", error_msg)



    def export_results_to_json(self):
        try:
            output = self.output_text.toPlainText()
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"ShadowDroid_Report_{timestamp}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump({"report": output}, f, indent=4)
            self.output_text.append(f"\n[+] JSON report saved as {filename}")
            QMessageBox.information(self, "JSON Saved", f"Report saved as {filename}")
        except Exception as e:
            error_msg = f"\n[-] Failed to save JSON report: {str(e)}"
            self.output_text.append(error_msg)
            QMessageBox.critical(self, "Save Error", error_msg)

    def add_export_button(self):
        export_btn = QPushButton("Export as JSON")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b8bba;
                color: white;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
        """)
        export_btn.clicked.connect(self.export_results_to_json)
        self.layout().itemAt(0).widget().layout().addWidget(export_btn)

    def add_theme_toggle_button(self):
        self.dark_mode = True
        theme_btn = QPushButton("Toggle Theme")
        theme_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b8bba;
                color: white;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
        """)
        theme_btn.clicked.connect(self.toggle_theme)
        self.layout().itemAt(0).widget().layout().addWidget(theme_btn)

    def toggle_theme(self):
        if self.dark_mode:
            self.setStyleSheet("background-color: #ffffff; color: #000000; font-family: Consolas; font-size: 12pt;")
            self.output_text.setStyleSheet("background-color: #f5f5f5; color: #000000; font-family: monospace;")
        else:
            self.setStyleSheet("background-color: #1e1e1e; color: #c8c8c8; font-family: Consolas; font-size: 12pt;")
            self.output_text.setStyleSheet("background-color: #111; color: #00ff00; font-family: monospace;")
        self.dark_mode = not self.dark_mode

# === MAIN LOOP ===
if __name__ == "__main__":
    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    QTimer.singleShot(2000, splash.close)
    window = ShadowDroid()
    window.add_export_button()
    window.add_theme_toggle_button()
    window.show()
    sys.exit(app.exec())
