import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget,
    QProgressBar, QListWidget, QMessageBox, QFileDialog, QCheckBox
)
from PyQt6.QtCore import QThread, pyqtSignal
from concurrent.futures import ThreadPoolExecutor
import json
from datetime import datetime


class ScannerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(dict)

    def __init__(self, target_url, scan_options):
        super().__init__()
        self.target_url = target_url
        self.scan_options = scan_options
        self.running = True

    def run(self):
        self.update_signal.emit("Starting scan...")
        results = self.scan_website()
        self.result_signal.emit(results)
        self.update_signal.emit("Scan completed!")

    def stop(self):
        self.running = False

    def scan_website(self):
        results = {
            "url": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": []
        }

        try:
            # Check for SQL Injection
            if self.scan_options.get("sql_injection", False):
                self.update_signal.emit("Checking for SQL Injection vulnerabilities...")
                if self.check_sql_injection():
                    results["vulnerabilities"].append({
                        "type": "SQL Injection",
                        "severity": "High",
                        "description": "Potential SQL injection vulnerability detected."
                    })

            # Check for XSS
            if self.scan_options.get("xss", False):
                self.update_signal.emit("Checking for Cross-Site Scripting (XSS) vulnerabilities...")
                if self.check_xss():
                    results["vulnerabilities"].append({
                        "type": "XSS",
                        "severity": "High",
                        "description": "Potential Cross-Site Scripting vulnerability detected."
                    })

            # Check for CSRF
            if self.scan_options.get("csrf", False):
                self.update_signal.emit("Checking for CSRF vulnerabilities...")
                if self.check_csrf():
                    results["vulnerabilities"].append({
                        "type": "CSRF",
                        "severity": "Medium",
                        "description": "Potential CSRF vulnerability detected."
                    })

            # Check for insecure headers
            if self.scan_options.get("headers", False):
                self.update_signal.emit("Checking for insecure HTTP headers...")
                insecure_headers = self.check_insecure_headers()
                if insecure_headers:
                    results["vulnerabilities"].append({
                        "type": "Insecure Headers",
                        "severity": "Medium",
                        "description": f"Insecure HTTP headers detected: {', '.join(insecure_headers)}"
                    })

            # Check for directory listing
            if self.scan_options.get("dir_listing", False):
                self.update_signal.emit("Checking for directory listing vulnerabilities...")
                if self.check_directory_listing():
                    results["vulnerabilities"].append({
                        "type": "Directory Listing",
                        "severity": "Low",
                        "description": "Directory listing is enabled."
                    })

        except Exception as e:
            self.update_signal.emit(f"Error during scan: {str(e)}")

        return results

    def check_sql_injection(self):
        test_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        vulnerable = False
        
        try:
            response = requests.get(self.target_url)
            forms = BeautifulSoup(response.text, 'html.parser').find_all('form')
            
            for form in forms:
                form_details = self.get_form_details(form)
                for payload in test_payloads:
                    data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden":
                            data[input_tag["name"]] = input_tag["value"] + payload
                        elif input_tag["type"] != "submit":
                            data[input_tag["name"]] = f"test{payload}"
                    
                    if form_details["method"] == "post":
                        res = requests.post(form_details["action"], data=data)
                    else:
                        res = requests.get(form_details["action"], params=data)
                    
                    if "error" in res.text.lower() or "exception" in res.text.lower() or "syntax" in res.text.lower():
                        vulnerable = True
                        break
                
                if vulnerable:
                    break
                    
        except Exception as e:
            print(f"Error checking SQLi: {e}")
            
        return vulnerable

    def check_xss(self):
        test_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        vulnerable = False
        
        try:
            response = requests.get(self.target_url)
            forms = BeautifulSoup(response.text, 'html.parser').find_all('form')
            
            for form in forms:
                form_details = self.get_form_details(form)
                for payload in test_payloads:
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden":
                            data[input_tag["name"]] = input_tag["value"] + payload
                        elif input_tag["type"] != "submit":
                            data[input_tag["name"]] = payload
                    
                    if form_details["method"] == "post":
                        res = requests.post(form_details["action"], data=data)
                    else:
                        res = requests.get(form_details["action"], params=data)
                    
                    if payload in res.text:
                        vulnerable = True
                        break
                
                if vulnerable:
                    break
                    
        except Exception as e:
            print(f"Error checking XSS: {e}")
            
        return vulnerable

    def check_csrf(self):
        try:
            response = requests.get(self.target_url)
            forms = BeautifulSoup(response.text, 'html.parser').find_all('form')
            
            for form in forms:
                if not form.find("input", {"name": "csrf_token"}) and not form.find("input", {"name": "csrfmiddlewaretoken"}):
                    return True
                    
        except Exception as e:
            print(f"Error checking CSRF: {e}")
            
        return False

    def check_insecure_headers(self):
        insecure_headers = []
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "X-XSS-Protection": "1; mode=block",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": None,
                "Strict-Transport-Security": None
            }
            
            for header, expected_value in security_headers.items():
                if header not in headers:
                    insecure_headers.append(f"Missing {header}")
                elif expected_value and headers[header].lower() != expected_value.lower():
                    insecure_headers.append(f"Insecure {header} value")
                    
        except Exception as e:
            print(f"Error checking headers: {e}")
            
        return insecure_headers

    def check_directory_listing(self):
        test_dirs = ["images/", "uploads/", "assets/"]
        vulnerable = False
        
        try:
            for directory in test_dirs:
                url = urljoin(self.target_url, directory)
                response = requests.get(url)
                if response.status_code == 200 and "Index of" in response.text:
                    vulnerable = True
                    break
                    
        except Exception as e:
            print(f"Error checking directory listing: {e}")
            
        return vulnerable

    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
            
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Vulnerability Scanner")
        self.setGeometry(100, 100, 800, 600)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        self.create_url_input()
        self.create_scan_options()
        self.create_scan_controls()
        self.create_output_tabs()
        self.create_status_bar()
        
        self.scan_thread = None
        self.scan_results = []
        
    def create_url_input(self):
        url_layout = QHBoxLayout()
        self.layout.addLayout(url_layout)
        
        url_label = QLabel("Target URL:")
        url_layout.addWidget(url_label)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_layout.addWidget(self.url_input)
        
    def create_scan_options(self):
        options_group = QWidget()
        options_layout = QHBoxLayout()
        options_group.setLayout(options_layout)
        self.layout.addWidget(options_group)
        
        self.sql_checkbox = QCheckBox("SQL Injection")
        self.sql_checkbox.setChecked(True)
        options_layout.addWidget(self.sql_checkbox)
        
        self.xss_checkbox = QCheckBox("XSS")
        self.xss_checkbox.setChecked(True)
        options_layout.addWidget(self.xss_checkbox)
        
        self.csrf_checkbox = QCheckBox("CSRF")
        options_layout.addWidget(self.csrf_checkbox)
        
        self.headers_checkbox = QCheckBox("Insecure Headers")
        options_layout.addWidget(self.headers_checkbox)
        
        self.dir_listing_checkbox = QCheckBox("Directory Listing")
        options_layout.addWidget(self.dir_listing_checkbox)
        
    def create_scan_controls(self):
        controls_layout = QHBoxLayout()
        self.layout.addLayout(controls_layout)
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        controls_layout.addWidget(self.stop_button)
        
        self.save_button = QPushButton("Save Results")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        controls_layout.addWidget(self.save_button)
        
    def create_output_tabs(self):
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Console Output Tab
        self.console_tab = QWidget()
        self.console_layout = QVBoxLayout()
        self.console_tab.setLayout(self.console_layout)
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_layout.addWidget(self.console_output)
        
        # Results Tab
        self.results_tab = QWidget()
        self.results_layout = QVBoxLayout()
        self.results_tab.setLayout(self.results_layout)
        
        self.results_list = QListWidget()
        self.results_layout.addWidget(self.results_list)
        
        self.details_output = QTextEdit()
        self.details_output.setReadOnly(True)
        self.results_layout.addWidget(self.details_output)
        
        self.tabs.addTab(self.console_tab, "Console")
        self.tabs.addTab(self.results_tab, "Results")
        
    def create_status_bar(self):
        self.status_bar = QProgressBar()
        self.layout.addWidget(self.status_bar)
        
    def start_scan(self):
        target_url = self.url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return
            
        scan_options = {
            "sql_injection": self.sql_checkbox.isChecked(),
            "xss": self.xss_checkbox.isChecked(),
            "csrf": self.csrf_checkbox.isChecked(),
            "headers": self.headers_checkbox.isChecked(),
            "dir_listing": self.dir_listing_checkbox.isChecked()
        }
        
        self.console_output.clear()
        self.results_list.clear()
        self.details_output.clear()
        
        self.scan_thread = ScannerThread(target_url, scan_options)
        self.scan_thread.update_signal.connect(self.update_console)
        self.scan_thread.progress_signal.connect(self.update_progress)
        self.scan_thread.result_signal.connect(self.scan_completed)
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        
        self.scan_thread.start()
        
    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.update_console("Scan stopped by user")
            
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
    def scan_completed(self, results):
        self.scan_results.append(results)
        self.display_results(results)
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.save_button.setEnabled(True)
        
    def update_console(self, message):
        self.console_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def update_progress(self, value):
        self.status_bar.setValue(value)
        
    def display_results(self, results):
        self.results_list.clear()
        
        if not results["vulnerabilities"]:
            self.results_list.addItem("No vulnerabilities found")
            return
            
        for vuln in results["vulnerabilities"]:
            self.results_list.addItem(f"{vuln['type']} ({vuln['severity']})")
            
        self.results_list.itemClicked.connect(self.show_vuln_details)
        
    def show_vuln_details(self, item):
        for vuln in self.scan_results[-1]["vulnerabilities"]:
            if item.text().startswith(vuln["type"]):
                details = f"Type: {vuln['type']}\n"
                details += f"Severity: {vuln['severity']}\n"
                details += f"Description: {vuln['description']}\n"
                details += f"URL: {self.scan_results[-1]['url']}\n"
                details += f"Timestamp: {self.scan_results[-1]['timestamp']}"
                
                self.details_output.setPlainText(details)
                break
                
    def save_results(self):
        if not self.scan_results:
            QMessageBox.warning(self, "Error", "No results to save")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Results",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=4)
                self.update_console(f"Results saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save results: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
    data = {}
