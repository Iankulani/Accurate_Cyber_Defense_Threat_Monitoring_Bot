#!/usr/bin/env python3
"""
CyberThreat Monitor - Advanced IP-Based Threat Detection System
Version: 0.0
Author: Ian Carter Kulani
Description: Real-time network threat monitoring tool with dashboard, analytics, and Telegram integration
"""

import sys
import os
import time
import threading
import socket
import struct
import datetime
import json
import platform
import subprocess
from collections import defaultdict, deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import requests
import psutil
import dpkt
from scapy.all import sniff, IP, TCP, UDP, ICMP
import numpy as np
from prettytable import PrettyTable

# Constants
CONFIG_FILE = "ctm_config.json"
MAX_LOG_ENTRIES = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot{}/sendMessage"
UPDATE_INTERVAL = 5  # seconds
THRESHOLDS = {
    'dos': 1000,  # packets/sec
    'ddos': 5000,  # packets/sec from multiple IPs
    'port_scan': 50,  # ports/sec
    'http_flood': 200,  # requests/sec
    'https_flood': 200,  # requests/sec
    'unusual_traffic': 2.0  # standard deviations from mean
}

class ThreatMonitor:
    def __init__(self):
        self.running = False
        self.monitoring_ip = None
        self.interface = None
        self.telegram_token = None
        self.telegram_chat_id = None
        self.packet_count = 0
        self.start_time = None
        self.traffic_stats = defaultdict(lambda: defaultdict(int))
        self.alert_history = deque(maxlen=100)
        self.packet_history = deque(maxlen=1000)
        self.port_scan_attempts = defaultdict(lambda: defaultdict(int))
        self.http_requests = defaultdict(int)
        self.https_requests = defaultdict(int)
        self.traffic_baseline = None
        self.baseline_period = 300  # 5 minutes for baseline
        self.theme = "dark"  # or "light"
        
        # Load configuration
        self.load_config()
        
        # Initialize network interface
        self.detect_network_interface()
        
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.theme = config.get('theme', 'dark')
        except Exception as e:
            print(f"Error loading config: {e}")

    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'theme': self.theme
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Error saving config: {e}")

    def detect_network_interface(self):
        """Detect the primary network interface"""
        try:
            if platform.system() == "Windows":
                # Windows implementation
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces") as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                ip_addr = winreg.QueryValueEx(subkey, "DhcpIPAddress")[0]
                                if ip_addr and ip_addr != '0.0.0.0':
                                    self.interface = subkey_name
                                    break
                            except WindowsError:
                                pass
            else:
                # Linux/Mac implementation
                routes = psutil.net_if_stats()
                for interface, stats in routes.items():
                    if stats.isup:
                        self.interface = interface
                        break
        except Exception as e:
            print(f"Error detecting network interface: {e}")
            self.interface = None

    def start_monitoring(self, ip_address):
        """Start monitoring a specific IP address"""
        if self.running:
            self.stop_monitoring()
            
        self.monitoring_ip = ip_address
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.traffic_stats.clear()
        self.alert_history.clear()
        self.packet_history.clear()
        self.port_scan_attempts.clear()
        self.http_requests.clear()
        self.https_requests.clear()
        self.traffic_baseline = None
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self.packet_capture, daemon=True)
        self.capture_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
        self.analysis_thread.start()
        
        return f"Started monitoring {ip_address} on interface {self.interface}"

    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join(timeout=2)
        if hasattr(self, 'analysis_thread'):
            self.analysis_thread.join(timeout=2)
        return "Monitoring stopped"

    def packet_capture(self):
        """Capture network packets using Scapy"""
        try:
            filter_str = f"host {self.monitoring_ip}" if self.monitoring_ip else ""
            sniff(iface=self.interface, prn=self.process_packet, filter=filter_str, store=False)
        except Exception as e:
            self.log_alert(f"Packet capture error: {e}", "SYSTEM")

    def process_packet(self, packet):
        """Process each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        timestamp = time.time()
        
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = None
                port = None
                
                # Determine protocol and port
                if TCP in packet:
                    protocol = "TCP"
                    port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    port = packet[UDP].dport
                elif ICMP in packet:
                    protocol = "ICMP"
                
                # Store packet info
                packet_info = {
                    'timestamp': timestamp,
                    'src_ip': ip_src,
                    'dst_ip': ip_dst,
                    'protocol': protocol,
                    'port': port,
                    'size': len(packet)
                }
                self.packet_history.append(packet_info)
                
                # Update traffic stats
                direction = "inbound" if ip_dst == self.monitoring_ip else "outbound"
                self.traffic_stats[direction]['packets'] += 1
                self.traffic_stats[direction]['bytes'] += len(packet)
                
                if protocol:
                    self.traffic_stats[direction][protocol] += 1
                
                # Track HTTP/HTTPS requests
                if port == 80:
                    self.http_requests[ip_src] += 1
                elif port == 443:
                    self.https_requests[ip_src] += 1
                
                # Track port scan attempts
                if direction == "inbound" and port is not None:
                    self.port_scan_attempts[ip_src][port] += 1
                    
        except Exception as e:
            self.log_alert(f"Packet processing error: {e}", "SYSTEM")

    def analyze_traffic(self):
        """Analyze captured traffic for threats"""
        # First establish baseline
        baseline_start = time.time()
        baseline_data = []
        
        while self.running and (time.time() - baseline_start) < self.baseline_period:
            time.sleep(1)
            if self.packet_history:
                baseline_data.append(len(self.packet_history))
        
        if baseline_data:
            self.traffic_baseline = {
                'mean': np.mean(baseline_data),
                'std': np.std(baseline_data)
            }
        
        # Continuous analysis
        while self.running:
            try:
                self.check_dos()
                self.check_ddos()
                self.check_port_scans()
                self.check_http_floods()
                self.check_https_floods()
                self.check_unusual_traffic()
                time.sleep(UPDATE_INTERVAL)
            except Exception as e:
                self.log_alert(f"Analysis error: {e}", "SYSTEM")
                time.sleep(5)

    def check_dos(self):
        """Check for Denial of Service attacks"""
        inbound_packets = self.traffic_stats['inbound']['packets']
        if inbound_packets > THRESHOLDS['dos']:
            msg = f"Potential DoS attack detected: {inbound_packets} packets/sec"
            self.log_alert(msg, "DOS")
            self.send_telegram_alert(msg)

    def check_ddos(self):
        """Check for Distributed Denial of Service attacks"""
        unique_sources = len(self.port_scan_attempts)
        if unique_sources > 10 and self.traffic_stats['inbound']['packets'] > THRESHOLDS['ddos']:
            msg = f"Potential DDoS attack detected: {unique_sources} sources, {self.traffic_stats['inbound']['packets']} packets/sec"
            self.log_alert(msg, "DDOS")
            self.send_telegram_alert(msg)

    def check_port_scans(self):
        """Check for port scanning activity"""
        for src_ip, ports in self.port_scan_attempts.items():
            if len(ports) > THRESHOLDS['port_scan']:
                msg = f"Port scan detected from {src_ip}: {len(ports)} ports scanned"
                self.log_alert(msg, "PORT_SCAN")
                self.send_telegram_alert(msg)

    def check_http_floods(self):
        """Check for HTTP flood attacks"""
        for src_ip, count in self.http_requests.items():
            if count > THRESHOLDS['http_flood']:
                msg = f"HTTP flood detected from {src_ip}: {count} requests"
                self.log_alert(msg, "HTTP_FLOOD")
                self.send_telegram_alert(msg)

    def check_https_floods(self):
        """Check for HTTPS flood attacks"""
        for src_ip, count in self.https_requests.items():
            if count > THRESHOLDS['https_flood']:
                msg = f"HTTPS flood detected from {src_ip}: {count} requests"
                self.log_alert(msg, "HTTPS_FLOOD")
                self.send_telegram_alert(msg)

    def check_unusual_traffic(self):
        """Check for unusual traffic patterns"""
        if self.traffic_baseline and self.packet_history:
            current_rate = len(self.packet_history) / UPDATE_INTERVAL
            z_score = (current_rate - self.traffic_baseline['mean']) / self.traffic_baseline['std']
            
            if abs(z_score) > THRESHOLDS['unusual_traffic']:
                msg = f"Unusual traffic detected: {current_rate:.1f} packets/sec (Z-score: {z_score:.2f})"
                self.log_alert(msg, "UNUSUAL_TRAFFIC")
                self.send_telegram_alert(msg)

    def log_alert(self, message, alert_type):
        """Log a security alert"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            'timestamp': timestamp,
            'message': message,
            'type': alert_type
        }
        self.alert_history.append(alert)
        print(f"[{timestamp}] [{alert_type}] {message}")

    def send_telegram_alert(self, message):
        """Send alert to Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            return
            
        try:
            url = TELEGRAM_API_URL.format(self.telegram_token)
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            response = requests.post(url, data=payload)
            if response.status_code != 200:
                print(f"Failed to send Telegram alert: {response.text}")
        except Exception as e:
            print(f"Error sending Telegram alert: {e}")

    def get_network_info(self):
        """Get network information using ifconfig/ipconfig"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error getting network info: {e}"

    def ping(self, ip_address):
        """Ping an IP address"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = '4'
            result = subprocess.run(['ping', param, count, ip_address], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error pinging {ip_address}: {e}"

    def traceroute(self, ip_address):
        """Perform traceroute to an IP address"""
        try:
            if platform.system() == "Windows":
                command = ['tracert', ip_address]
            else:
                command = ['traceroute', ip_address]
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error performing traceroute: {e}"

    def get_netstat(self):
        """Get network statistics"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            else:
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error getting netstat: {e}"

    def generate_report(self):
        """Generate a threat report"""
        report = {
            'monitoring_ip': self.monitoring_ip,
            'start_time': datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'duration': time.time() - self.start_time if self.start_time else 0,
            'total_packets': self.packet_count,
            'alerts': list(self.alert_history),
            'traffic_stats': dict(self.traffic_stats),
            'port_scan_sources': len(self.port_scan_attempts),
            'http_requests': sum(self.http_requests.values()),
            'https_requests': sum(self.https_requests.values())
        }
        return json.dumps(report, indent=2)

    def get_traffic_summary(self):
        """Get traffic summary statistics"""
        table = PrettyTable()
        table.field_names = ["Direction", "Packets", "Bytes", "TCP", "UDP", "ICMP"]
        
        for direction in ['inbound', 'outbound']:
            stats = self.traffic_stats.get(direction, {})
            table.add_row([
                direction,
                stats.get('packets', 0),
                stats.get('bytes', 0),
                stats.get('TCP', 0),
                stats.get('UDP', 0),
                stats.get('ICMP', 0)
            ])
        
        return str(table)

    def get_alerts_summary(self):
        """Get alerts summary"""
        alert_counts = defaultdict(int)
        for alert in self.alert_history:
            alert_counts[alert['type']] += 1
        
        table = PrettyTable()
        table.field_names = ["Alert Type", "Count"]
        for alert_type, count in alert_counts.items():
            table.add_row([alert_type, count])
        
        return str(table)

class CyberThreatMonitorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Threat Monitroing Bot")
        self.root.geometry("1200x800")
        
        self.monitor = ThreatMonitor()
        self.create_menu()
        self.create_tabs()
        self.create_terminal()
        self.create_status_bar()
        self.apply_theme()
        
        # Start periodic updates
        self.update_interval = 5000  # ms
        self.update_display()
        
    def create_menu(self):
        """Create the main menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Report", command=self.save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.set_theme("dark"))
        view_menu.add_command(label="Light Theme", command=lambda: self.set_theme("light"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Info", command=self.show_network_info)
        tools_menu.add_command(label="Ping Tool", command=self.show_ping_tool)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute)
        tools_menu.add_command(label="Netstat", command=self.show_netstat)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Telegram Settings", command=self.show_telegram_settings)
        settings_menu.add_command(label="Threshold Settings", command=self.show_threshold_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_tabs(self):
        """Create the tabbed interface"""
        self.tab_control = ttk.Notebook(self.root)
        
        # Dashboard tab
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.dashboard_tab, text="Dashboard")
        self.create_dashboard()
        
        # Alerts tab
        self.alerts_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.alerts_tab, text="Alerts")
        self.create_alerts_tab()
        
        # Traffic tab
        self.traffic_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.traffic_tab, text="Traffic")
        self.create_traffic_tab()
        
        # Reports tab
        self.reports_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.reports_tab, text="Reports")
        self.create_reports_tab()
        
        self.tab_control.pack(expand=1, fill="both")
    
    def create_dashboard(self):
        """Create dashboard widgets"""
        # Left frame for stats
        left_frame = ttk.Frame(self.dashboard_tab)
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Stats panel
        stats_label = ttk.Label(left_frame, text="Traffic Statistics", font=('Helvetica', 12, 'bold'))
        stats_label.pack(pady=5)
        
        self.stats_text = scrolledtext.ScrolledText(left_frame, width=50, height=15)
        self.stats_text.pack(fill="both", expand=True)
        
        # Right frame for charts
        right_frame = ttk.Frame(self.dashboard_tab)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # Traffic chart
        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(5, 3))
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, master=right_frame)
        self.traffic_canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Alerts chart
        self.alerts_fig, self.alerts_ax = plt.subplots(figsize=(5, 3))
        self.alerts_canvas = FigureCanvasTkAgg(self.alerts_fig, master=right_frame)
        self.alerts_canvas.get_tk_widget().pack(fill="both", expand=True)
    
    def create_alerts_tab(self):
        """Create alerts tab widgets"""
        self.alerts_text = scrolledtext.ScrolledText(self.alerts_tab, width=100, height=30)
        self.alerts_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    def create_traffic_tab(self):
        """Create traffic analysis tab"""
        # Packet details
        packet_frame = ttk.Frame(self.traffic_tab)
        packet_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        packet_label = ttk.Label(packet_frame, text="Packet Details", font=('Helvetica', 12, 'bold'))
        packet_label.pack()
        
        columns = ("Timestamp", "Source", "Destination", "Protocol", "Port", "Size")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)
        
        self.packet_tree.pack(fill="both", expand=True)
        
        # Filter controls
        filter_frame = ttk.Frame(self.traffic_tab)
        filter_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.filter_var).pack(side="left", fill="x", expand=True)
        ttk.Button(filter_frame, text="Apply", command=self.apply_filter).pack(side="left", padx=5)
    
    def create_reports_tab(self):
        """Create reports tab"""
        self.report_text = scrolledtext.ScrolledText(self.reports_tab, width=100, height=30)
        self.report_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        button_frame = ttk.Frame(self.reports_tab)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report).pack(side="left")
        ttk.Button(button_frame, text="Send to Telegram", command=self.send_report_to_telegram).pack(side="left", padx=5)
    
    def create_terminal(self):
        """Create the terminal emulator"""
        terminal_frame = ttk.Frame(self.root)
        terminal_frame.pack(fill="x", padx=5, pady=5)
        
        self.terminal_text = scrolledtext.ScrolledText(terminal_frame, height=10)
        self.terminal_text.pack(fill="x")
        
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill="x")
        
        self.cmd_entry = ttk.Entry(input_frame)
        self.cmd_entry.pack(side="left", fill="x", expand=True)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        ttk.Button(input_frame, text="Execute", command=self.execute_command).pack(side="left", padx=5)
        
        # Print welcome message
        self.terminal_print("CyberThreat Monitor Terminal - Type 'help' for commands")
    
    def create_status_bar(self):
        """Create the status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(side="bottom", fill="x")
    
    def apply_theme(self):
        """Apply the selected theme"""
        if self.monitor.theme == "dark":
            bg = "#2e2e2e"
            fg = "#ffffff"
            self.root.tk_setPalette(background=bg, foreground=fg, activeBackground=bg, activeForeground=fg)
            
            # Configure matplotlib style
            plt.style.use('dark_background')
            
            # Configure text widgets
            for widget in [self.stats_text, self.alerts_text, self.report_text, self.terminal_text]:
                widget.config(bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        else:
            bg = "#ffffff"
            fg = "#000000"
            self.root.tk_setPalette(background=bg, foreground=fg, activeBackground=bg, activeForeground=fg)
            plt.style.use('default')
            
            for widget in [self.stats_text, self.alerts_text, self.report_text, self.terminal_text]:
                widget.config(bg="white", fg="black", insertbackground="black")
        
        # Redraw plots
        self.update_charts()
    
    def set_theme(self, theme):
        """Set the UI theme"""
        self.monitor.theme = theme
        self.monitor.save_config()
        self.apply_theme()
    
    def update_display(self):
        """Update the display with current data"""
        if self.monitor.running:
            # Update stats display
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, self.monitor.get_traffic_summary())
            
            # Update alerts display
            self.alerts_text.delete(1.0, tk.END)
            for alert in self.monitor.alert_history:
                self.alerts_text.insert(tk.END, f"[{alert['timestamp']}] [{alert['type']}] {alert['message']}\n")
            
            # Update packet tree
            self.update_packet_tree()
            
            # Update charts
            self.update_charts()
            
            # Update status
            elapsed = time.time() - self.monitor.start_time
            self.status_var.set(f"Monitoring {self.monitor.monitoring_ip} - {elapsed:.1f} seconds - {self.monitor.packet_count} packets")
        
        self.root.after(self.update_interval, self.update_display)
    
    def update_packet_tree(self):
        """Update the packet tree view"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        for packet in self.monitor.packet_history:
            timestamp = datetime.datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S')
            self.packet_tree.insert("", "end", values=(
                timestamp,
                packet['src_ip'],
                packet['dst_ip'],
                packet['protocol'],
                packet['port'],
                packet['size']
            ))
    
    def update_charts(self):
        """Update the traffic and alerts charts"""
        # Traffic chart
        self.traffic_ax.clear()
        
        if self.monitor.traffic_stats:
            directions = ['inbound', 'outbound']
            protocols = ['TCP', 'UDP', 'ICMP']
            
            bottom = None
            for proto in protocols:
                counts = [self.monitor.traffic_stats[d].get(proto, 0) for d in directions]
                self.traffic_ax.bar(directions, counts, label=proto, bottom=bottom)
                if bottom is None:
                    bottom = counts
                else:
                    bottom = [bottom[i] + counts[i] for i in range(len(bottom))]
            
            self.traffic_ax.set_title("Traffic by Protocol")
            self.traffic_ax.legend()
        
        self.traffic_canvas.draw()
        
        # Alerts chart
        self.alerts_ax.clear()
        
        if self.monitor.alert_history:
            alert_counts = defaultdict(int)
            for alert in self.monitor.alert_history:
                alert_counts[alert['type']] += 1
            
            if alert_counts:
                labels = list(alert_counts.keys())
                counts = list(alert_counts.values())
                
                self.alerts_ax.pie(counts, labels=labels, autopct='%1.1f%%')
                self.alerts_ax.set_title("Alert Distribution")
        
        self.alerts_canvas.draw()
    
    def apply_filter(self):
        """Apply filter to packet tree"""
        filter_text = self.filter_var.get().lower()
        
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)['values']
            if any(filter_text in str(v).lower() for v in values):
                self.packet_tree.attatch(item)
            else:
                self.packet_tree.detach(item)
    
    def execute_command(self, event=None):
        """Execute a terminal command"""
        cmd = self.cmd_entry.get()
        self.cmd_entry.delete(0, tk.END)
        
        self.terminal_print(f"> {cmd}")
        
        if not cmd:
            return
            
        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:]
        
        try:
            if command == "help":
                self.show_help()
            elif command == "exit":
                self.root.quit()
            elif command == "ifconfig":
                if len(args) > 0 and args[0] == "/all":
                    output = self.monitor.get_network_info()
                else:
                    output = self.monitor.get_network_info()
                self.terminal_print(output)
            elif command == "clear":
                self.terminal_text.delete(1.0, tk.END)
            elif command == "start" and len(args) >= 2 and args[0] == "monitoring":
                ip = args[1]
                output = self.monitor.start_monitoring(ip)
                self.terminal_print(output)
            elif command == "stop":
                output = self.monitor.stop_monitoring()
                self.terminal_print(output)
            elif command == "netstat":
                output = self.monitor.get_netstat()
                self.terminal_print(output)
            elif command == "ping" and len(args) >= 1:
                ip = args[0]
                output = self.monitor.ping(ip)
                self.terminal_print(output)
            elif command == "tracert" and len(args) >= 1:
                ip = args[0]
                output = self.monitor.traceroute(ip)
                self.terminal_print(output)
            else:
                self.terminal_print(f"Unknown command: {command}. Type 'help' for available commands.")
        except Exception as e:
            self.terminal_print(f"Error executing command: {e}")
    
    def terminal_print(self, text):
        """Print text to the terminal"""
        self.terminal_text.insert(tk.END, text + "\n")
        self.terminal_text.see(tk.END)
    
    def new_session(self):
        """Start a new monitoring session"""
        ip = tk.simpledialog.askstring("New Session", "Enter IP address to monitor:")
        if ip:
            self.monitor.stop_monitoring()
            self.terminal_print(self.monitor.start_monitoring(ip))
    
    def save_report(self):
        """Save the current report to a file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.monitor.generate_report())
                self.status_var.set(f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")
    
    def generate_report(self):
        """Generate and display a report"""
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, self.monitor.generate_report())
    
    def send_report_to_telegram(self):
        """Send the current report to Telegram"""
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            messagebox.showwarning("Warning", "Telegram token and chat ID must be configured in Settings")
            return
            
        report = self.monitor.generate_report()
        self.monitor.send_telegram_alert(f"Accurate Cyber Defense Threat Monitorirng Bot Threat Report:\n\n{report}")
        self.status_var.set("Report sent to Telegram")
    
    def show_network_info(self):
        """Show network information"""
        info = self.monitor.get_network_info()
        self.show_info_window("Network Information", info)
    
    def show_ping_tool(self):
        """Show ping tool dialog"""
        ip = tk.simpledialog.askstring("Ping Tool", "Enter IP address to ping:")
        if ip:
            result = self.monitor.ping(ip)
            self.show_info_window(f"Ping Results for {ip}", result)
    
    def show_traceroute(self):
        """Show traceroute dialog"""
        ip = tk.simpledialog.askstring("Traceroute", "Enter IP address to trace:")
        if ip:
            result = self.monitor.traceroute(ip)
            self.show_info_window(f"Traceroute to {ip}", result)
    
    def show_netstat(self):
        """Show netstat information"""
        result = self.monitor.get_netstat()
        self.show_info_window("Network Statistics", result)
    
    def show_telegram_settings(self):
        """Show Telegram settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Telegram Settings")
        
        ttk.Label(dialog, text="Bot Token:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        token_entry = ttk.Entry(dialog, width=40)
        token_entry.grid(row=0, column=1, padx=5, pady=5)
        if self.monitor.telegram_token:
            token_entry.insert(0, self.monitor.telegram_token)
        
        ttk.Label(dialog, text="Chat ID:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        chat_id_entry = ttk.Entry(dialog, width=40)
        chat_id_entry.grid(row=1, column=1, padx=5, pady=5)
        if self.monitor.telegram_chat_id:
            chat_id_entry.insert(0, self.monitor.telegram_chat_id)
        
        def save_settings():
            self.monitor.telegram_token = token_entry.get()
            self.monitor.telegram_chat_id = chat_id_entry.get()
            self.monitor.save_config()
            dialog.destroy()
            self.status_var.set("Telegram settings saved")
        
        ttk.Button(dialog, text="Save", command=save_settings).grid(row=2, column=1, padx=5, pady=5, sticky="e")
    
    def show_threshold_settings(self):
        """Show threshold settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Threshold Settings")
        
        row = 0
        entries = {}
        
        for threat, value in THRESHOLDS.items():
            ttk.Label(dialog, text=f"{threat.replace('_', ' ').title()}:").grid(row=row, column=0, padx=5, pady=5, sticky="e")
            entry = ttk.Entry(dialog, width=10)
            entry.grid(row=row, column=1, padx=5, pady=5)
            entry.insert(0, str(value))
            entries[threat] = entry
            row += 1
        
        def save_settings():
            for threat, entry in entries.items():
                try:
                    THRESHOLDS[threat] = float(entry.get())
                except ValueError:
                    messagebox.showerror("Error", f"Invalid value for {threat}")
                    return
            
            self.status_var.set("Threshold settings updated")
            dialog.destroy()
        
        ttk.Button(dialog, text="Save", command=save_settings).grid(row=row, column=1, padx=5, pady=5, sticky="e")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Accurate Cyber Defense Threat Monitoring Bot.0
Advanced IP-Based Threat Detection System

Features:
- Real-time network monitoring
- DoS/DDoS detection
- Port scan detection
- HTTP/HTTPS flood detection
- Unusual traffic detection
- Telegram alerting
- Comprehensive reporting
"""
        messagebox.showinfo("About Accurate Cyber Defense Threat Monitoring Bot", about_text)
    
    def show_help(self):
        """Show help information"""
        help_text = """Available Commands:
help - Show this help message
exit - Exit the application
ifconfig - Show network interface information
ifconfig /all - Show detailed network information
clear - Clear the terminal
start monitoring <ip> - Start monitoring an IP address
stop - Stop monitoring
netstat - Show network statistics
ping <ip> - Ping an IP address
tracert <ip> - Perform traceroute to an IP address
"""
        self.show_info_window("Help", help_text)
    
    def show_info_window(self, title, text):
        """Show a simple info window with text"""
        window = tk.Toplevel(self.root)
        window.title(title)
        
        text_widget = scrolledtext.ScrolledText(window, width=80, height=20)
        text_widget.pack(fill="both", expand=True, padx=5, pady=5)
        text_widget.insert(tk.END, text)
        text_widget.config(state="disabled")
        
        ttk.Button(window, text="Close", command=window.destroy).pack(pady=5)

def main():
    root = tk.Tk()
    app = CyberThreatMonitorUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()