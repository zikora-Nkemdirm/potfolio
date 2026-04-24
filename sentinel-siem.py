import tkinter as tk
from tkinter import ttk, messagebox
import random
import socket
import struct
import time
import threading
import os
import ctypes
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
from PIL import Image, ImageTk
import csv

class Sentinel:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel Enterprise - SIEM")
        self.root.geometry("1400x900") 
        
        # Theme Colors
        self.bg_main = "#0f172a" 
        self.bg_card = "#1e293b"
        self.accent_blue = "#6366f1" 
        self.accent_red = "#fb7185"  
        self.text_dim = "#94a3b8"
        self.root.configure(bg=self.bg_main)
        # State Variables
        self.max_data_points = 50 # Increased for better scrolling
        self.eps_data = deque([0] * self.max_data_points, maxlen=self.max_data_points)
        self.event_count_this_second = 0
        self.is_running = True
        self.is_paused = False # NEW: Pause state
        self.blocked_ips = set()
        self.capture_on = False
        self.is_closing = False  # Flag to prevent UI updates after window closes
        
        # Settings dictionary
        self.settings = {
            'critical_eps_threshold': 100,
            'keyword_watchlist': '',
            'port_filter': '',
            'capture_mode': 'Simulation Mode',
            'auto_archive': False,
            'theme': 'Emerald Night',
            'refresh_rate': 1.0
        }
        
        self.locations = [
            "All Regions",
            # Nigerian Locations (30+)
            "Lagos, NG",
            "Abuja, NG",
            "Ibadan, NG",
            "Kano, NG",
            "Port Harcourt, NG",
            "Benin City, NG",
            "Kaduna, NG",
            "Katsina, NG",
            "Enugu, NG",
            "Ilorin, NG",
            "Osogbo, NG",
            "Ado-Ekiti, NG",
            "Akure, NG",
            "Yenagoa, NG",
            "Lokoja, NG",
            "Makurdi, NG",
            "Jos, NG",
            "Calabar, NG",
            "Yola, NG",
            "Maiduguri, NG",
            "Gusau, NG",
            "Damaturu, NG",
            "Birnin Kebbi, NG",
            "Gombe, NG",
            "Bauchi, NG",
            "Abeokuta, NG",
            "Asaba, NG",
            "Warri, NG",
            "Owerri, NG",
            "Aba, NG",
            "Onitsha, NG",
            "Uyo, NG",
            "Lafia, NG",
            # Foreign Locations (6)
            "Berlin, DE",
            "Austin, US",
    "Paris, FR",
            "Singapore, SG"
        ]
        self.selected_location = tk.StringVar(value=self.locations[0])
        self.selected_location.trace_add("write", self.update_scope)
        self.packet_capture_status = tk.StringVar(value="Packet Capture: OFF")
        
        self.setup_styles()
        self.setup_layout()
        self.create_context_menu()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Background Threads
        threading.Thread(target=self.run_simulation, daemon=True).start()
        self.update_graph()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("Treeview", background=self.bg_card, foreground="#e2e8f0", 
                             fieldbackground=self.bg_card, rowheight=30)
        self.style.configure("Treeview.Heading", background="#334155", foreground=self.text_dim)
        self.style.configure("TCombobox", fieldbackground=self.bg_card, background=self.bg_card, foreground="#e2e8f0", selectbackground=self.accent_blue)

    def setup_layout(self):
        # Header
        self.header = tk.Frame(self.root, bg=self.bg_main)
        self.header.pack(fill=tk.X, padx=30, pady=20)
        
        # Display logo text
        tk.Label(self.header, text="sentinel", fg="#f1f5f9", bg=self.bg_main, font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT)
        
        # Settings button
        settings_btn = tk.Button(self.header, text="⚙", command=self.open_settings, 
                                bg=self.bg_main, fg="#f1f5f9", relief=tk.FLAT, 
                                font=("Segoe UI", 14), padx=10)
        settings_btn.pack(side=tk.RIGHT, padx=10)
        
        # Controls Group
        self.ctrl_frame = tk.Frame(self.header, bg=self.bg_main)
        self.ctrl_frame.pack(side=tk.RIGHT)

        # PAUSE BUTTON
        self.pause_btn = tk.Button(self.ctrl_frame, text="PAUSE SYSTEM", command=self.toggle_pause, 
                                   bg=self.accent_blue, fg="white", relief=tk.FLAT, padx=15)
        self.pause_btn.pack(side=tk.LEFT, padx=10)

        # PACKET CAPTURE BUTTON
        self.cap_btn = tk.Button(self.ctrl_frame, text="START CAPTURE", command=self.authorize_and_start_capture, 
                                 bg="#334155", fg="white", relief=tk.FLAT, padx=15)
        self.cap_btn.pack(side=tk.LEFT, padx=10)

        # LOCATION SELECTOR
        self.loc_combo = ttk.Combobox(self.ctrl_frame, textvariable=self.selected_location, values=self.locations, state="readonly", width=15)
        self.loc_combo.pack(side=tk.LEFT, padx=10)

        # Main Container
        self.main_container = tk.Frame(self.root, bg=self.bg_main)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=30)

        # Stats Cards
        self.threat_card = self.create_card(self.main_container, "System Status", "ACTIVE", 0, 0)
        self.sensor_card = self.create_card(self.main_container, "Live EPS", "0", 0, 1)
        self.geo_card = self.create_card(self.main_container, "Scope", "Global", 0, 2)

        # Middle Content (Treeview with Scrollbar)
        self.content_frame = tk.Frame(self.main_container, bg=self.bg_main)
        self.content_frame.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=20)

        self.log_container = tk.Frame(self.content_frame, bg=self.bg_card)
        self.log_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        columns = ("ts", "ip", "geo", "event")
        self.log_tree = ttk.Treeview(self.log_container, columns=columns, show="headings")
        for col in columns: self.log_tree.heading(col, text=col.upper())
        
        # Scrollbar for data analysis
        self.scrollbar = ttk.Scrollbar(self.log_container, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=self.scrollbar.set)
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Graph Section
        self.viz_frame = tk.Frame(self.main_container, bg=self.bg_card, highlightthickness=1, highlightbackground="#334155")
        self.viz_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 30))
        
        self.fig, self.ax = plt.subplots(figsize=(10, 2.5), facecolor=self.bg_card)
        self.ax.set_facecolor(self.bg_card)
        self.line, = self.ax.plot(self.eps_data, color=self.accent_blue, linewidth=2)
        self.ax.grid(True, color="#334155", linestyle='--', linewidth=0.5)
        
        for spine in self.ax.spines.values(): spine.set_visible(False)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.main_container.grid_columnconfigure((0,1,2), weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

    def create_card(self, parent, title, value, r, c):
        card = tk.Frame(parent, bg=self.bg_card, highlightbackground="#334155", highlightthickness=1)
        card.grid(row=r, column=c, padx=8, sticky="nsew")
        tk.Label(card, text=title.upper(), fg=self.text_dim, bg=self.bg_card, font=("Segoe UI", 8, "bold")).pack(pady=(10, 2))
        val_label = tk.Label(card, text=value, fg="#f8fafc", bg=self.bg_card, font=("Segoe UI", 16, "bold"))
        val_label.pack(pady=(0, 10))
        return val_label

    def toggle_pause(self):
        """Pauses or resumes the UI updates and simulations."""
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_btn.config(text="RESUME SYSTEM", bg=self.accent_red)
            self.threat_card.config(text="PAUSED", fg=self.accent_red)
        else:
            self.pause_btn.config(text="PAUSE SYSTEM", bg=self.accent_blue)
            self.threat_card.config(text="ACTIVE", fg="#2dd4bf")

    def update_scope(self, *args):
        self.geo_card.config(text=self.selected_location.get())

    def check_authorization(self):
        """Verify if the app has administrative privileges for packet capture."""
        try:
            if os.name == 'nt': # Windows
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else: # Linux/Mac
                return os.getuid() == 0
        except:
            return False

    def authorize_and_start_capture(self):
        if self.capture_on:
            self.capture_on = False
            self.cap_btn.config(text="START CAPTURE", bg="#334155")
            return

        if not self.check_authorization():
            messagebox.showerror("Auth Error", "Packet Capture requires Admin/Root privileges.\nPlease restart the app as Administrator.")
            return

        self.capture_on = True
        self.cap_btn.config(text="STOP CAPTURE", bg=self.accent_red)
        threading.Thread(target=self.run_packet_capture, daemon=True).start()

    def run_packet_capture(self):
        """Simple raw socket capture (Generic IP packets)."""
        try:
            cap_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            cap_sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            cap_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            cap_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            while self.capture_on:
                raw_data, _ = cap_sock.recvfrom(65535)
                
                # Parse IP header to get ports (simplified)
                if len(raw_data) >= 20:  # Minimum IP header length
                    ip_header = raw_data[:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    protocol = iph[6]
                    
                    # Check port filter if set
                    port_match = True
                    if self.settings['port_filter']:
                        try:
                            target_port = int(self.settings['port_filter'])
                            if protocol in (6, 17):  # TCP or UDP
                                if len(raw_data) >= 24:  # Has transport header
                                    src_port = struct.unpack('!H', raw_data[20:22])[0]
                                    dst_port = struct.unpack('!H', raw_data[22:24])[0]
                                    port_match = (src_port == target_port or dst_port == target_port)
                        except ValueError:
                            pass  # Invalid port filter, ignore
                    
                    if port_match and not self.is_paused:
                        self.event_count_this_second += 1
            
            cap_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception as e:
            self.capture_on = False
            self.root.after(0, lambda: messagebox.showwarning("Capture Stopped", f"Interface Error: {e}"))

    def update_graph(self):
        if self.is_running and not self.is_closing:
            if not self.is_paused:
                self.eps_data.append(self.event_count_this_second)
                
                # Check critical threshold
                eps_value = self.event_count_this_second
                if eps_value > self.settings['critical_eps_threshold']:
                    self.sensor_card.config(text=f"{eps_value}", fg="#dc2626")
                    # Add critical warning to log
                    if not hasattr(self, '_last_critical_time') or time.time() - self._last_critical_time > 5:
                        self._last_critical_time = time.time()
                        ts = datetime.now().strftime("%H:%M:%S")
                        self.root.after(0, lambda: self.update_ui("CRITICAL OVERLOAD", ts, "SYSTEM", "ALERT"))
                else:
                    self.sensor_card.config(text=str(eps_value), fg="#f8fafc")
                
                self.event_count_this_second = 0 
                
                self.line.set_ydata(self.eps_data)
                curr_max = max(self.eps_data)
                self.ax.set_ylim(0, curr_max + 10 if curr_max > 5 else 20)
                
                ticks = [0, 10, 20, 30, 40, 49]
                labels = [f"-{50-t}s" for t in ticks]
                self.ax.set_xticks(ticks)
                self.ax.set_xticklabels(labels)
                self.canvas.draw()
            
            # Use refresh rate from settings
            refresh_ms = int(self.settings['refresh_rate'] * 1000)
            self.root.after(refresh_ms, lambda: self.update_graph())

    def run_simulation(self):
        while self.is_running:
            # Only run simulation if in simulation mode
            if self.settings['capture_mode'] == 'Simulation Mode' and not self.is_paused:
                time.sleep(random.uniform(0.3, 0.8))
                ts = datetime.now().strftime("%H:%M:%S")
                ip = f"192.168.1.{random.randint(2, 254)}"
                if self.selected_location.get() == "All Regions":
                    geo = random.choice(self.locations[1:])
                else:
                    geo = self.selected_location.get()
                msg = random.choice(["Inbound TCP", "UDP Stream", "DDoS Attempt", "Auth Success"])
                
                self.event_count_this_second += 1
                self.root.after(0, lambda: self.update_ui(msg, ts, ip, geo))
            else:
                time.sleep(0.5)

    def update_ui(self, msg, ts, ip, geo):
        if self.is_paused or self.is_closing: return
        
        # Check for keyword highlighting
        watchlist = self.settings['keyword_watchlist'].lower().split(',')
        should_highlight = any(word.strip() in msg.lower() for word in watchlist if word.strip())
        
        item_id = self.log_tree.insert("", 0, values=(ts, ip, geo, msg))
        
        # Apply highlighting if keyword found
        if should_highlight:
            self.log_tree.tag_configure("highlight", background="#dc2626", foreground="white")
            self.log_tree.item(item_id, tags=("highlight",))
        
        if len(self.log_tree.get_children()) > 100:
            self.log_tree.delete(self.log_tree.get_children()[-1])
        
        # Auto-archive functionality
        if self.settings['auto_archive'] and len(self.log_tree.get_children()) >= 1000:
            self.archive_logs()

    def open_settings(self):
        """Open the settings window."""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("500x600")
        settings_win.configure(bg=self.bg_main)
        settings_win.resizable(False, False)
        
        # Main container
        main_frame = tk.Frame(settings_win, bg=self.bg_main)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, text="SYSTEM SETTINGS", 
                              font=("Segoe UI", 16, "bold"), fg="#f1f5f9", bg=self.bg_main)
        title_label.pack(pady=(0, 20))
        
        # Alerting & Threshold Configurations
        alert_frame = tk.LabelFrame(main_frame, text="Alerting & Thresholds", 
                                   bg=self.bg_card, fg="#f1f5f9", font=("Segoe UI", 10, "bold"))
        alert_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Critical EPS Threshold
        eps_frame = tk.Frame(alert_frame, bg=self.bg_card)
        eps_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(eps_frame, text="Critical EPS Threshold:", fg="#f1f5f9", bg=self.bg_card).pack(side=tk.LEFT)
        eps_slider = tk.Scale(eps_frame, from_=0, to=200, orient=tk.HORIZONTAL, 
                             bg=self.bg_card, fg="#f1f5f9", highlightbackground=self.bg_card,
                             troughcolor=self.bg_main, activebackground=self.accent_blue)
        eps_slider.set(self.settings['critical_eps_threshold'])
        eps_slider.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # Keyword Watchlist
        keyword_frame = tk.Frame(alert_frame, bg=self.bg_card)
        keyword_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(keyword_frame, text="Keyword Watchlist (comma-separated):", 
                fg="#f1f5f9", bg=self.bg_card).pack(anchor=tk.W)
        keyword_entry = tk.Entry(keyword_frame, bg=self.bg_main, fg="#f1f5f9", 
                                insertbackground="#f1f5f9")
        keyword_entry.insert(0, self.settings['keyword_watchlist'])
        keyword_entry.pack(fill=tk.X, pady=(2, 0))
        
        # Network & Capture Settings
        network_frame = tk.LabelFrame(main_frame, text="Network & Capture", 
                                     bg=self.bg_card, fg="#f1f5f9", font=("Segoe UI", 10, "bold"))
        network_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Port Filter
        port_frame = tk.Frame(network_frame, bg=self.bg_card)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(port_frame, text="Port Filter:", fg="#f1f5f9", bg=self.bg_card).pack(side=tk.LEFT)
        port_entry = tk.Entry(port_frame, bg=self.bg_main, fg="#f1f5f9", 
                             insertbackground="#f1f5f9", width=10)
        port_entry.insert(0, self.settings['port_filter'])
        port_entry.pack(side=tk.RIGHT)
        
        # Capture Mode
        mode_frame = tk.Frame(network_frame, bg=self.bg_card)
        mode_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(mode_frame, text="Capture Mode:", fg="#f1f5f9", bg=self.bg_card).pack(side=tk.LEFT)
        mode_combo = ttk.Combobox(mode_frame, values=["Simulation Mode", "Live Capture Mode"], 
                                 state="readonly", width=15)
        mode_combo.set(self.settings['capture_mode'])
        mode_combo.pack(side=tk.RIGHT)
        
        # Data Management & Persistence
        data_frame = tk.LabelFrame(main_frame, text="Data Management", 
                                  bg=self.bg_card, fg="#f1f5f9", font=("Segoe UI", 10, "bold"))
        data_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Export Logs Button
        export_btn = tk.Button(data_frame, text="Export Logs to CSV", 
                              command=self.export_logs, bg=self.accent_blue, fg="white", 
                              relief=tk.FLAT, padx=10, pady=5)
        export_btn.pack(pady=5)
        
        # Auto-Archive
        archive_var = tk.BooleanVar(value=self.settings['auto_archive'])
        archive_check = tk.Checkbutton(data_frame, text="Auto-Archive (clear logs at 1000 entries)", 
                                      variable=archive_var, bg=self.bg_card, fg="#f1f5f9", 
                                      selectcolor=self.bg_main, activebackground=self.bg_card, 
                                      activeforeground="#f1f5f9")
        archive_check.pack(anchor=tk.W, padx=10, pady=5)
        
        # UI/UX Customization
        ui_frame = tk.LabelFrame(main_frame, text="UI/UX Customization", 
                                bg=self.bg_card, fg="#f1f5f9", font=("Segoe UI", 10, "bold"))
        ui_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Theme Selector
        theme_frame = tk.Frame(ui_frame, bg=self.bg_card)
        theme_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(theme_frame, text="Theme:", fg="#f1f5f9", bg=self.bg_card).pack(side=tk.LEFT)
        theme_combo = ttk.Combobox(theme_frame, values=["Emerald Night", "High Contrast"], 
                                  state="readonly", width=15)
        theme_combo.set(self.settings['theme'])
        theme_combo.pack(side=tk.RIGHT)
        
        # Refresh Rate
        refresh_frame = tk.Frame(ui_frame, bg=self.bg_card)
        refresh_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(refresh_frame, text="Refresh Rate (seconds):", fg="#f1f5f9", bg=self.bg_card).pack(side=tk.LEFT)
        refresh_slider = tk.Scale(refresh_frame, from_=0.5, to=3.0, resolution=0.1, orient=tk.HORIZONTAL,
                                 bg=self.bg_card, fg="#f1f5f9", highlightbackground=self.bg_card,
                                 troughcolor=self.bg_main, activebackground=self.accent_blue)
        refresh_slider.set(self.settings['refresh_rate'])
        refresh_slider.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        # Save and Cancel buttons
        button_frame = tk.Frame(main_frame, bg=self.bg_main)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def save_settings():
            self.settings['critical_eps_threshold'] = eps_slider.get()
            self.settings['keyword_watchlist'] = keyword_entry.get()
            self.settings['port_filter'] = port_entry.get()
            self.settings['capture_mode'] = mode_combo.get()
            self.settings['auto_archive'] = archive_var.get()
            self.settings['theme'] = theme_combo.get()
            self.settings['refresh_rate'] = refresh_slider.get()
            
            # Apply theme change
            self.apply_theme()
            
            settings_win.destroy()
            messagebox.showinfo("Settings", "Settings saved successfully!")
        
        save_btn = tk.Button(button_frame, text="Save", command=save_settings, 
                            bg=self.accent_blue, fg="white", relief=tk.FLAT, padx=20, pady=5)
        save_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        cancel_btn = tk.Button(button_frame, text="Cancel", command=settings_win.destroy, 
                              bg="#334155", fg="white", relief=tk.FLAT, padx=20, pady=5)
        cancel_btn.pack(side=tk.RIGHT)

    def export_logs(self):
        """Export current log tree contents to CSV."""
        try:
            with open('sentinel_logs.csv', 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Timestamp', 'IP Address', 'Location', 'Event'])
                
                for item in self.log_tree.get_children():
                    values = self.log_tree.item(item)['values']
                    writer.writerow(values)
            
            messagebox.showinfo("Export Complete", "Logs exported to sentinel_logs.csv")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {e}")

    def archive_logs(self):
        """Archive logs to a text file and clear the treeview."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sentinel_archive_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Sentinel SIEM Log Archive - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                for item in self.log_tree.get_children():
                    values = self.log_tree.item(item)['values']
                    f.write(f"{values[0]} | {values[1]} | {values[2]} | {values[3]}\n")
            
            # Clear the treeview
            for item in self.log_tree.get_children():
                self.log_tree.delete(item)
            
            print(f"Logs archived to {filename}")
        except Exception as e:
            print(f"Archive failed: {e}")

    def apply_theme(self):
        """Apply the selected theme."""
        if self.settings['theme'] == 'High Contrast':
            self.bg_main = "#000000"
            self.bg_card = "#111111"
            self.accent_blue = "#00ff00"
            self.accent_red = "#ff0000"
            self.text_dim = "#cccccc"
        else:  # Emerald Night
            self.bg_main = "#0f172a"
            self.bg_card = "#1e293b"
            self.accent_blue = "#6366f1"
            self.accent_red = "#fb7185"
            self.text_dim = "#94a3b8"
        
        # Update UI colors (simplified - would need more comprehensive updates for full theme change)
        self.root.configure(bg=self.bg_main)
        self.header.configure(bg=self.bg_main)
        self.main_container.configure(bg=self.bg_main)
        self.content_frame.configure(bg=self.bg_main)

    def create_context_menu(self):
        self.menu = tk.Menu(self.root, tearoff=0, bg=self.bg_card, fg="white")
        self.menu.add_command(label="Block IP", command=lambda: messagebox.showinfo("Action", "IP Blocked"))

    def on_closing(self):
        self.is_closing = True
        self.is_running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = Sentinel(root)
    root.mainloop()