import tkinter as tk
from tkinter import ttk, scrolledtext, font
import random
import time
import threading
import math

class CyberCommandCenter(tk.Tk):
    def __init__(self):
        super().__init__()

        # Theme colors - charcoal and deep navy
        self.bg_primary = "#1a1a1a"  # Charcoal
        self.bg_secondary = "#0f1419"  # Deep navy
        self.bg_card = "#1e2329"  # Slightly lighter navy
        self.accent_cyan = "#00ffff"  # Glowing cyan
        self.accent_amber = "#ffbf00"  # Amber for alerts
        self.text_primary = "#ffffff"  # White text
        self.text_secondary = "#b0b0b0"  # Gray text
        self.text_green = "#00ff00"  # Green for data streams

        self.title("Cybersecurity Command Center")
        self.geometry("1920x1080")  # 8k-like resolution
        self.configure(bg=self.bg_primary)

        # Custom fonts
        self.title_font = font.Font(family="Segoe UI", size=16, weight="bold")
        self.body_font = font.Font(family="Segoe UI", size=10)
        self.mono_font = font.Font(family="Consolas", size=9)

        self.setup_ui()
        self.start_data_streams()

    def setup_ui(self):
        # Main container
        main_frame = tk.Frame(self, bg=self.bg_primary)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Top header
        self.create_header(main_frame)

        # Main content area
        content_frame = tk.Frame(main_frame, bg=self.bg_primary)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

        # Left panel - Data Connectors
        self.create_data_connectors_panel(content_frame)

        # Center panel - Detection Engine
        self.create_detection_engine_panel(content_frame)

        # Right panel - Compliance & Retention
        self.create_compliance_panel(content_frame)

        # User Permissions overlay (initially hidden)
        self.create_user_permissions_overlay()

    def create_header(self, parent):
        header = tk.Frame(parent, bg=self.bg_secondary, height=60)
        header.pack(fill=tk.X, pady=(0, 10))
        header.pack_propagate(False)

        # Title
        title_label = tk.Label(header, text="CYBERSECURITY COMMAND CENTER",
                              font=self.title_font, fg=self.accent_cyan, bg=self.bg_secondary)
        title_label.pack(side=tk.LEFT, padx=20, pady=15)

        # Status indicators
        status_frame = tk.Frame(header, bg=self.bg_secondary)
        status_frame.pack(side=tk.RIGHT, padx=20)

        # System status
        status_label = tk.Label(status_frame, text="● SYSTEM ACTIVE",
                               font=self.body_font, fg=self.text_green, bg=self.bg_secondary)
        status_label.pack(side=tk.LEFT, padx=(0, 20))

        # Threat level
        threat_label = tk.Label(status_frame, text="THREAT LEVEL: LOW",
                               font=self.body_font, fg=self.text_primary, bg=self.bg_secondary)
        threat_label.pack(side=tk.LEFT, padx=(0, 20))

        # User permissions button
        perm_btn = tk.Button(status_frame, text="USER PERMISSIONS",
                           font=self.body_font, fg=self.text_primary, bg=self.bg_card,
                           relief=tk.FLAT, padx=15, pady=5, command=self.toggle_user_permissions)
        perm_btn.pack(side=tk.LEFT)

    def create_data_connectors_panel(self, parent):
        # Data Connectors panel
        panel = tk.Frame(parent, bg=self.bg_card, width=400)
        panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        panel.pack_propagate(False)

        # Panel header
        header = tk.Frame(panel, bg=self.bg_card, height=40)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title = tk.Label(header, text="DATA CONNECTORS", font=self.title_font,
                        fg=self.accent_cyan, bg=self.bg_card)
        title.pack(side=tk.LEFT, padx=15, pady=8)

        # Connector streams
        self.connector_frames = {}
        connectors = ["Cloud", "Firewall", "Endpoint", "Network", "Database"]

        for connector in connectors:
            self.create_connector_stream(panel, connector)

    def create_connector_stream(self, parent, name):
        frame = tk.Frame(parent, bg=self.bg_secondary, height=120)
        frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        frame.pack_propagate(False)

        # Connector header
        header = tk.Frame(frame, bg=self.bg_secondary, height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        status_indicator = tk.Label(header, text="●", font=self.body_font,
                                  fg=self.text_green, bg=self.bg_secondary)
        status_indicator.pack(side=tk.LEFT, padx=(10, 5), pady=5)

        name_label = tk.Label(header, text=name.upper(), font=self.body_font,
                             fg=self.text_primary, bg=self.bg_secondary)
        name_label.pack(side=tk.LEFT, pady=5)

        # Scrolling text area
        text_frame = tk.Frame(frame, bg=self.bg_primary, height=90)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        text_area = scrolledtext.ScrolledText(text_frame, height=4, width=40,
                                            bg=self.bg_primary, fg=self.text_green,
                                            font=self.mono_font, relief=tk.FLAT,
                                            selectbackground=self.accent_cyan)
        text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text_area.config(state=tk.DISABLED)

        self.connector_frames[name] = text_area

    def create_detection_engine_panel(self, parent):
        # Central Detection Engine panel
        panel = tk.Frame(parent, bg=self.bg_card)
        panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

        # Panel header
        header = tk.Frame(panel, bg=self.bg_card, height=40)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title = tk.Label(header, text="DETECTION ENGINE", font=self.title_font,
                        fg=self.accent_cyan, bg=self.bg_card)
        title.pack(side=tk.LEFT, padx=15, pady=8)

        # Radar visualization area
        radar_frame = tk.Frame(panel, bg=self.bg_primary, height=400)
        radar_frame.pack(fill=tk.X, padx=20, pady=(10, 20))
        radar_frame.pack_propagate(False)

        # Create radar canvas
        self.radar_canvas = tk.Canvas(radar_frame, bg=self.bg_primary, height=400,
                                    highlightthickness=0)
        self.radar_canvas.pack(fill=tk.BOTH, expand=True)

        # Alert section
        alert_frame = tk.Frame(panel, bg=self.bg_secondary, height=200)
        alert_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        alert_frame.pack_propagate(False)

        alert_title = tk.Label(alert_frame, text="CRITICAL ALERTS", font=self.title_font,
                              fg=self.accent_amber, bg=self.bg_secondary)
        alert_title.pack(anchor=tk.W, padx=15, pady=(10, 5))

        self.alert_text = tk.Text(alert_frame, height=6, bg=self.bg_secondary,
                                fg=self.text_primary, font=self.body_font,
                                relief=tk.FLAT, selectbackground=self.accent_cyan)
        self.alert_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        self.alert_text.insert(tk.END, "• Network intrusion detected from IP 192.168.1.100\n• Multiple failed login attempts on admin account\n• Unusual data exfiltration pattern detected\n• Firewall rule violation on port 3389")
        self.alert_text.config(state=tk.DISABLED)

        # Network map placeholder
        map_frame = tk.Frame(panel, bg=self.bg_primary, height=200)
        map_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        map_title = tk.Label(map_frame, text="NETWORK TOPOLOGY MAP", font=self.title_font,
                           fg=self.accent_cyan, bg=self.bg_primary)
        map_title.pack(anchor=tk.W, padx=15, pady=10)

        # Simple network representation
        self.create_network_map(map_frame)

    def create_network_map(self, parent):
        canvas = tk.Canvas(parent, bg=self.bg_primary, height=150, highlightthickness=0)
        canvas.pack(fill=tk.X, padx=15, pady=(0, 10))

        # Draw simple network nodes
        nodes = [(50, 50), (150, 50), (250, 50), (350, 50), (200, 120)]
        labels = ["Firewall", "Server", "Database", "Endpoint", "Router"]

        for i, (x, y) in enumerate(nodes):
            # Node circle
            canvas.create_oval(x-15, y-15, x+15, y+15, fill=self.bg_card,
                             outline=self.accent_cyan, width=2)
            # Node label
            canvas.create_text(x, y+25, text=labels[i], fill=self.text_primary,
                             font=self.body_font)

        # Connections
        connections = [(0, 1), (1, 2), (2, 3), (1, 4), (4, 0)]
        for start, end in connections:
            x1, y1 = nodes[start]
            x2, y2 = nodes[end]
            canvas.create_line(x1, y1, x2, y2, fill=self.accent_cyan, width=1)

    def create_compliance_panel(self, parent):
        # Compliance & Retention panel
        panel = tk.Frame(parent, bg=self.bg_card, width=350)
        panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        panel.pack_propagate(False)

        # Panel header
        header = tk.Frame(panel, bg=self.bg_card, height=40)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title = tk.Label(header, text="COMPLIANCE & RETENTION", font=self.title_font,
                        fg=self.accent_cyan, bg=self.bg_card)
        title.pack(side=tk.LEFT, padx=15, pady=8)

        # Retention calendar
        calendar_frame = tk.Frame(panel, bg=self.bg_secondary, height=150)
        calendar_frame.pack(fill=tk.X, padx=15, pady=(15, 10))
        calendar_frame.pack_propagate(False)

        cal_title = tk.Label(calendar_frame, text="DATA RETENTION: 365 DAYS",
                           font=self.body_font, fg=self.text_primary, bg=self.bg_secondary)
        cal_title.pack(anchor=tk.W, padx=10, pady=(10, 5))

        # Progress bar
        progress_frame = tk.Frame(calendar_frame, bg=self.bg_secondary)
        progress_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Simple progress bar representation
        self.create_progress_bar(progress_frame, 75)  # 75% complete

        days_label = tk.Label(calendar_frame, text="275/365 days completed",
                            font=self.body_font, fg=self.text_secondary, bg=self.bg_secondary)
        days_label.pack(anchor=tk.W, padx=10, pady=(0, 10))

        # Data masking toggle
        masking_frame = tk.Frame(panel, bg=self.bg_secondary, height=100)
        masking_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        masking_frame.pack_propagate(False)

        masking_title = tk.Label(masking_frame, text="DATA MASKING",
                               font=self.body_font, fg=self.text_primary, bg=self.bg_secondary)
        masking_title.pack(anchor=tk.W, padx=10, pady=(10, 5))

        # Toggle button
        self.masking_var = tk.BooleanVar(value=True)
        toggle_btn = tk.Checkbutton(masking_frame, text="ACTIVE",
                                  variable=self.masking_var, font=self.body_font,
                                  fg=self.text_green, bg=self.bg_secondary,
                                  selectcolor=self.bg_card, activebackground=self.bg_secondary,
                                  activeforeground=self.text_green)
        toggle_btn.pack(anchor=tk.W, padx=10, pady=(0, 10))

        # Additional compliance metrics
        metrics_frame = tk.Frame(panel, bg=self.bg_secondary, height=200)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        metrics_title = tk.Label(metrics_frame, text="COMPLIANCE METRICS",
                               font=self.body_font, fg=self.text_primary, bg=self.bg_secondary)
        metrics_title.pack(anchor=tk.W, padx=10, pady=(10, 10))

        metrics = [
            "GDPR: Compliant",
            "HIPAA: Compliant",
            "SOX: Compliant",
            "PCI DSS: Compliant"
        ]

        for metric in metrics:
            metric_label = tk.Label(metrics_frame, text=f"● {metric}",
                                  font=self.body_font, fg=self.text_green, bg=self.bg_secondary)
            metric_label.pack(anchor=tk.W, padx=20, pady=2)

    def create_progress_bar(self, parent, percentage):
        # Simple progress bar
        bar_width = 250
        bar_height = 20

        canvas = tk.Canvas(parent, width=bar_width, height=bar_height,
                         bg=self.bg_primary, highlightthickness=0)
        canvas.pack()

        # Background
        canvas.create_rectangle(0, 0, bar_width, bar_height, fill=self.bg_primary, outline=self.accent_cyan)

        # Progress fill
        fill_width = int(bar_width * percentage / 100)
        canvas.create_rectangle(0, 0, fill_width, bar_height, fill=self.accent_cyan, outline="")

        # Percentage text
        canvas.create_text(bar_width/2, bar_height/2, text=f"{percentage}%",
                         fill=self.bg_primary, font=self.body_font)

    def create_user_permissions_overlay(self):
        # User Permissions overlay (initially hidden)
        self.permissions_overlay = tk.Frame(self, bg=self.bg_primary)
        self.permissions_overlay.place(relwidth=1, relheight=1)
        self.permissions_overlay.place_forget()  # Hide initially

        # Semi-transparent background
        overlay_bg = tk.Frame(self.permissions_overlay, bg="#000000")
        overlay_bg.place(relwidth=1, relheight=1)

        # Permissions panel
        panel = tk.Frame(self.permissions_overlay, bg=self.bg_card, width=500, height=600)
        panel.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Header
        header = tk.Frame(panel, bg=self.bg_card, height=50)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title = tk.Label(header, text="USER PERMISSIONS", font=self.title_font,
                        fg=self.accent_cyan, bg=self.bg_card)
        title.pack(side=tk.LEFT, padx=20, pady=12)

        close_btn = tk.Button(header, text="×", font=("Segoe UI", 16),
                            fg=self.text_primary, bg=self.bg_card,
                            relief=tk.FLAT, command=self.toggle_user_permissions)
        close_btn.pack(side=tk.RIGHT, padx=15, pady=5)

        # User roles list
        roles_frame = tk.Frame(panel, bg=self.bg_card)
        roles_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        roles = [
            ("System Administrator", "Full access to all systems"),
            ("Security Analyst", "Read access to logs and alerts"),
            ("Compliance Officer", "Access to compliance reports"),
            ("Network Engineer", "Network configuration access"),
            ("Auditor", "Read-only access to all data")
        ]

        for role, desc in roles:
            role_frame = tk.Frame(roles_frame, bg=self.bg_secondary, height=60)
            role_frame.pack(fill=tk.X, pady=(0, 10))
            role_frame.pack_propagate(False)

            # Avatar placeholder (circle)
            avatar_canvas = tk.Canvas(role_frame, width=40, height=40,
                                    bg=self.bg_secondary, highlightthickness=0)
            avatar_canvas.pack(side=tk.LEFT, padx=(10, 15), pady=10)
            avatar_canvas.create_oval(5, 5, 35, 35, fill=self.accent_cyan, outline=self.accent_cyan)

            # Role info
            info_frame = tk.Frame(role_frame, bg=self.bg_secondary)
            info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)

            role_label = tk.Label(info_frame, text=role, font=self.body_font,
                                fg=self.text_primary, bg=self.bg_secondary)
            role_label.pack(anchor=tk.W)

            desc_label = tk.Label(info_frame, text=desc, font=self.body_font,
                                fg=self.text_secondary, bg=self.bg_secondary)
            desc_label.pack(anchor=tk.W)

    def toggle_user_permissions(self):
        if self.permissions_overlay.winfo_viewable():
            self.permissions_overlay.place_forget()
        else:
            self.permissions_overlay.place(relwidth=1, relheight=1)

    def start_data_streams(self):
        # Start background threads for data streams
        threading.Thread(target=self.update_data_streams, daemon=True).start()
        threading.Thread(target=self.animate_radar, daemon=True).start()

    def update_data_streams(self):
        while True:
            for connector, text_area in self.connector_frames.items():
                # Generate random log entries
                log_entries = [
                    f"[{time.strftime('%H:%M:%S')}] {connector}: Connection established",
                    f"[{time.strftime('%H:%M:%S')}] {connector}: Data packet received",
                    f"[{time.strftime('%H:%M:%S')}] {connector}: Security scan completed",
                    f"[{time.strftime('%H:%M:%S')}] {connector}: Authentication successful"
                ]

                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, random.choice(log_entries) + "\n")
                text_area.see(tk.END)  # Auto scroll
                text_area.config(state=tk.DISABLED)

            time.sleep(2)  # Update every 2 seconds

    def animate_radar(self):
        # Simple radar animation
        angle = 0
        while True:
            # Clear previous sweep
            self.radar_canvas.delete("sweep")

            # Draw radar circles
            center_x, center_y = 300, 200
            for radius in range(50, 201, 50):
                self.radar_canvas.create_oval(center_x-radius, center_y-radius,
                                            center_x+radius, center_y+radius,
                                            outline=self.accent_cyan, width=1, tags="radar")

            # Draw sweep line
            sweep_x = center_x + 150 * math.cos(math.radians(angle))
            sweep_y = center_y + 150 * math.sin(math.radians(angle))
            self.radar_canvas.create_line(center_x, center_y, sweep_x, sweep_y,
                                        fill=self.accent_cyan, width=2, tags="sweep")

            # Draw center dot
            self.radar_canvas.create_oval(center_x-3, center_y-3, center_x+3, center_y+3,
                                        fill=self.accent_cyan, tags="radar")

            angle = (angle + 5) % 360
            time.sleep(0.1)

if __name__ == "__main__":
    app = CyberCommandCenter()
    app.mainloop()