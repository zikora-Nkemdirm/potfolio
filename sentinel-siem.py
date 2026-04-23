import tkinter as tk
from tkinter import ttk, messagebox
import random
import time
import threading
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque

class SentinaxSIEM:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinax SIEM // Enterprise")
        self.root.geometry("1400x900") 
        # Softer background color (Dark Slate)
        self.bg_main = "#0f172a" 
        self.bg_card = "#1e293b"
        self.accent_blue = "#6366f1" # Soft Indigo
        self.accent_red = "#fb7185"  # Soft Rose
        self.text_dim = "#94a3b8"
        
        self.root.configure(bg=self.bg_main)
        
        self.max_data_points = 25
        self.eps_data = deque([0] * self.max_data_points, maxlen=self.max_data_points)
        self.event_count_this_second = 0
        self.is_running = True
        self.blocked_ips = set()
        
        self.locations = ["All Regions", "Lagos, NG", "Berlin, DE", "Austin, US", "Tokyo, JP", "London, UK", "Akpugo, NG"]
        self.selected_location = tk.StringVar(value=self.locations[0])
        
        self.setup_styles()
        self.setup_layout()
        self.create_context_menu()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.sim_thread = threading.Thread(target=self.run_simulation, daemon=True)
        self.sim_thread.start()
        self.update_graph()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Softer Treeview
        self.style.configure("Treeview", 
                             background=self.bg_card, 
                             foreground="#e2e8f0", 
                             fieldbackground=self.bg_card, 
                             borderwidth=0, 
                             font=("Segoe UI", 10),
                             rowheight=30)
        self.style.configure("Treeview.Heading", 
                             background="#334155", 
                             foreground=self.text_dim, 
                             font=("Segoe UI", 9, "bold"),
                             borderwidth=0)
        self.style.map("Treeview", background=[('selected', '#334155')])
        
        # Soft Dropdown
        self.style.configure("TMenubutton", background=self.bg_card, foreground="#f1f5f9", borderwidth=0)

    def setup_layout(self):
        # Header with more padding
        self.header = tk.Frame(self.root, bg=self.bg_main)
        self.header.pack(fill=tk.X, padx=30, pady=20)
        
        tk.Label(self.header, text="Sentinax", fg="#f1f5f9", bg=self.bg_main, font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT)
        tk.Label(self.header, text="SIEM", fg=self.accent_blue, bg=self.bg_main, font=("Segoe UI", 18)).pack(side=tk.LEFT)
        
        selector_frame = tk.Frame(self.header, bg=self.bg_main)
        selector_frame.pack(side=tk.LEFT, padx=40)
        tk.Label(selector_frame, text="Scope:", fg=self.text_dim, bg=self.bg_main, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5)
        self.location_menu = ttk.OptionMenu(selector_frame, self.selected_location, *self.locations)
        self.location_menu.pack(side=tk.LEFT)

        self.status_label = tk.Label(self.header, text="● System Healthy", fg="#2dd4bf", bg=self.bg_main, font=("Segoe UI", 9))
        self.status_label.pack(side=tk.RIGHT)

        # Main Container
        self.main_container = tk.Frame(self.root, bg=self.bg_main)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=30)

        # Stats Cards
        self.threat_card = self.create_card(self.main_container, "Threat Level", "SECURE", 0, 0)
        self.threat_card.config(fg="#2dd4bf")
        self.sensor_card = self.create_card(self.main_container, "Active Sensors", "1,242", 0, 1)
        self.geo_card = self.create_card(self.main_container, "Active Region", "Global", 0, 2)

        # Middle Content Area
        self.content_frame = tk.Frame(self.main_container, bg=self.bg_main)
        self.content_frame.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=20)

        # Log Treeview (Left)
        self.log_frame = tk.Frame(self.content_frame, bg=self.bg_card, padx=10, pady=10)
        self.log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        columns = ("ts", "ip", "geo", "event")
        self.log_tree = ttk.Treeview(self.log_frame, columns=columns, show="headings")
        for col in columns:
            self.log_tree.heading(col, text=col.upper())
        self.log_tree.column("ts", width=100)
        self.log_tree.column("ip", width=150)
        self.log_tree.column("geo", width=150)
        self.log_tree.column("event", width=400)
        self.log_tree.pack(fill=tk.BOTH, expand=True)
        self.log_tree.bind("<Button-3>", self.show_context_menu)

        # Mitigation Panel (Right)
        self.soar_panel = tk.Frame(self.content_frame, bg=self.bg_card, width=280, padx=10, pady=10)
        self.soar_panel.pack(side=tk.RIGHT, fill=tk.Y)
        tk.Label(self.soar_panel, text="MITIGATION LOG", fg=self.text_dim, bg=self.bg_card, font=("Segoe UI", 8, "bold")).pack(pady=(0,10))
        self.soar_log = tk.Listbox(self.soar_panel, bg="#111827", fg="#94a3b8", font=("Consolas", 9), borderwidth=0, highlightthickness=0)
        self.soar_log.pack(fill=tk.BOTH, expand=True)
        
        # Graph (Bottom)
        self.viz_frame = tk.Frame(self.main_container, bg=self.bg_card, padx=10, pady=10)
        self.viz_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 30))
        
        self.fig, self.ax = plt.subplots(figsize=(10, 1.8), facecolor=self.bg_card)
        self.ax.set_facecolor(self.bg_card)
        self.line, = self.ax.plot(self.eps_data, color=self.accent_blue, linewidth=3, alpha=0.8)
        self.ax.axis('off')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.main_container.grid_columnconfigure((0,1,2), weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

    def create_card(self, parent, title, value, r, c):
        card = tk.Frame(parent, bg=self.bg_card, highlightbackground="#334155", highlightthickness=1)
        card.grid(row=r, column=c, padx=8, sticky="nsew")
        tk.Label(card, text=title.upper(), fg=self.text_dim, bg=self.bg_card, font=("Segoe UI", 8, "bold")).pack(pady=(15, 2))
        val_label = tk.Label(card, text=value, fg="#f8fafc", bg=self.bg_card, font=("Segoe UI", 20, "bold"))
        val_label.pack(pady=(0, 15))
        return val_label

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=self.bg_card, fg="#f8fafc", borderwidth=0)
        self.context_menu.add_command(label="🚫 Block Address", command=self.action_block_ip)
        self.context_menu.add_command(label="🔍 Investigation", command=self.action_whois)

    def show_context_menu(self, event):
        item = self.log_tree.identify_row(event.y)
        if item:
            self.log_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def action_block_ip(self):
        selected = self.log_tree.selection()[0]
        ip = self.log_tree.item(selected)['values'][1]
        self.blocked_ips.add(ip)
        self.log_soar(f"Blocked: {ip}")

    def action_whois(self):
        selected = self.log_tree.selection()[0]
        ip = self.log_tree.item(selected)['values'][1]
        self.log_soar(f"Whois: {ip}")

    def log_soar(self, action):
        ts = datetime.now().strftime("%H:%M")
        self.soar_log.insert(0, f" {ts} | {action}")

    def update_graph(self):
        if self.is_running:
            try:
                self.eps_data.append(self.event_count_this_second)
                self.event_count_this_second = 0 
                self.line.set_ydata(self.eps_data)
                self.ax.set_ylim(0, max(self.eps_data) + 5)
                self.canvas.draw()
                self.root.after(1000, self.update_graph)
            except: pass

    def run_simulation(self):
        logs = [
            ("192.168.1.50", "User Login"),
            ("45.67.23.11", "SQL Warning"),
            ("102.89.34.122", "Network Scan"),
            ("185.220.101.4", "Inbound Request"),
            ("10.0.0.42", "File Access")
        ]
        while self.is_running:
            time.sleep(random.uniform(0.6, 1.8))
            if not self.is_running: break
            target = self.selected_location.get()
            geo = random.choice(self.locations[1:]) 
            if target != "All Regions" and geo != target: continue
            ip, msg = random.choice(logs)
            if ip in self.blocked_ips: continue 
            self.event_count_this_second += 1
            ts = datetime.now().strftime("%H:%M:%S")
            is_critical = any(x in msg.lower() for x in ["warning", "scan"])
            try: self.root.after(0, self.update_ui, msg, ts, ip, geo, is_critical)
            except: break

    def update_ui(self, msg, ts, ip, geo, is_critical):
        if not self.is_running: return
        try:
            item = self.log_tree.insert("", 0, values=(ts, ip, geo, msg))
            if is_critical:
                self.log_tree.tag_configure("crit", foreground=self.accent_red)
                self.log_tree.item(item, tags=("crit",))
                self.threat_card.config(text="ELEVATED", fg=self.accent_red)
                self.root.after(3000, self.reset_threat_level)
            if len(self.log_tree.get_children()) > 40:
                self.log_tree.delete(self.log_tree.get_children()[-1])
            self.geo_card.config(text=geo)
        except: pass

    def reset_threat_level(self):
        if self.is_running:
            try: self.threat_card.config(text="SECURE", fg="#2dd4bf")
            except: pass

    def on_closing(self):
        self.is_running = False
        try:
            for after_id in self.root.tk.eval('after info').split():
                self.root.after_cancel(after_id)
        except: pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SentinaxSIEM(root)
    root.mainloop()