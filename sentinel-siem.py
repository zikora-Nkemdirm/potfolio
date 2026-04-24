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
        
        self.locations = ["All Regions", "Lagos, NG", "Berlin, DE", "Austin, US", "Tokyo, JP", "London, UK"]
        self.selected_location = tk.StringVar(value=self.locations[0])
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

    def setup_layout(self):
        # Header
        self.header = tk.Frame(self.root, bg=self.bg_main)
        self.header.pack(fill=tk.X, padx=30, pady=20)
        
        tk.Label(self.header, text="SENTINEL", fg="#f1f5f9", bg=self.bg_main, font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT)
        
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
                if not self.is_paused:
                    self.event_count_this_second += 1
            
            cap_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception as e:
            self.capture_on = False
            self.root.after(0, lambda: messagebox.showwarning("Capture Stopped", f"Interface Error: {e}"))

    def update_graph(self):
        if self.is_running:
            if not self.is_paused:
                self.eps_data.append(self.event_count_this_second)
                self.sensor_card.config(text=str(self.event_count_this_second))
                self.event_count_this_second = 0 
                
                self.line.set_ydata(self.eps_data)
                curr_max = max(self.eps_data)
                self.ax.set_ylim(0, curr_max + 10 if curr_max > 5 else 20)
                
                ticks = [0, 10, 20, 30, 40, 49]
                labels = [f"-{50-t}s" for t in ticks]
                self.ax.set_xticks(ticks)
                self.ax.set_xticklabels(labels)
                self.canvas.draw()
            
            self.root.after(1000, self.update_graph)

    def run_simulation(self):
        while self.is_running:
            if not self.is_paused:
                time.sleep(random.uniform(0.3, 0.8))
                ts = datetime.now().strftime("%H:%M:%S")
                ip = f"192.168.1.{random.randint(2, 254)}"
                geo = random.choice(self.locations[1:])
                msg = random.choice(["Inbound TCP", "UDP Stream", "DDoS Attempt", "Auth Success"])
                
                self.event_count_this_second += 1
                self.root.after(0, self.update_ui, msg, ts, ip, geo)
            else:
                time.sleep(0.5)

    def update_ui(self, msg, ts, ip, geo):
        if self.is_paused: return
        self.log_tree.insert("", 0, values=(ts, ip, geo, msg))
        if len(self.log_tree.get_children()) > 100:
            self.log_tree.delete(self.log_tree.get_children()[-1])

    def create_context_menu(self):
        self.menu = tk.Menu(self.root, tearoff=0, bg=self.bg_card, fg="white")
        self.menu.add_command(label="Block IP", command=lambda: messagebox.showinfo("Action", "IP Blocked"))

    def on_closing(self):
        self.is_running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = Sentinel(root)
    root.mainloop()