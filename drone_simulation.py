"""
Drone Surveillance Simulation System
=====================================
Autonomous drones detecting, tracking, and following moving targets
in a simulated environment with custom Tkinter UI.
"""

import tkinter as tk
from tkinter import ttk, font
import math
import random
import time
import threading
import colorsys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from enum import Enum
from collections import deque


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

class DroneState(Enum):
    IDLE       = "IDLE"
    PATROLLING = "PATROL"
    DETECTING  = "DETECT"
    TRACKING   = "TRACK"
    FOLLOWING  = "FOLLOW"
    RETURNING  = "RETURN"
    LOW_BATTERY= "LOW BAT"

class TargetType(Enum):
    CIVILIAN = "civilian"
    VEHICLE  = "vehicle"
    ANOMALY  = "anomaly"

class AlertLevel(Enum):
    LOW    = ("LOW",    "#00ff88")
    MEDIUM = ("MEDIUM", "#ffcc00")
    HIGH   = ("HIGH",   "#ff4444")

CANVAS_W, CANVAS_H = 900, 620
DRONE_RADIUS   = 12
TARGET_RADIUS  = 9
DETECTION_RANGE = 130
FOLLOW_DISTANCE = 40
PATROL_SPEED    = 1.8
FOLLOW_SPEED    = 2.5
TARGET_SPEED    = 1.4

COLORS = {
    "bg_dark":     "#0a0e1a",
    "bg_panel":    "#0d1225",
    "bg_card":     "#111827",
    "grid":        "#1a2540",
    "accent":      "#00d4ff",
    "accent2":     "#7c3aed",
    "drone_idle":  "#4ade80",
    "drone_track": "#f59e0b",
    "drone_follow":"#ef4444",
    "drone_low":   "#6b7280",
    "target_civ":  "#60a5fa",
    "target_veh":  "#fb923c",
    "target_anom": "#f43f5e",
    "scan_ring":   "#00d4ff",
    "trail":       "#1e3a5f",
    "text_primary":"#e2e8f0",
    "text_dim":    "#64748b",
    "border":      "#1e293b",
    "alert_low":   "#00ff88",
    "alert_med":   "#ffcc00",
    "alert_hi":    "#ff4444",
    "hud_green":   "#00ff88",
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Vector2D:
    x: float = 0.0
    y: float = 0.0

    def distance_to(self, other: 'Vector2D') -> float:
        return math.hypot(self.x - other.x, self.y - other.y)

    def angle_to(self, other: 'Vector2D') -> float:
        return math.atan2(other.y - self.y, other.x - self.x)

    def normalize(self) -> 'Vector2D':
        mag = math.hypot(self.x, self.y)
        if mag == 0:
            return Vector2D(0, 0)
        return Vector2D(self.x / mag, self.y / mag)


@dataclass
class Target:
    id: int
    position: Vector2D
    velocity: Vector2D
    target_type: TargetType
    trail: deque = field(default_factory=lambda: deque(maxlen=30))
    detected: bool = False
    tracked_by: Optional[int] = None
    threat_level: float = 0.0
    waypoints: List[Vector2D] = field(default_factory=list)
    wp_index: int = 0

    def __post_init__(self):
        self._gen_waypoints()

    def _gen_waypoints(self):
        count = random.randint(4, 8)
        self.waypoints = [
            Vector2D(random.uniform(50, CANVAS_W - 50),
                     random.uniform(50, CANVAS_H - 50))
            for _ in range(count)
        ]
        self.wp_index = 0

    def update(self):
        self.trail.append((self.position.x, self.position.y))
        if self.waypoints:
            wp = self.waypoints[self.wp_index % len(self.waypoints)]
            dist = self.position.distance_to(wp)
            if dist < 8:
                self.wp_index = (self.wp_index + 1) % len(self.waypoints)
            else:
                angle = self.position.angle_to(wp)
                spd = TARGET_SPEED * (1.3 if self.target_type == TargetType.VEHICLE else 1.0)
                self.velocity.x = math.cos(angle) * spd
                self.velocity.y = math.sin(angle) * spd
        self.position.x = max(10, min(CANVAS_W - 10, self.position.x + self.velocity.x))
        self.position.y = max(10, min(CANVAS_H - 10, self.position.y + self.velocity.y))


@dataclass
class Drone:
    id: int
    position: Vector2D
    state: DroneState = DroneState.IDLE
    battery: float = 100.0
    target: Optional[Target] = None
    patrol_points: List[Vector2D] = field(default_factory=list)
    patrol_index: int = 0
    trail: deque = field(default_factory=lambda: deque(maxlen=20))
    scan_angle: float = 0.0
    detection_events: int = 0
    uptime: float = 0.0
    home: Vector2D = field(default_factory=lambda: Vector2D(CANVAS_W // 2, CANVAS_H // 2))

    def __post_init__(self):
        self._gen_patrol()

    def _gen_patrol(self):
        cx, cy = self.position.x, self.position.y
        r = random.uniform(80, 180)
        pts = random.randint(4, 7)
        self.patrol_points = [
            Vector2D(cx + r * math.cos(2 * math.pi * i / pts + random.uniform(-0.3, 0.3)),
                     cy + r * math.sin(2 * math.pi * i / pts + random.uniform(-0.3, 0.3)))
            for i in range(pts)
        ]

    def update(self, targets: List[Target], tick: int):
        self.uptime += 1 / 30
        self.battery = max(0, self.battery - 0.015)
        self.scan_angle = (self.scan_angle + 4) % 360
        self.trail.append((self.position.x, self.position.y))

        if self.battery < 15:
            self.state = DroneState.LOW_BATTERY
            self._move_toward(self.home, PATROL_SPEED)
            return

        # AI decision making
        if self.state in (DroneState.IDLE, DroneState.PATROLLING):
            detected = self._scan_targets(targets)
            if detected:
                self.target = detected
                detected.tracked_by = self.id
                detected.detected = True
                self.state = DroneState.DETECTING
                self.detection_events += 1
            else:
                self.state = DroneState.PATROLLING
                self._patrol()

        elif self.state == DroneState.DETECTING:
            if self.target and self.position.distance_to(self.target.position) < DETECTION_RANGE:
                self.state = DroneState.TRACKING
            else:
                self.state = DroneState.PATROLLING
                self.target = None

        elif self.state == DroneState.TRACKING:
            if self.target:
                dist = self.position.distance_to(self.target.position)
                if dist < FOLLOW_DISTANCE * 1.5:
                    self.state = DroneState.FOLLOWING
                elif dist < DETECTION_RANGE:
                    self._move_toward(self.target.position, FOLLOW_SPEED * 0.8)
                else:
                    self.state = DroneState.PATROLLING
                    self.target.tracked_by = None
                    self.target = None
            else:
                self.state = DroneState.PATROLLING

        elif self.state == DroneState.FOLLOWING:
            if self.target:
                dist = self.position.distance_to(self.target.position)
                if dist > DETECTION_RANGE * 1.2:
                    self.state = DroneState.PATROLLING
                    self.target.tracked_by = None
                    self.target = None
                else:
                    # A* simplified: move to offset position behind target
                    offset_angle = self.target.position.angle_to(self.position)
                    fx = self.target.position.x + math.cos(offset_angle) * FOLLOW_DISTANCE
                    fy = self.target.position.y + math.sin(offset_angle) * FOLLOW_DISTANCE
                    self._move_toward(Vector2D(fx, fy), FOLLOW_SPEED)
            else:
                self.state = DroneState.PATROLLING

    def _scan_targets(self, targets: List[Target]) -> Optional[Target]:
        """Computer vision simulation - closest untracked target in range."""
        best, best_dist = None, DETECTION_RANGE
        for t in targets:
            if t.tracked_by is not None and t.tracked_by != self.id:
                continue
            d = self.position.distance_to(t.position)
            if d < best_dist:
                best_dist = d
                best = t
        return best

    def _move_toward(self, dest: Vector2D, speed: float):
        d = self.position.distance_to(dest)
        if d < 2:
            return
        angle = self.position.angle_to(dest)
        self.position.x += math.cos(angle) * min(speed, d)
        self.position.y += math.sin(angle) * min(speed, d)
        self.position.x = max(10, min(CANVAS_W - 10, self.position.x))
        self.position.y = max(10, min(CANVAS_H - 10, self.position.y))

    def _patrol(self):
        if not self.patrol_points:
            return
        wp = self.patrol_points[self.patrol_index % len(self.patrol_points)]
        if self.position.distance_to(wp) < 10:
            self.patrol_index = (self.patrol_index + 1) % len(self.patrol_points)
        self._move_toward(wp, PATROL_SPEED)


# ─────────────────────────────────────────────────────────────────────────────
# SIMULATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class SimulationEngine:
    def __init__(self):
        self.drones: List[Drone] = []
        self.targets: List[Target] = []
        self.tick: int = 0
        self.running: bool = False
        self.alerts: deque = deque(maxlen=20)
        self.stats = {
            "total_detections": 0,
            "active_tracks": 0,
            "elapsed": 0.0,
        }
        self.lock = threading.Lock()

    def init_drones(self, count: int = 4):
        self.drones.clear()
        positions = [
            (CANVAS_W * 0.25, CANVAS_H * 0.25),
            (CANVAS_W * 0.75, CANVAS_H * 0.25),
            (CANVAS_W * 0.25, CANVAS_H * 0.75),
            (CANVAS_W * 0.75, CANVAS_H * 0.75),
            (CANVAS_W * 0.50, CANVAS_H * 0.50),
            (CANVAS_W * 0.10, CANVAS_H * 0.50),
        ]
        for i in range(min(count, len(positions))):
            px, py = positions[i]
            d = Drone(id=i, position=Vector2D(px, py),
                      home=Vector2D(px, py),
                      battery=random.uniform(80, 100))
            self.drones.append(d)

    def init_targets(self, count: int = 6):
        self.targets.clear()
        types = [TargetType.CIVILIAN, TargetType.VEHICLE, TargetType.ANOMALY]
        for i in range(count):
            t = Target(
                id=i,
                position=Vector2D(random.uniform(60, CANVAS_W - 60),
                                  random.uniform(60, CANVAS_H - 60)),
                velocity=Vector2D(0, 0),
                target_type=random.choice(types),
                threat_level=random.uniform(0.1, 0.9),
            )
            self.targets.append(t)

    def step(self):
        with self.lock:
            self.tick += 1
            self.stats["elapsed"] += 1 / 30
            for t in self.targets:
                t.update()
            prev_tracks = sum(1 for t in self.targets if t.tracked_by is not None)
            for d in self.drones:
                prev_state = d.state
                d.update(self.targets, self.tick)
                if prev_state != DroneState.DETECTING and d.state == DroneState.DETECTING:
                    self.stats["total_detections"] += 1
                    ttype = d.target.target_type.value if d.target else "unknown"
                    level = "HIGH" if d.target and d.target.threat_level > 0.6 else "MEDIUM" if d.target and d.target.threat_level > 0.3 else "LOW"
                    self.alerts.appendleft({
                        "time": self.stats["elapsed"],
                        "msg": f"Drone-{d.id} detected {ttype}",
                        "level": level,
                    })
            self.stats["active_tracks"] = sum(1 for t in self.targets if t.tracked_by is not None)


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM UI WIDGETS
# ─────────────────────────────────────────────────────────────────────────────

class GlowButton(tk.Canvas):
    def __init__(self, parent, text, command=None, width=140, height=36,
                 color="#00d4ff", **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=COLORS["bg_panel"], highlightthickness=0, **kwargs)
        self.command = command
        self.color = color
        self.text = text
        self.w, self.h = width, height
        self._draw(False)
        self.bind("<Enter>", lambda e: self._draw(True))
        self.bind("<Leave>", lambda e: self._draw(False))
        self.bind("<Button-1>", self._click)

    def _draw(self, hover):
        self.delete("all")
        alpha_col = self.color if hover else "#1e3a5f"
        # Border rect
        self.create_rectangle(1, 1, self.w - 1, self.h - 1,
                               outline=self.color if hover else "#2d4a6f",
                               fill=alpha_col if hover else "#0d1e35",
                               width=1)
        # Corner accents
        for cx, cy, ex, ey in [(1,1,8,1),(1,1,1,8),
                                (self.w-8,1,self.w-1,1),(self.w-1,1,self.w-1,8),
                                (1,self.h-8,1,self.h-1),(1,self.h-1,8,self.h-1),
                                (self.w-8,self.h-1,self.w-1,self.h-1),(self.w-1,self.h-8,self.w-1,self.h-1)]:
            self.create_line(cx, cy, ex, ey, fill=self.color, width=2)
        self.create_text(self.w // 2, self.h // 2, text=self.text,
                         fill="#ffffff" if hover else COLORS["text_primary"],
                         font=("Courier", 9, "bold"))

    def _click(self, e):
        if self.command:
            self.command()


class StatCard(tk.Frame):
    def __init__(self, parent, label, value="0", unit="", color="#00d4ff", **kwargs):
        super().__init__(parent, bg=COLORS["bg_card"],
                         highlightbackground=COLORS["border"],
                         highlightthickness=1, **kwargs)
        self.color = color
        tk.Label(self, text=label, bg=COLORS["bg_card"],
                 fg=COLORS["text_dim"], font=("Courier", 7)).pack(anchor="w", padx=8, pady=(6, 0))
        self.val_label = tk.Label(self, text=value, bg=COLORS["bg_card"],
                                   fg=color, font=("Courier", 18, "bold"))
        self.val_label.pack(anchor="w", padx=8)
        if unit:
            tk.Label(self, text=unit, bg=COLORS["bg_card"],
                     fg=COLORS["text_dim"], font=("Courier", 7)).pack(anchor="w", padx=8, pady=(0, 6))

    def update_value(self, val):
        self.val_label.config(text=str(val))


class BatteryBar(tk.Canvas):
    def __init__(self, parent, width=100, height=14, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=COLORS["bg_card"], highlightthickness=0, **kwargs)
        self.w, self.h = width, height
        self.draw(100)

    def draw(self, pct):
        self.delete("all")
        self.create_rectangle(0, 0, self.w, self.h,
                               fill="#1a2540", outline="#2d4a6f")
        color = "#4ade80" if pct > 50 else "#f59e0b" if pct > 20 else "#ef4444"
        fill_w = int((self.w - 2) * pct / 100)
        if fill_w > 0:
            self.create_rectangle(1, 1, fill_w, self.h - 1, fill=color, outline="")
        self.create_text(self.w // 2, self.h // 2, text=f"{pct:.0f}%",
                         fill="white", font=("Courier", 7, "bold"))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

class DroneSimApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DRONE SURVEILLANCE SYSTEM  ◈  v2.0")
        self.configure(bg=COLORS["bg_dark"])
        self.resizable(False, False)

        self.engine = SimulationEngine()
        self.sim_thread: Optional[threading.Thread] = None
        self._running = False
        self._paused = False
        self.selected_drone: Optional[int] = None

        self._drone_count = tk.IntVar(value=4)
        self._target_count = tk.IntVar(value=6)
        self._speed_mult = tk.DoubleVar(value=1.0)

        self._build_ui()
        self._draw_static_grid()
        self.engine.init_drones(4)
        self.engine.init_targets(6)
        self._render()

    # ── UI BUILD ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Top header
        header = tk.Frame(self, bg=COLORS["bg_dark"])
        header.pack(fill="x", padx=0, pady=0)
        self._build_header(header)

        # Main body
        body = tk.Frame(self, bg=COLORS["bg_dark"])
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Left panel
        left = tk.Frame(body, bg=COLORS["bg_dark"], width=200)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        self._build_left_panel(left)

        # Canvas
        canvas_frame = tk.Frame(body, bg=COLORS["border"],
                                 highlightthickness=1,
                                 highlightbackground=COLORS["accent"])
        canvas_frame.pack(side="left", fill="both", expand=True)
        self.canvas = tk.Canvas(canvas_frame, width=CANVAS_W, height=CANVAS_H,
                                 bg=COLORS["bg_dark"], highlightthickness=0)
        self.canvas.pack()
        self.canvas.bind("<Button-1>", self._on_canvas_click)

        # Right panel
        right = tk.Frame(body, bg=COLORS["bg_dark"], width=220)
        right.pack(side="left", fill="y", padx=(8, 0))
        right.pack_propagate(False)
        self._build_right_panel(right)

    def _build_header(self, parent):
        bar = tk.Frame(parent, bg="#080c18", height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # Logo / title
        title_f = tk.Frame(bar, bg="#080c18")
        title_f.pack(side="left", padx=16, pady=8)
        tk.Label(title_f, text="◈ DRONEWATCH", bg="#080c18",
                 fg=COLORS["accent"], font=("Courier", 14, "bold")).pack(side="left")
        tk.Label(title_f, text=" SURVEILLANCE SYSTEM", bg="#080c18",
                 fg=COLORS["text_dim"], font=("Courier", 9)).pack(side="left", pady=4)

        # Status indicators
        status_f = tk.Frame(bar, bg="#080c18")
        status_f.pack(side="left", padx=20)
        self.sys_status_dot = tk.Canvas(status_f, width=10, height=10,
                                         bg="#080c18", highlightthickness=0)
        self.sys_status_dot.pack(side="left", padx=(0, 4))
        self.sys_status_dot.create_oval(1, 1, 9, 9, fill="#4ade80", outline="")
        self.sys_status_lbl = tk.Label(status_f, text="SYSTEM OFFLINE",
                                        bg="#080c18", fg=COLORS["text_dim"],
                                        font=("Courier", 8))
        self.sys_status_lbl.pack(side="left")

        # Clock
        self.clock_lbl = tk.Label(bar, text="T+00:00:00", bg="#080c18",
                                   fg=COLORS["accent2"], font=("Courier", 11, "bold"))
        self.clock_lbl.pack(side="right", padx=16)

        # Controls
        ctrl = tk.Frame(bar, bg="#080c18")
        ctrl.pack(side="right", padx=8)
        self.btn_start = GlowButton(ctrl, "▶  START", self._start_sim,
                                     color=COLORS["hud_green"])
        self.btn_start.pack(side="left", padx=4)
        self.btn_pause = GlowButton(ctrl, "⏸  PAUSE", self._pause_sim,
                                     color=COLORS["accent"])
        self.btn_pause.pack(side="left", padx=4)
        GlowButton(ctrl, "⏹  RESET", self._reset_sim,
                   color="#ef4444").pack(side="left", padx=4)

    def _build_left_panel(self, parent):
        # Stats
        tk.Label(parent, text="SYSTEM METRICS", bg=COLORS["bg_dark"],
                 fg=COLORS["text_dim"], font=("Courier", 8)).pack(anchor="w", pady=(8, 4))

        self.stat_detections = StatCard(parent, "TOTAL DETECTIONS", "0",
                                         color=COLORS["accent"])
        self.stat_detections.pack(fill="x", pady=2)

        self.stat_tracks = StatCard(parent, "ACTIVE TRACKS", "0",
                                    color=COLORS["alert_med"])
        self.stat_tracks.pack(fill="x", pady=2)

        self.stat_drones = StatCard(parent, "DRONES ACTIVE", "0",
                                    color=COLORS["hud_green"])
        self.stat_drones.pack(fill="x", pady=2)

        # Config
        tk.Label(parent, text="CONFIGURATION", bg=COLORS["bg_dark"],
                 fg=COLORS["text_dim"], font=("Courier", 8)).pack(anchor="w", pady=(16, 4))

        cfg = tk.Frame(parent, bg=COLORS["bg_card"],
                       highlightbackground=COLORS["border"], highlightthickness=1)
        cfg.pack(fill="x", pady=2)

        tk.Label(cfg, text="DRONES", bg=COLORS["bg_card"],
                 fg=COLORS["text_dim"], font=("Courier", 7)).pack(anchor="w", padx=8, pady=(6, 0))
        drone_spin = tk.Spinbox(cfg, from_=1, to=6, textvariable=self._drone_count,
                                 width=5, bg=COLORS["bg_dark"], fg=COLORS["accent"],
                                 font=("Courier", 10, "bold"),
                                 buttonbackground=COLORS["bg_card"],
                                 highlightthickness=0, bd=0)
        drone_spin.pack(padx=8, pady=4)

        tk.Label(cfg, text="TARGETS", bg=COLORS["bg_card"],
                 fg=COLORS["text_dim"], font=("Courier", 7)).pack(anchor="w", padx=8)
        target_spin = tk.Spinbox(cfg, from_=1, to=15, textvariable=self._target_count,
                                  width=5, bg=COLORS["bg_dark"], fg=COLORS["target_veh"],
                                  font=("Courier", 10, "bold"),
                                  buttonbackground=COLORS["bg_card"],
                                  highlightthickness=0, bd=0)
        target_spin.pack(padx=8, pady=(4, 8))

        tk.Label(parent, text="SIM SPEED", bg=COLORS["bg_dark"],
                 fg=COLORS["text_dim"], font=("Courier", 7)).pack(anchor="w", pady=(8, 2))
        speed_scale = tk.Scale(parent, variable=self._speed_mult,
                                from_=0.5, to=4.0, resolution=0.5,
                                orient="horizontal", length=180,
                                bg=COLORS["bg_dark"], fg=COLORS["text_primary"],
                                troughcolor=COLORS["bg_card"],
                                highlightthickness=0, bd=0,
                                activebackground=COLORS["accent"],
                                font=("Courier", 7))
        speed_scale.pack()

        # Legend
        tk.Label(parent, text="LEGEND", bg=COLORS["bg_dark"],
                 fg=COLORS["text_dim"], font=("Courier", 8)).pack(anchor="w", pady=(16, 4))

        legend_data = [
            ("◆ DRONE – PATROL", COLORS["drone_idle"]),
            ("◆ DRONE – TRACKING", COLORS["drone_track"]),
            ("◆ DRONE – FOLLOWING", COLORS["drone_follow"]),
            ("◆ DRONE – LOW BAT", COLORS["drone_low"]),
            ("● CIVILIAN TARGET", COLORS["target_civ"]),
            ("● VEHICLE TARGET", COLORS["target_veh"]),
            ("● ANOMALY TARGET", COLORS["target_anom"]),
        ]
        for txt, col in legend_data:
            tk.Label(parent, text=txt, bg=COLORS["bg_dark"],
                     fg=col, font=("Courier", 8), anchor="w").pack(fill="x", pady=1)

    def _build_right_panel(self, parent):
        # Drone status cards
        tk.Label(parent, text="DRONE STATUS", bg=COLORS["bg_dark"],
                 fg=COLORS["text_dim"], font=("Courier", 8)).pack(anchor="w", pady=(8, 4))

        self.drone_cards: Dict[int, Dict] = {}
        self.drone_card_frame = tk.Frame(parent, bg=COLORS["bg_dark"])
        self.drone_card_frame.pack(fill="x")

        # Alert log
        tk.Label(parent, text="ALERT LOG", bg=COLORS["bg_dark"],
                 fg=COLORS["text_dim"], font=("Courier", 8)).pack(anchor="w", pady=(12, 4))

        log_frame = tk.Frame(parent, bg=COLORS["bg_card"],
                              highlightbackground=COLORS["border"], highlightthickness=1)
        log_frame.pack(fill="both", expand=True, pady=2)

        self.alert_listbox = tk.Listbox(log_frame, bg=COLORS["bg_card"],
                                         fg=COLORS["text_primary"],
                                         font=("Courier", 7),
                                         selectbackground=COLORS["bg_card"],
                                         highlightthickness=0, bd=0,
                                         activestyle="none")
        self.alert_listbox.pack(fill="both", expand=True, padx=4, pady=4)

    def _rebuild_drone_cards(self):
        for w in self.drone_card_frame.winfo_children():
            w.destroy()
        self.drone_cards.clear()

        for d in self.engine.drones:
            card = tk.Frame(self.drone_card_frame, bg=COLORS["bg_card"],
                             highlightbackground=COLORS["border"], highlightthickness=1)
            card.pack(fill="x", pady=2)

            top = tk.Frame(card, bg=COLORS["bg_card"])
            top.pack(fill="x", padx=6, pady=(4, 0))

            state_col = self._drone_color(d)
            id_lbl = tk.Label(top, text=f"DRONE-{d.id}", bg=COLORS["bg_card"],
                               fg=state_col, font=("Courier", 8, "bold"))
            id_lbl.pack(side="left")
            state_lbl = tk.Label(top, text=d.state.value, bg=COLORS["bg_card"],
                                  fg=state_col, font=("Courier", 7))
            state_lbl.pack(side="right")

            bat = BatteryBar(card, width=192)
            bat.pack(padx=6, pady=(2, 4))

            self.drone_cards[d.id] = {"state": state_lbl, "bat": bat, "id_lbl": id_lbl}

    def _drone_color(self, d: Drone) -> str:
        if d.state == DroneState.LOW_BATTERY:
            return COLORS["drone_low"]
        if d.state == DroneState.FOLLOWING:
            return COLORS["drone_follow"]
        if d.state in (DroneState.TRACKING, DroneState.DETECTING):
            return COLORS["drone_track"]
        return COLORS["drone_idle"]

    # ── CANVAS DRAWING ────────────────────────────────────────────────────────

    def _draw_static_grid(self):
        self.canvas.delete("grid")
        step = 50
        for x in range(0, CANVAS_W, step):
            self.canvas.create_line(x, 0, x, CANVAS_H,
                                     fill=COLORS["grid"], width=1, tags="grid")
        for y in range(0, CANVAS_H, step):
            self.canvas.create_line(0, y, CANVAS_W, y,
                                     fill=COLORS["grid"], width=1, tags="grid")
        # Crosshair center
        cx, cy = CANVAS_W // 2, CANVAS_H // 2
        for dx, dy in [(-20, 0), (20, 0), (0, -20), (0, 20)]:
            self.canvas.create_line(cx, cy, cx + dx, cy + dy,
                                     fill=COLORS["accent"], width=1, tags="grid")

    def _render(self):
        self.canvas.delete("dynamic")

        with self.engine.lock:
            drones  = list(self.engine.drones)
            targets = list(self.engine.targets)
            alerts  = list(self.engine.alerts)
            stats   = dict(self.engine.stats)

        # Draw target trails
        for t in targets:
            trail = list(t.trail)
            if len(trail) > 1:
                for i in range(1, len(trail)):
                    alpha = i / len(trail)
                    col = self._fade_color(COLORS["trail"], alpha * 0.6)
                    self.canvas.create_line(
                        trail[i-1][0], trail[i-1][1],
                        trail[i][0],   trail[i][1],
                        fill=col, width=1, tags="dynamic"
                    )

        # Draw drone scan rings
        for d in drones:
            px, py = d.position.x, d.position.y
            col = self._drone_color(d)
            # Detection radius
            self.canvas.create_oval(
                px - DETECTION_RANGE, py - DETECTION_RANGE,
                px + DETECTION_RANGE, py + DETECTION_RANGE,
                outline=col, width=1, dash=(4, 8),
                fill="", tags="dynamic"
            )
            # Rotating scan line
            angle_rad = math.radians(d.scan_angle)
            sx = px + math.cos(angle_rad) * DETECTION_RANGE
            sy = py + math.sin(angle_rad) * DETECTION_RANGE
            self.canvas.create_line(px, py, sx, sy,
                                     fill=col, width=1,
                                     tags="dynamic")

        # Draw drone trails
        for d in drones:
            trail = list(d.trail)
            if len(trail) > 1:
                for i in range(1, len(trail)):
                    alpha = i / len(trail)
                    self.canvas.create_line(
                        trail[i-1][0], trail[i-1][1],
                        trail[i][0],   trail[i][1],
                        fill=self._fade_color(self._drone_color(d), alpha * 0.5),
                        width=1, tags="dynamic"
                    )

        # Draw targets
        for t in targets:
            px, py = t.position.x, t.position.y
            col = {
                TargetType.CIVILIAN: COLORS["target_civ"],
                TargetType.VEHICLE:  COLORS["target_veh"],
                TargetType.ANOMALY:  COLORS["target_anom"],
            }[t.target_type]

            if t.detected:
                # Pulsing detection ring
                pulse_r = TARGET_RADIUS + 8 + 4 * math.sin(time.time() * 6)
                self.canvas.create_oval(
                    px - pulse_r, py - pulse_r, px + pulse_r, py + pulse_r,
                    outline=col, width=2, tags="dynamic"
                )

            self.canvas.create_oval(
                px - TARGET_RADIUS, py - TARGET_RADIUS,
                px + TARGET_RADIUS, py + TARGET_RADIUS,
                fill=col, outline="#ffffff", width=1, tags="dynamic"
            )
            # Type icon
            icon = {"civilian": "👤", "vehicle": "🚗", "anomaly": "⚠"}[t.target_type.value]
            self.canvas.create_text(px, py - TARGET_RADIUS - 10,
                                     text=icon, font=("", 8), tags="dynamic")

        # Draw drones
        for d in drones:
            px, py = d.position.x, d.position.y
            col = self._drone_color(d)

            # Drone body (diamond shape)
            size = DRONE_RADIUS
            pts = [px, py - size, px + size, py, px, py + size, px - size, py]
            self.canvas.create_polygon(pts, fill=col, outline="#ffffff",
                                        width=1, tags="dynamic")

            # Arms
            for ax, ay in [(-size * 0.7, -size * 0.7), (size * 0.7, -size * 0.7),
                           (-size * 0.7,  size * 0.7), (size * 0.7,  size * 0.7)]:
                self.canvas.create_oval(
                    px + ax - 3, py + ay - 3,
                    px + ax + 3, py + ay + 3,
                    fill="#334155", outline=col, width=1, tags="dynamic"
                )

            # Label
            self.canvas.create_text(px, py + DRONE_RADIUS + 10,
                                     text=f"D{d.id}",
                                     fill=col, font=("Courier", 7, "bold"),
                                     tags="dynamic")

            # Target link line
            if d.target:
                tx, ty = d.target.position.x, d.target.position.y
                self.canvas.create_line(px, py, tx, ty,
                                         fill=col, width=1, dash=(3, 5),
                                         tags="dynamic")

            # Home indicator (small dot)
            hx, hy = d.home.x, d.home.y
            self.canvas.create_oval(hx - 3, hy - 3, hx + 3, hy + 3,
                                     fill=col, outline="", tags="dynamic")

        # Update HUD overlay
        self._draw_hud(stats)

        # Update right panel
        self._update_drone_cards(drones)
        self._update_alerts(alerts)
        self._update_stats(stats)
        self._update_clock(stats["elapsed"])

        self.after(33, self._render)

    def _draw_hud(self, stats):
        self.canvas.delete("hud")
        # Top-left info
        self.canvas.create_text(12, 10, anchor="nw",
                                 text=f"TICK: {self.engine.tick:06d}",
                                 fill=COLORS["text_dim"], font=("Courier", 7),
                                 tags="hud")
        self.canvas.create_text(12, 22, anchor="nw",
                                 text=f"DETECTIONS: {stats['total_detections']}",
                                 fill=COLORS["accent"], font=("Courier", 7),
                                 tags="hud")
        self.canvas.create_text(12, 34, anchor="nw",
                                 text=f"ACTIVE TRACKS: {stats['active_tracks']}",
                                 fill=COLORS["alert_med"], font=("Courier", 7),
                                 tags="hud")

        status = "RUNNING" if self._running and not self._paused else "PAUSED" if self._paused else "STANDBY"
        col = COLORS["hud_green"] if status == "RUNNING" else COLORS["alert_med"] if status == "PAUSED" else COLORS["text_dim"]
        self.canvas.create_text(CANVAS_W - 8, 10, anchor="ne",
                                 text=f"● {status}",
                                 fill=col, font=("Courier", 8, "bold"),
                                 tags="hud")

    def _update_drone_cards(self, drones):
        for d in drones:
            if d.id in self.drone_cards:
                card = self.drone_cards[d.id]
                col = self._drone_color(d)
                card["state"].config(text=d.state.value, fg=col)
                card["id_lbl"].config(fg=col)
                card["bat"].draw(d.battery)

    def _update_alerts(self, alerts):
        self.alert_listbox.delete(0, "end")
        for a in alerts:
            t = a["time"]
            col_map = {"HIGH": COLORS["alert_hi"],
                       "MEDIUM": COLORS["alert_med"],
                       "LOW": COLORS["alert_low"]}
            self.alert_listbox.insert("end", f"[{t:06.1f}s] {a['level']} {a['msg']}")
            idx = self.alert_listbox.size() - 1
            self.alert_listbox.itemconfig(idx, fg=col_map.get(a["level"], "white"))

    def _update_stats(self, stats):
        self.stat_detections.update_value(stats["total_detections"])
        self.stat_tracks.update_value(stats["active_tracks"])
        active = sum(1 for d in self.engine.drones
                     if d.state not in (DroneState.IDLE, DroneState.LOW_BATTERY))
        self.stat_drones.update_value(active)

    def _update_clock(self, elapsed):
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)
        self.clock_lbl.config(text=f"T+{h:02d}:{m:02d}:{s:02d}")

    # ── SIMULATION CONTROL ───────────────────────────────────────────────────

    def _start_sim(self):
        if self._running and not self._paused:
            return
        if self._paused:
            self._paused = False
            self.sys_status_lbl.config(text="SYSTEM ACTIVE", fg=COLORS["hud_green"])
            self.sys_status_dot.delete("all")
            self.sys_status_dot.create_oval(1, 1, 9, 9, fill=COLORS["hud_green"], outline="")
            return

        self._running = True
        self._paused  = False
        self.engine.init_drones(self._drone_count.get())
        self.engine.init_targets(self._target_count.get())
        self._rebuild_drone_cards()
        self.sys_status_lbl.config(text="SYSTEM ACTIVE", fg=COLORS["hud_green"])
        self.sys_status_dot.delete("all")
        self.sys_status_dot.create_oval(1, 1, 9, 9, fill=COLORS["hud_green"], outline="")

        self.sim_thread = threading.Thread(target=self._sim_loop, daemon=True)
        self.sim_thread.start()

    def _pause_sim(self):
        if not self._running:
            return
        self._paused = not self._paused
        if self._paused:
            self.sys_status_lbl.config(text="SYSTEM PAUSED", fg=COLORS["alert_med"])
            self.sys_status_dot.delete("all")
            self.sys_status_dot.create_oval(1, 1, 9, 9, fill=COLORS["alert_med"], outline="")
        else:
            self.sys_status_lbl.config(text="SYSTEM ACTIVE", fg=COLORS["hud_green"])
            self.sys_status_dot.delete("all")
            self.sys_status_dot.create_oval(1, 1, 9, 9, fill=COLORS["hud_green"], outline="")

    def _reset_sim(self):
        self._running = False
        self._paused  = False
        time.sleep(0.05)
        self.engine = SimulationEngine()
        self.engine.init_drones(self._drone_count.get())
        self.engine.init_targets(self._target_count.get())
        self._rebuild_drone_cards()
        self.sys_status_lbl.config(text="SYSTEM OFFLINE", fg=COLORS["text_dim"])
        self.sys_status_dot.delete("all")
        self.sys_status_dot.create_oval(1, 1, 9, 9, fill=COLORS["text_dim"], outline="")

    def _sim_loop(self):
        target_dt = 1 / 30
        while self._running:
            if not self._paused:
                mult = self._speed_mult.get()
                steps = max(1, int(mult))
                for _ in range(steps):
                    self.engine.step()
            time.sleep(target_dt)

    def _on_canvas_click(self, event):
        cx, cy = event.x, event.y
        with self.engine.lock:
            for d in self.engine.drones:
                if math.hypot(cx - d.position.x, cy - d.position.y) < DRONE_RADIUS + 5:
                    self.selected_drone = d.id
                    return

    # ── HELPERS ───────────────────────────────────────────────────────────────

    @staticmethod
    def _fade_color(hex_color: str, alpha: float) -> str:
        hex_color = hex_color.lstrip("#")
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        br = int(r * alpha)
        bg = int(g * alpha)
        bb = int(b * alpha)
        return f"#{br:02x}{bg:02x}{bb:02x}"


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = DroneSimApp()
    app.mainloop()
