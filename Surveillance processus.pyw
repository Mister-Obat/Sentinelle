import json
import os
import base64
import ctypes
import hashlib
import subprocess
import sys
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import messagebox, ttk
from pathlib import Path

try:
    import psutil
    import pystray
    from PIL import Image
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Dépendance manquante",
        "Des composants nécessaires sont manquants. Ouvrez un terminal dans le dossier de l'outil et lancez :\n\npy -m pip install -r requirements.txt",
    )
    raise SystemExit(1)


APP_TITLE = "Sentinelle"
APP_DIR = Path(__file__).resolve().parent
APP_ICON = APP_DIR / "Sentinelle.ico"
TRAY_IMAGE = APP_DIR / "Sentinelle.png"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SurveillanceProcessus"
POLICY_FILE = DATA_DIR / "blocked.json"
FIREWALL_FILE = DATA_DIR / "firewall_blocked.json"
HISTORY_FILE = DATA_DIR / "process_history.json"
STARTUP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "Microsoft/Windows/Start Menu/Programs/Startup"
STARTUP_VBS = STARTUP_DIR / "SurveillanceProcessus.vbs"
SCAN_INTERVAL_MS = 900
DISPLAY_INTERVAL_MS = 15_000
WINDOWS_APP_ID = "obat.sentinelle.v1"
DONATION_URL = "https://www.paypal.com/paypalme/creaprisme"
NEVER_BLOCK = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe"}


def path_key(path):
    return os.path.normcase(os.path.abspath(path))


def process_label(proc, exe):
    try:
        name = proc.info.get("name") or Path(exe).name
    except Exception:
        name = Path(exe).name
    return name


class ProcessGuard:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        if APP_ICON.exists():
            try:
                self.root.iconbitmap(str(APP_ICON))
            except tk.TclError:
                pass
        self.root.geometry("1050x620")
        self.root.minsize(780, 440)
        self.root.configure(bg="#15171b")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.blocked = self.load_policy()
        self.network_blocked = self.load_path_set(FIREWALL_FILE)
        self.history = self.load_history()
        self.rows = {}
        self.processes = list(self.history.values())
        self.sort_column = "started"
        self.sort_reverse = True
        self.last_stopped = 0
        self.scan_job = None
        self.display_job = None
        self.last_history_save = 0
        self.build_ui()
        self.set_windows_window_icon()
        self.apply_dark_title_bar()
        self.create_tray_icon()
        self.scan_processes()
        self.render_processes()
        self.scan_job = self.root.after(SCAN_INTERVAL_MS, self.scan_tick)
        self.display_job = self.root.after(DISPLAY_INTERVAL_MS, self.display_tick)

    def load_policy(self):
        try:
            raw = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            return {path_key(p) for p in raw if isinstance(p, str) and p}
        except (OSError, ValueError, TypeError):
            return set()

    def save_policy(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temp_file = POLICY_FILE.with_suffix(".tmp")
        temp_file.write_text(json.dumps(sorted(self.blocked), ensure_ascii=False, indent=2), encoding="utf-8")
        temp_file.replace(POLICY_FILE)

    def load_path_set(self, file_path):
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
            return {path_key(p) for p in raw if isinstance(p, str) and p}
        except (OSError, ValueError, TypeError):
            return set()

    def save_network_policy(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temp_file = FIREWALL_FILE.with_suffix(".tmp")
        temp_file.write_text(json.dumps(sorted(self.network_blocked), ensure_ascii=False, indent=2), encoding="utf-8")
        temp_file.replace(FIREWALL_FILE)

    def load_history(self):
        history = {}
        try:
            raw_entries = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return history
        if not isinstance(raw_entries, list):
            return history
        for entry in raw_entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("exe"), str):
                continue
            exe = entry["exe"]
            key = path_key(exe)
            started = entry.get("started", 0)
            first_seen = entry.get("first_seen", 0)
            last_seen = entry.get("last_seen", 0)
            history[key] = {
                "key": key,
                "exe": exe,
                "name": entry.get("name") if isinstance(entry.get("name"), str) else Path(exe).name,
                "pid": None,
                "started": float(started) if isinstance(started, (int, float)) else 0,
                "first_seen": float(first_seen) if isinstance(first_seen, (int, float)) else 0,
                "last_seen": float(last_seen) if isinstance(last_seen, (int, float)) else 0,
                "active": False,
            }
        return history

    def save_history(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temp_file = HISTORY_FILE.with_suffix(".tmp")
        entries = [
            {key: item[key] for key in ("exe", "name", "started", "first_seen", "last_seen")}
            for item in self.history.values()
        ]
        temp_file.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
        temp_file.replace(HISTORY_FILE)
        self.last_history_save = time.time()

    def apply_firewall_rules(self, exe, block):
        """Add or remove persistent Windows Firewall rules for both directions."""
        normalized = path_key(exe)
        digest = hashlib.sha256(normalized.casefold().encode("utf-8")).hexdigest()[:20]
        action = "add" if block else "remove"
        path_encoded = base64.b64encode(normalized.encode("utf-8")).decode("ascii")
        ps_script = f'''$ErrorActionPreference = 'Stop'
$exe = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{path_encoded}'))
$base = 'MiniBloqueur-{digest}'
$names = @("$base-Inbound", "$base-Outbound")
try {{
    if ('{action}' -eq 'add') {{
        $disabled = @(Get-NetFirewallProfile | Where-Object {{ -not $_.Enabled }})
        if ($disabled.Count -gt 0) {{ throw 'Le Pare-feu Windows est désactivé sur au moins un profil.' }}
        Get-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        New-NetFirewallRule -DisplayName $names[0] -Direction Inbound -Action Block -Program $exe -Profile Any -Enabled True -ErrorAction Stop | Out-Null
        New-NetFirewallRule -DisplayName $names[1] -Direction Outbound -Action Block -Program $exe -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    }} else {{
        Get-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
    }}
    exit 0
}} catch {{
    if ('{action}' -eq 'add') {{ Get-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue }}
    exit 1
}}
'''
        encoded_script = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        parent_script = (
            "$argsForChild = @('-NoProfile','-WindowStyle','Hidden','-EncodedCommand','" + encoded_script + "'); "
            "$child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $argsForChild; "
            "exit $child.ExitCode"
        )
        powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-WindowStyle", "Hidden", "-Command", parent_script],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), capture_output=True, text=True, timeout=120, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Règle pare-feu non appliquée. Vérifie la confirmation UAC et l'état du Pare-feu Windows.")

    def build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        bg = "#15171b"
        surface = "#202329"
        elevated = "#2b3038"
        foreground = "#eeeeee"
        muted = "#b7bdc7"
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=foreground)
        style.configure("Treeview", background=surface, foreground=foreground, fieldbackground=surface, rowheight=28, borderwidth=0, bordercolor=surface, lightcolor=surface, darkcolor=surface)
        style.configure("Treeview.Heading", background=elevated, foreground=foreground, font=("Segoe UI", 9, "bold"), bordercolor=bg, lightcolor=elevated, darkcolor=elevated, relief="flat")
        style.map("Treeview", background=[("selected", "#1769aa")], foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", "#363d47")])
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 7), background=elevated, foreground=foreground, bordercolor=bg, lightcolor=elevated, darkcolor=elevated, relief="flat", focuscolor=bg)
        style.map("TButton", background=[("disabled", "#202329"), ("pressed", "#1769aa"), ("active", "#363d47")], foreground=[("disabled", "#737b86"), ("active", "#ffffff")], bordercolor=[("focus", "#4cc2ff")])
        style.configure("TCheckbutton", background=bg, foreground=muted, padding=(5, 4), indicatorbackground=surface, indicatorforeground=foreground)
        style.map("TCheckbutton", background=[("active", bg)], foreground=[("active", foreground)], indicatorbackground=[("selected", "#1769aa"), ("active", elevated)])
        style.configure("TEntry", fieldbackground=surface, foreground=foreground, insertcolor=foreground, bordercolor=surface, lightcolor=surface, darkcolor=surface, padding=6, relief="flat")
        style.map("TEntry", fieldbackground=[("disabled", elevated), ("focus", surface)], foreground=[("disabled", "#737b86")])
        style.configure("TCombobox", fieldbackground=surface, foreground=foreground, background=elevated, arrowcolor=foreground, bordercolor=bg, lightcolor=surface, darkcolor=surface, padding=5, relief="flat")
        style.map("TCombobox", fieldbackground=[("readonly", surface), ("disabled", elevated)], foreground=[("readonly", foreground), ("disabled", "#737b86")], selectbackground=[("readonly", surface)], selectforeground=[("readonly", foreground)], background=[("active", "#363d47")])
        self.root.option_add("*TCombobox*Listbox.background", surface)
        self.root.option_add("*TCombobox*Listbox.foreground", foreground)
        self.root.option_add("*TCombobox*Listbox.selectBackground", "#1769aa")
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        style.configure("Vertical.TScrollbar", background=elevated, troughcolor=bg, bordercolor=bg, arrowcolor=foreground, lightcolor=elevated, darkcolor=elevated, relief="flat", gripcount=0)
        style.configure("Horizontal.TScrollbar", background=elevated, troughcolor=bg, bordercolor=bg, arrowcolor=foreground, lightcolor=elevated, darkcolor=elevated, relief="flat", gripcount=0)
        style.map("Vertical.TScrollbar", background=[("active", "#454d58"), ("pressed", "#1769aa")])
        style.map("Horizontal.TScrollbar", background=[("active", "#454d58"), ("pressed", "#1769aa")])

        frame = tk.Frame(self.root, bg="#15171b", padx=18, pady=16)
        frame.pack(fill="both", expand=True)
        heading = tk.Frame(frame, bg="#15171b")
        heading.pack(fill="x")
        tk.Label(heading, text="Sentinelle", bg="#15171b", fg="#4cc2ff", font=("Segoe UI", 19, "bold")).pack(side="left", anchor="w")
        ttk.Button(heading, text="Faire un don ❤️", style="TButton", command=lambda: webbrowser.open(DONATION_URL), cursor="hand2").pack(side="right", padx=(12, 0))
        tk.Label(
            frame,
            text="Bloquer arrête les relances surveillées et demande à Windows de bloquer le réseau entrant et sortant de cet exécutable. Une confirmation UAC est requise pour le pare-feu.",
            bg="#15171b", fg="#b7bdc7", font=("Segoe UI", 9), wraplength=1000, justify="left",
        ).pack(anchor="w", pady=(4, 12))

        bar = tk.Frame(frame, bg="#15171b")
        bar.pack(fill="x", pady=(0, 10))
        self.action = ttk.Button(bar, text="Bloquer ce programme", command=self.toggle_selected)
        self.action.pack(side="left")
        self.firewall_action = ttk.Button(bar, text="Configurer le pare-feu", command=self.configure_firewall_selected)
        self.firewall_action.pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="Actualiser", command=self.refresh).pack(side="left", padx=8)
        self.startup_var = tk.BooleanVar(value=STARTUP_VBS.exists())
        ttk.Checkbutton(bar, text="Lancer avec Windows (sans terminal)", variable=self.startup_var, command=self.toggle_startup).pack(side="right")

        filters = tk.Frame(frame, bg="#15171b")
        filters.pack(fill="x", pady=(0, 8))
        tk.Label(filters, text="Afficher :", bg="#15171b", fg="#eeeeee", font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self.filter_var = tk.StringVar(value="Tous les programmes")
        filter_box = ttk.Combobox(filters, textvariable=self.filter_var, state="readonly", width=24, values=(
            "Tous les programmes", "Programmes bloqués", "Programmes autorisés",
        ))
        filter_box.pack(side="left")
        filter_box.bind("<<ComboboxSelected>>", lambda _event: self.render_processes())
        tk.Label(filters, text="Rechercher par nom :", bg="#15171b", fg="#eeeeee", font=("Segoe UI", 9)).pack(side="left", padx=(18, 6))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filters, textvariable=self.search_var, width=32)
        search_entry.pack(side="left", fill="x", expand=True)
        self.search_var.trace_add("write", lambda *_args: self.render_processes())

        table_frame = tk.Frame(frame, bg="#15171b")
        table_frame.pack(fill="both", expand=True)
        columns = ("state", "name", "pid", "started", "seen", "path")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.column_titles = {"state": "ÉTAT", "name": "PROGRAMME", "pid": "PID", "started": "DERNIER DÉMARRAGE", "seen": "DERNIÈRE DÉTECTION", "path": "EMPLACEMENT"}
        for key, title, width in (("state", "ÉTAT", 225), ("name", "PROGRAMME", 190), ("pid", "PID", 65), ("started", "DERNIER DÉMARRAGE", 145), ("seen", "DERNIÈRE DÉTECTION", 150), ("path", "EMPLACEMENT", 450)):
            self.table.heading(key, text=title, command=lambda column=key: self.sort_by(column))
            self.table.column(key, width=width, minwidth=65, stretch=(key == "path"), anchor="w")
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.table.bind("<<TreeviewSelect>>", self.update_action)
        self.table.bind("<Double-1>", lambda _event: self.toggle_selected())
        self.table.tag_configure("blocked", foreground="#ff9c88")

        self.status = tk.StringVar()
        tk.Label(frame, textvariable=self.status, bg="#15171b", fg="#9ca3ad", font=("Segoe UI", 9), anchor="w").pack(fill="x", pady=(9, 0))
        tk.Label(frame, text="Limite : l'arrêt de processus reste réactif, pas une interdiction de lancement à 100 %. Le pare-feu s'applique au chemin exact et seulement tant que le Pare-feu Windows est actif.", bg="#15171b", fg="#d1aa70", font=("Segoe UI", 8), anchor="w", wraplength=1000, justify="left").pack(fill="x", pady=(5, 0))

    def set_windows_window_icon(self):
        if os.name != "nt" or not APP_ICON.exists():
            return
        try:
            self.root.update_idletasks()
            get_parent = ctypes.windll.user32.GetParent
            get_parent.restype = ctypes.c_void_p
            get_parent.argtypes = [ctypes.c_void_p]
            hwnd = get_parent(ctypes.c_void_p(self.root.winfo_id()))
            send_message = ctypes.windll.user32.SendMessageW
            send_message.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
            load_image = ctypes.windll.user32.LoadImageW
            load_image.restype = ctypes.c_void_p
            load_image.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
            big_icon = load_image(None, str(APP_ICON), 1, 48, 48, 0x0010)
            small_icon = load_image(None, str(APP_ICON), 1, 16, 16, 0x0010)
            if big_icon:
                send_message(hwnd, 0x0080, ctypes.c_void_p(1), ctypes.c_void_p(big_icon))
                self._taskbar_icon_big = big_icon
            if small_icon:
                send_message(hwnd, 0x0080, ctypes.c_void_p(0), ctypes.c_void_p(small_icon))
                self._taskbar_icon_small = small_icon
        except (AttributeError, OSError, TypeError):
            pass

    def apply_dark_title_bar(self):
        if os.name != "nt":
            return
        try:
            self.root.update_idletasks()
            get_parent = ctypes.windll.user32.GetParent
            get_parent.restype = ctypes.c_void_p
            get_parent.argtypes = [ctypes.c_void_p]
            hwnd = get_parent(ctypes.c_void_p(self.root.winfo_id()))
            set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
            set_attribute.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
            set_attribute.restype = ctypes.c_long
            value = ctypes.c_int(1)
            result = set_attribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
            if result != 0:
                set_attribute(hwnd, 19, ctypes.byref(value), ctypes.sizeof(value))
            border_color = ctypes.c_uint(0x00292320)
            set_attribute(hwnd, 34, ctypes.byref(border_color), ctypes.sizeof(border_color))
        except (AttributeError, OSError, TypeError):
            pass

    def stop_blocked(self):
        stopped = 0
        survivors = set()
        terminated = set()
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            exe = None
            try:
                exe = proc.info.get("exe")
                name = (proc.info.get("name") or "").lower()
                if not exe or path_key(exe) not in self.blocked or self.is_protected(proc.info.get("pid"), name, exe):
                    continue
                proc.terminate()
                stopped += 1
                terminated.add(path_key(exe))
            except psutil.AccessDenied:
                if exe:
                    survivors.add(path_key(exe))
            except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                continue
        return stopped, survivors, terminated

    def refresh(self):
        if self.scan_job is not None:
            try:
                self.root.after_cancel(self.scan_job)
            except tk.TclError:
                pass
            self.scan_job = None
        self.scan_processes()
        self.render_processes()
        self.scan_job = self.root.after(SCAN_INTERVAL_MS, self.scan_tick)

    def scan_processes(self):
        now = time.time()
        history_changed = False
        for item in self.history.values():
            item["active"] = False
            item["pid"] = None

        for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            try:
                info = proc.info
                exe = info.get("exe")
                if not exe:
                    continue
                name = process_label(proc, exe)
                if self.is_protected(info.get("pid"), name.lower(), exe):
                    continue
                key = path_key(exe)
                started = info.get("create_time") or now
                is_new = key not in self.history
                item = self.history.setdefault(key, {
                    "key": key,
                    "exe": exe,
                    "name": name,
                    "pid": None,
                    "started": started,
                    "first_seen": now,
                    "last_seen": now,
                    "active": False,
                })
                if is_new:
                    history_changed = True
                item.update({"exe": exe, "name": name, "pid": info.get("pid"), "active": True, "last_seen": now})
                if started > item.get("started", 0):
                    item["started"] = started
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
        for key in self.blocked:
            if key not in self.history:
                self.history[key] = {
                    "key": key,
                    "exe": key,
                    "name": Path(key).name or key,
                    "pid": None,
                    "started": 0,
                    "first_seen": 0,
                    "last_seen": 0,
                    "active": False,
                }
                history_changed = True

        stopped, survivors, terminated = self.stop_blocked()
        self.last_stopped = stopped
        for key in terminated - survivors:
            if key in self.history:
                self.history[key]["active"] = False
                self.history[key]["pid"] = None
        for key in self.blocked:
            if key in survivors and key in self.history:
                self.history[key]["active"] = True
        self.processes = sorted(self.history.values(), key=lambda item: item["started"], reverse=True)
        if history_changed:
            try:
                self.save_history()
            except OSError:
                pass

    def scan_tick(self):
        self.scan_processes()
        self.scan_job = self.root.after(SCAN_INTERVAL_MS, self.scan_tick)

    def display_tick(self):
        self.render_processes()
        if time.time() - self.last_history_save >= DISPLAY_INTERVAL_MS / 1000:
            try:
                self.save_history()
            except OSError:
                pass
        self.display_job = self.root.after(DISPLAY_INTERVAL_MS, self.display_tick)

    def is_protected(self, pid, name, exe):
        return name.lower() in NEVER_BLOCK or Path(exe).name.lower() in NEVER_BLOCK or pid == os.getpid()

    def render_processes(self):
        selected = self.table.selection()
        selected_path = self.rows.get(selected[0], (None,))[0] if selected else None
        self.table.delete(*self.table.get_children())
        self.rows.clear()
        filter_value = self.filter_var.get()
        query = self.search_var.get().strip().casefold()
        filtered = []
        for item in self.processes:
            is_blocked = item["key"] in self.blocked
            if filter_value == "Programmes bloqués" and not is_blocked:
                continue
            if filter_value == "Programmes autorisés" and is_blocked:
                continue
            if query and query not in item["name"].casefold():
                continue
            filtered.append(item)

        def sort_key(item):
            if self.sort_column == "state":
                return 0 if item["key"] in self.blocked else 1
            if self.sort_column == "name":
                return item["name"].casefold()
            if self.sort_column == "pid":
                return int(item["pid"] or 0)
            if self.sort_column == "seen":
                return item["last_seen"]
            if self.sort_column == "path":
                return item["exe"].casefold()
            return item["started"]

        filtered.sort(key=sort_key, reverse=self.sort_reverse)
        for column, title in self.column_titles.items():
            marker = (" ▼" if self.sort_reverse else " ▲") if column == self.sort_column else ""
            self.table.heading(column, text=title + marker)

        for item in filtered:
            is_blocked = item["key"] in self.blocked
            started = datetime.fromtimestamp(item["started"]).strftime("%d/%m/%Y %H:%M:%S") if item["started"] else "Inconnu"
            seen = datetime.fromtimestamp(item["last_seen"]).strftime("%d/%m/%Y %H:%M:%S") if item["last_seen"] else "Inconnu"
            if is_blocked:
                state = ("Bloqué · actif" if item["active"] else "Bloqué · inactif")
                state += " · pare-feu configuré" if item["key"] in self.network_blocked else " · pare-feu à configurer"
            else:
                state = "Autorisé · actif" if item["active"] else "Autorisé · inactif"
                if item["key"] in self.network_blocked:
                    state += " · pare-feu configuré"
            iid = self.table.insert("", "end", values=(state, item["name"], item["pid"] or "—", started, seen, item["exe"]), tags=("blocked",) if is_blocked else ())
            self.rows[iid] = (item["key"], item["exe"])
            if item["key"] == selected_path:
                self.table.selection_set(iid)
        self.update_action()
        sort_names = {"state": "état", "name": "nom du programme", "pid": "PID", "started": "date de démarrage", "seen": "dernière détection", "path": "chemin"}
        direction = "décroissant" if self.sort_reverse else "croissant"
        suffix = f" · {self.last_stopped} arrêt(s) effectué(s)" if self.last_stopped else ""
        self.status.set(f"{len(filtered)} affiché(s) / {len(self.processes)} entrées d'historique · {len(self.blocked)} bloqué(s), {len(self.network_blocked)} pare-feu configuré(s){suffix} · Scan {SCAN_INTERVAL_MS / 1000:g} s / affichage {DISPLAY_INTERVAL_MS / 1000:g} s · Tri : {sort_names[self.sort_column]} {direction}")

    def sort_by(self, column):
        if column == self.sort_column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = column == "started"
        self.render_processes()

    def selected_path(self):
        selection = self.table.selection()
        return self.rows.get(selection[0]) if selection else None

    def update_action(self, _event=None):
        item = self.selected_path()
        if not item:
            self.action.configure(text="Bloquer ce programme", state="disabled")
            self.firewall_action.configure(text="Configurer le pare-feu", state="disabled")
            return
        key, exe = item
        if key in self.blocked:
            self.action.configure(text="Autoriser ce programme", state="normal")
        else:
            self.action.configure(text="Bloquer ce programme", state="normal")
        firewall_label = "Retirer le blocage réseau" if key in self.network_blocked else "Configurer le pare-feu"
        self.firewall_action.configure(text=firewall_label, state="normal")

    def configure_firewall_selected(self):
        item = self.selected_path()
        if not item:
            return
        key, exe = item
        if key in self.network_blocked:
            try:
                self.apply_firewall_rules(exe, False)
                self.network_blocked.discard(key)
                self.save_network_policy()
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                messagebox.showerror("Retrait des règles impossible", f"Windows n'a pas confirmé le retrait des règles réseau.\n\n{error}", parent=self.root)
        else:
            try:
                self.apply_firewall_rules(exe, True)
                self.network_blocked.add(key)
                self.save_network_policy()
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                messagebox.showwarning(
                    "Pare-feu non configuré",
                    f"Windows n'a pas confirmé les règles entrantes et sortantes pour cet exécutable.\n\n{error}",
                    parent=self.root,
                )
        self.refresh()

    def toggle_selected(self):
        item = self.selected_path()
        if not item:
            return
        key, exe = item
        is_blocking = key not in self.blocked
        if key in self.blocked:
            self.blocked.remove(key)
        else:
            self.blocked.add(key)
        try:
            self.save_policy()
        except OSError as error:
            messagebox.showerror("Enregistrement impossible", str(error), parent=self.root)
            self.blocked = self.load_policy()
            self.refresh()
            return
        if is_blocking and key not in self.network_blocked:
            self.stop_blocked()
            try:
                self.apply_firewall_rules(exe, True)
                self.network_blocked.add(key)
                self.save_network_policy()
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                messagebox.showwarning("Pare-feu non configuré", f"Le blocage local reste enregistré, mais Windows n'a pas confirmé les règles entrantes et sortantes. Utilise « Configurer le pare-feu » après avoir accepté l'UAC et vérifié le Pare-feu Windows.\n\n{error}", parent=self.root)
        self.refresh()

    def toggle_startup(self):
        try:
            if self.startup_var.get():
                STARTUP_DIR.mkdir(parents=True, exist_ok=True)
                pythonw = Path(sys.executable)
                if pythonw.name.lower() == "python.exe":
                    pythonw = pythonw.with_name("pythonw.exe")
                command = f'"{pythonw}" "{Path(__file__).resolve()}"'.replace('"', '""')
                working_dir = str(APP_DIR).replace('"', '""')
                vbs = f'Set WshShell = CreateObject("WScript.Shell")\r\nWshShell.CurrentDirectory = "{working_dir}"\r\nWshShell.Run "{command}", 0, False\r\n'
                STARTUP_VBS.write_text(vbs, encoding="utf-16")
            elif STARTUP_VBS.exists():
                STARTUP_VBS.unlink()
        except OSError as error:
            messagebox.showerror("Démarrage automatique indisponible", str(error), parent=self.root)
            self.startup_var.set(STARTUP_VBS.exists())

    def close(self):
        self.root.withdraw()

    def create_tray_icon(self):
        image = Image.open(TRAY_IMAGE).convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
        menu = pystray.Menu(
            pystray.MenuItem("Afficher", self.tray_show, default=True),
            pystray.MenuItem("Quitter", self.tray_quit),
        )
        self.tray_icon = pystray.Icon("SurveillanceProcessus", image, APP_TITLE, menu)
        self.tray_icon.run_detached()

    def tray_show(self, _icon, _item):
        self.root.after(0, self.show_window)

    def tray_quit(self, _icon, _item):
        self.root.after(0, self.quit_app)

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def quit_app(self):
        for job in (self.scan_job, self.display_job):
            if job is not None:
                try:
                    self.root.after_cancel(job)
                except tk.TclError:
                    pass
        try:
            self.save_history()
        except OSError:
            pass
        self.tray_icon.stop()
        self.root.destroy()


if __name__ == "__main__":
    if os.name == "nt":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(WINDOWS_APP_ID)
        except (AttributeError, OSError):
            pass
    app_root = tk.Tk()
    ProcessGuard(app_root)
    app_root.mainloop()
