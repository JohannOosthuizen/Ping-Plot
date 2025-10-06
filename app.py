import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import platform
import math
import datetime
import csv
import os
import re

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

import numpy as np

# ---------------- Global Settings and Variables ----------------

# Global ping settings
ping_interval = 0.5         # seconds (configurable)
warning_threshold = 300     # ms (initial default; will be auto-updated if enabled)
error_threshold = 580       # ms (initial default; will be auto-updated if enabled)
auto_thresholds = True      # If True, thresholds are computed from average RTT data

# View window options (in seconds) including as low as 10 seconds.
view_window_options = {
    "10 sec": 10,
    "20 sec": 20,
    "30 sec": 30,
    "1 min": 60,
    "2 min": 120,
    "5 min": 300,
    "10 min": 600,
    "15 min": 900,
    "30 min": 1800,
    "1 hour": 3600,
    "2 hours": 7200,
    "4 hours": 14400,
    "8 hours": 28800,
    "16 hours": 57600,
    "24 hours": 86400,
    "All": None
}
view_window = view_window_options["2 min"]  # default view window

# Logging
log_file = "ping_history.csv"
file_lock = threading.Lock()

# Dictionary to store PingTarget objects (keyed by IP)
targets = {}

# Global flag for pinging activity
pinging_active = False

# Theme management
current_theme = "Dark"  # Default to Dark theme

# Full screen flag
full_screen = True

# Full screen plot flag
plot_fullscreen = False

# ---------------- Create the Main Tkinter Root Window First ----------------

root = tk.Tk()
root.title("Ping-Plot")

# ---------------- Now Create Beep Alert Configuration Variables ----------------
# (These must be created after the root window so they have a proper master.)
up_alert_var = tk.BooleanVar(value=False)
down_alert_var = tk.BooleanVar(value=True)

def play_alarm_up():
    """Plays a sound to indicate a target has come online."""
    print("Up alert!")
    try:
        import winsound
        winsound.Beep(600, 500)
    except ImportError:
        root.bell()

def play_alarm_down():
    """Plays a sound to indicate a target has gone offline."""
    print("Down alert!")
    try:
        import winsound
        winsound.Beep(400, 500)
    except ImportError:
        root.bell()

# ---------------- Utility Functions ----------------

def get_default_gateway():
    """
    Retrieves the default gateway IP address for the current machine.

    Supports both Windows and Linux/macOS systems by parsing the output of
    'route print' or 'ip route show default' respectively.

    Returns:
        str: The default gateway IP address as a string, or None if it cannot be determined.
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.check_output("route print 0.0.0.0", shell=True, universal_newlines=True)
            match = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+([\d\.]+)', result)
            if match:
                return match.group(1)
        else:
            result = subprocess.check_output("ip route show default", shell=True, universal_newlines=True)
            match = re.search(r'default via ([\d\.]+)', result)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error retrieving default gateway: {e}")
    return None

def ping_host(ip):
    """
    Sends a single ICMP echo request to the specified IP address.

    Args:
        ip (str): The IP address or hostname to ping.

    Returns:
        bool: True if the ping is successful (return code 0), False otherwise.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def log_ping_event(ip, timestamp, rtt, status):
    """
    Logs a single ping event to a CSV file.

    This function is thread-safe, using a lock to prevent race conditions
    when writing to the log file.

    Args:
        ip (str): The IP address that was pinged.
        timestamp (datetime.datetime): The time of the ping event.
        rtt (float or None): The round-trip time in milliseconds. None if the ping failed.
        status (str): The status of the ping ("Online" or "Offline").
    """
    with file_lock:
        file_exists = os.path.exists(log_file)
        with open(log_file, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow(["timestamp", "ip", "rtt", "status"])
            writer.writerow([timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                             ip,
                             f"{rtt:.1f}" if rtt is not None else "",
                             status])

# ---------------- PingTarget Class ----------------

class PingTarget:
    """
    Represents a single target to be monitored.

    Each PingTarget instance runs its own pinging loop in a separate thread,
    collecting RTT data and status information.

    Attributes:
        ip (str): The IP address or hostname of the target.
        rtt_list (list): A list of RTT values in ms. None indicates a failed ping.
        time_list (list): A list of datetime objects corresponding to each ping.
        status (bool): The current online status of the target.
        running (bool): A flag to control the pinging thread.
        thread (threading.Thread): The thread object for the ping loop.
    """
    def __init__(self, ip):
        self.ip = ip
        self.rtt_list = []       # List of RTT values (ms); None indicates failure.
        self.time_list = []      # List of datetime objects for each ping.
        self.status = False      # Current online status.
        self.running = False     # Controls the ping thread.
        self.thread = None
        # For alert logic per target
        self.last_alarm_time = None
        self.was_online = False

    def start(self):
        """Starts the pinging loop in a new thread."""
        self.running = True
        self.thread = threading.Thread(target=self.ping_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the pinging loop."""
        self.running = False

    def ping_loop(self):
        """
        The main loop for pinging the target.

        Continuously pings the target at the globally defined `ping_interval`,
        records the RTT and status, and logs the event.
        """
        global ping_interval
        while self.running:
            current_time = datetime.datetime.now()
            start_time = time.time()
            success = ping_host(self.ip)
            rtt = (time.time() - start_time) * 1000  # RTT in ms
            self.status = success

            if success:
                if not self.was_online:
                    if up_alert_var.get():
                        play_alarm_up()
                    self.last_alarm_time = time.time()
                    self.was_online = True
                elif time.time() - self.last_alarm_time >= 30:
                    if up_alert_var.get():
                        play_alarm_up()
                    self.last_alarm_time = time.time()
            else:
                if self.was_online:
                    if down_alert_var.get():
                        play_alarm_down()
                self.was_online = False
                self.last_alarm_time = None

            self.rtt_list.append(rtt if success else None)
            self.time_list.append(current_time)
            log_ping_event(self.ip, current_time, rtt if success else None, "Online" if success else "Offline")
            time.sleep(ping_interval)

# ---------------- GUI and Plotting ----------------

def apply_theme(theme):
    """
    Applies a visual theme to the application.

    Args:
        theme (str): The name of the theme to apply ("Dark" or "Light").
    """
    global current_theme
    current_theme = theme
    if theme == "Dark":
        bg_color = "#282a36"
        fg_color = "#f8f8f2"
        widget_bg = "#44475a"
        plot_bg = "#282a36" 
        root.tk_setPalette(background=bg_color, foreground=fg_color,
                           activeBackground=widget_bg, activeForeground=fg_color)
        
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure(".", background=bg_color, foreground=fg_color)
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TLabelFrame", background=bg_color, foreground=fg_color)
        style.configure("TLabelFrame.Label", background=bg_color, foreground=fg_color)
        
        style.configure("Treeview",
                        background=widget_bg,
                        foreground=fg_color,
                        fieldbackground=widget_bg,
                        rowheight=25)
        style.map("Treeview", background=[('selected', '#6272a4')])
        style.configure("Treeview.Heading",
                        background=widget_bg,
                        foreground=fg_color)
        
        style.configure("TMenubutton",
                        background=widget_bg,
                        foreground=fg_color)
        style.map("TMenubutton",
                  background=[('active', '#6272a4')])
                  
        style.configure("TCheckbutton",
                        background=bg_color,
                        foreground=fg_color,
                        selectcolor=widget_bg)
        style.map("TCheckbutton",
                  foreground=[('active', fg_color)],
                  background=[('active', bg_color)])
    else:
        root.tk_setPalette(background="SystemButtonFace", foreground="black")
        style = ttk.Style()
        style.theme_use("default")

# --- Target Management Frame ---
target_frame = tk.LabelFrame(root, text="Targets", padx=5, pady=5)
target_frame.pack(fill=tk.X, padx=10, pady=5)

tk.Label(target_frame, text="Target IP:").grid(row=0, column=0, sticky="w")
target_entry = tk.Entry(target_frame, width=20)
target_entry.grid(row=0, column=1, padx=5, pady=5)

def add_target():
    """Adds a new ping target from the entry field."""
    ip = target_entry.get().strip()
    if ip == "":
        messagebox.showerror("Error", "Please enter a valid IP address.")
        return
    if ip in targets:
        messagebox.showwarning("Warning", f"Target {ip} already exists.")
        return
    new_target = PingTarget(ip)
    targets[ip] = new_target
    target_listbox.insert(tk.END, ip)
    target_entry.delete(0, tk.END)

add_target_button = tk.Button(target_frame, text="Add Target", command=add_target)
add_target_button.grid(row=0, column=2, padx=5)

tk.Label(target_frame, text="Current Targets:").grid(row=1, column=0, columnspan=3, sticky="w")
target_listbox = tk.Listbox(target_frame, height=4)
target_listbox.grid(row=2, column=0, columnspan=3, sticky="we", padx=5, pady=5)

def remove_target():
    """Removes the selected target from the list."""
    selected = target_listbox.curselection()
    if not selected:
        messagebox.showerror("Error", "Please select a target to remove.")
        return
    index = selected[0]
    ip = target_listbox.get(index)
    if ip in targets:
        targets[ip].stop()
        del targets[ip]
    target_listbox.delete(index)

remove_target_button = tk.Button(target_frame, text="Remove Selected", command=remove_target)
remove_target_button.grid(row=3, column=0, columnspan=3, pady=(0,5))

# --- Settings Frame ---
settings_frame = tk.LabelFrame(root, text="Settings", padx=5, pady=5)
settings_frame.pack(fill=tk.X, padx=10, pady=5)

tk.Label(settings_frame, text="Warning Threshold (ms):").grid(row=0, column=0, sticky="w")
warning_entry = tk.Entry(settings_frame, width=8)
warning_entry.insert(0, str(warning_threshold))
warning_entry.grid(row=0, column=1, padx=5)

tk.Label(settings_frame, text="Error Threshold (ms):").grid(row=0, column=2, sticky="w")
error_entry = tk.Entry(settings_frame, width=8)
error_entry.insert(0, str(error_threshold))
error_entry.grid(row=0, column=3, padx=5)

def set_thresholds():
    """Sets the RTT warning and error thresholds from the entry fields."""
    global warning_threshold, error_threshold, auto_thresholds
    try:
        w = float(warning_entry.get().strip())
        e = float(error_entry.get().strip())
        if w >= e:
            status_var.set("Warning threshold must be less than Error threshold.")
        else:
            warning_threshold = w
            error_threshold = e
            auto_thresholds = False  # disable auto-updating thresholds
            status_var.set(f"Thresholds set: OK < {w:.1f} ms, Warning {w:.1f}-{e:.1f} ms, Error ≥ {e:.1f} ms")
    except ValueError:
        status_var.set("Invalid threshold values.")

tk.Button(settings_frame, text="Set Thresholds", command=set_thresholds).grid(row=0, column=4, padx=5)

tk.Label(settings_frame, text="Ping Frequency (s):").grid(row=1, column=0, sticky="w")
frequency_entry = tk.Entry(settings_frame, width=8)
frequency_entry.insert(0, str(ping_interval))
frequency_entry.grid(row=1, column=1, padx=5)

def set_frequency():
    """Sets the ping interval from the entry field."""
    global ping_interval
    try:
        new_interval = float(frequency_entry.get().strip())
        ping_interval = new_interval
        status_var.set(f"Ping frequency set to {new_interval} s")
    except ValueError:
        status_var.set("Invalid frequency value.")

tk.Button(settings_frame, text="Set Frequency", command=set_frequency).grid(row=1, column=2, padx=5)

tk.Label(settings_frame, text="View Window:").grid(row=1, column=3, sticky="e")
view_var = tk.StringVar(value="5 min")
def set_view_window(*args):
    """Sets the time window for the data displayed on the plot."""
    global view_window
    view_window = view_window_options[view_var.get()]
view_var.trace("w", set_view_window)
view_menu = ttk.OptionMenu(settings_frame, view_var, view_var.get(), *view_window_options.keys())
view_menu.grid(row=1, column=4, padx=5)

# Beep Alert Options
tk.Label(settings_frame, text="Up Alert:").grid(row=2, column=0, sticky="w")
ttk.Checkbutton(settings_frame, text="Enable", variable=up_alert_var).grid(row=2, column=1, sticky="w")
tk.Label(settings_frame, text="Down Alert:").grid(row=2, column=2, sticky="w")
ttk.Checkbutton(settings_frame, text="Enable", variable=down_alert_var).grid(row=2, column=3, sticky="w")

# Theme selector
tk.Label(settings_frame, text="Theme:").grid(row=2, column=4, sticky="e")
theme_var = tk.StringVar(value="Dark")
def theme_changed(new_value):
    apply_theme(new_value)
theme_menu = ttk.OptionMenu(settings_frame, theme_var, "Dark", "Light", "Dark", command=theme_changed)
theme_menu.grid(row=2, column=5, padx=5)


def toggle_plot_fullscreen():
    """Toggles a fullscreen mode for the plot area, hiding other widgets."""
    global plot_fullscreen
    plot_fullscreen = not plot_fullscreen
    
    widgets_to_hide = [target_frame, settings_frame, stats_frame, status_label]
    
    if plot_fullscreen:
        for widget in widgets_to_hide:
            widget.pack_forget()
        fullscreen_plot_button.config(text="Exit Fullscreen")
    else:
        control_frame.pack_forget()
        stats_frame.pack_forget()
        status_label.pack_forget()
        canvas.get_tk_widget().pack_forget()
        canvas._tkcanvas.pack_forget()
        
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        settings_frame.pack(fill=tk.X, padx=10, pady=5)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        status_label.pack(pady=5)
        
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        toolbar.update()
        canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
        
        fullscreen_plot_button.config(text="Fullscreen Plot")

def exit_fullscreen_modes(event=None):
    """Exits any active fullscreen mode (plot or window) when the Escape key is pressed."""
    global fullscreen_ax, full_screen
    if fullscreen_ax:
        fullscreen_ax = None
        return

    if full_screen:
        toggle_fullscreen()

def discover_and_add_hops(destination_ip="8.8.8.8"):
    """
    Discovers intermediate network hops to a destination using traceroute.

    Args:
        destination_ip (str): The destination IP for the traceroute.
    """
    system = platform.system().lower()
    if system == "windows":
        command = ["tracert", "-d", "-w", "1000", destination_ip]
    else:
        command = ["traceroute", "-n", "-w", "1", destination_ip]

    try:
        status_var.set(f"Discovering hops to {destination_ip}... This may take a moment.")
        root.update_idletasks()

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0
        )

        if result.returncode != 0:
            print(f"Traceroute command failed: {result.stderr}")
            status_var.set("Traceroute command failed.")
            return

        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        discovered_ips = set()

        for line in result.stdout.splitlines():
            line = line.strip()
            if line and line.split()[0].isdigit():
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(0)
                    if ip != destination_ip:
                        discovered_ips.add(ip)

        if not discovered_ips:
            status_var.set("Could not discover any new intermediate hops.")
            return

        added_count = 0
        for ip in discovered_ips:
            if ip not in targets:
                new_target = PingTarget(ip)
                targets[ip] = new_target
                target_listbox.insert(tk.END, ip)
                added_count += 1
                if pinging_active:
                    new_target.start()
        
        status_var.set(f"Added {added_count} new hop(s) as ping targets.")

    except FileNotFoundError:
        status_var.set("Traceroute command not found. Cannot discover hops.")
    except subprocess.TimeoutExpired:
        status_var.set("Traceroute command timed out.")
    except Exception as e:
        status_var.set("An error occurred during hop discovery.")
        print(f"Hop discovery error: {e}")

# --- Control Buttons ---
control_frame = tk.Frame(root)
control_frame.pack(fill=tk.X, padx=10, pady=5)

def toggle_pinging():
    """Starts or stops the pinging process for all targets."""
    global pinging_active
    if not pinging_active:
        if not targets:
            status_var.set("No targets to ping. Please add at least one target.")
            return
        for target in targets.values():
            target.start()
        pinging_active = True
        ping_button.config(text="Stop Pinging", background="red", fg="white")
    else:
        for target in targets.values():
            target.stop()
        pinging_active = False
        ping_button.config(text="Start Pinging", background=default_button_color, fg="black")

ping_button = tk.Button(control_frame, text="Start Pinging", command=toggle_pinging, fg="black")
ping_button.pack(side=tk.LEFT, padx=5)
default_button_color = ping_button.cget("background")

def toggle_fullscreen():
    """Toggles the main application window's fullscreen state."""
    global full_screen
    full_screen = not full_screen
    root.attributes("-fullscreen", full_screen)
    
tk.Button(control_frame, text="Toggle Full Screen", command=toggle_fullscreen).pack(side=tk.LEFT, padx=5)
fullscreen_plot_button = tk.Button(control_frame, text="Fullscreen Plot", command=toggle_plot_fullscreen)
fullscreen_plot_button.pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="Discover Hops", command=discover_and_add_hops, fg="black").pack(side=tk.LEFT, padx=5)

def load_history():
    """Loads and displays historical ping data from the CSV log file."""
    if not os.path.exists(log_file):
        messagebox.showinfo("Load History", "No history file found.")
        return
    history_data = {}
    with open(log_file, "r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip = row["ip"]
            ts = datetime.datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            try:
                rtt = float(row["rtt"]) if row["rtt"] != "" else None
            except ValueError:
                rtt = None
            if ip not in history_data:
                history_data[ip] = {"times": [], "rtts": []}
            history_data[ip]["times"].append(ts)
            history_data[ip]["rtts"].append(rtt)
    hist_win = tk.Toplevel(root)
    hist_win.title("Historical Ping Data")
    
    plt.style.use("dark_background")
    fig_hist = Figure(figsize=(7, 4), dpi=100)
    ax_hist = fig_hist.add_subplot(111)
    
    ax_hist.set_title("Historical RTT Data")
    ax_hist.set_xlabel("Time of Day")
    ax_hist.set_ylabel("RTT (ms)")
    ax_hist.xaxis_date()
    ax_hist.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    
    colors = ['#50fa7b', '#ffb86c', '#ff79c6', '#bd93f9', '#8be9fd', '#f1fa8c']
    for i, (ip, data) in enumerate(history_data.items()):
        x_vals = mdates.date2num(data["times"])
        y_vals = [r if r is not None else np.nan for r in data["rtts"]]
        ax_hist.plot_date(x_vals, y_vals, linestyle='-', color=colors[i % len(colors)], label=ip)

    handles, labels = ax_hist.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax_hist.legend(by_label.values(), by_label.keys(), loc="upper right")
    fig_hist.autofmt_xdate()
    canvas_hist = FigureCanvasTkAgg(fig_hist, master=hist_win)
    canvas_hist.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    NavigationToolbar2Tk(canvas_hist, hist_win)
    
tk.Button(control_frame, text="Load History", command=load_history).pack(side=tk.LEFT, padx=5)

# --- Statistics Frame ---
stats_frame = tk.LabelFrame(root, text="Statistics", padx=5, pady=5)
stats_frame.pack(fill=tk.X, padx=10, pady=5)

stats_tree = ttk.Treeview(stats_frame, columns=("target", "min", "max", "avg"), show="headings", height=4)
stats_tree.heading("target", text="Target")
stats_tree.heading("min", text="Min (ms)")
stats_tree.heading("max", text="Max (ms)")
stats_tree.heading("avg", text="Avg (ms)")
stats_tree.column("target", width=100, anchor="center")
stats_tree.column("min", width=80, anchor="center")
stats_tree.column("max", width=80, anchor="center")
stats_tree.column("avg", width=80, anchor="center")
stats_tree.pack(fill=tk.X, padx=5, pady=5)

def update_stats():
    """Periodically updates the statistics treeview with the latest data."""
    for row in stats_tree.get_children():
        stats_tree.delete(row)
    now = datetime.datetime.now()
    lower_bound = now - datetime.timedelta(seconds=view_window) if view_window is not None else None
    for ip, target in targets.items():
        data = [r for t, r in zip(target.time_list, target.rtt_list) if (lower_bound is None or t >= lower_bound) and r is not None]
        if data:
            m = min(data)
            M = max(data)
            avg = sum(data) / len(data)
            stats_tree.insert("", tk.END, values=(ip, f"{m:.1f}", f"{M:.1f}", f"{avg:.1f}"))
        else:
            stats_tree.insert("", tk.END, values=(ip, "N/A", "N/A", "N/A"))
    root.after(1000, update_stats)

update_stats()

# --- Status Label ---
status_var = tk.StringVar(value="Status: Idle")
status_label = tk.Label(root, textvariable=status_var, font=("Helvetica", 12))
status_label.pack(pady=5)

# --- Matplotlib Figure for Live RTT Graph ---
plt.style.use("dark_background")
fig = Figure(figsize=(8, 4), dpi=100)
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
toolbar = NavigationToolbar2Tk(canvas, root)
toolbar.update()
canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)

fullscreen_ax = None # To track which axis is in fullscreen

def on_plot_click(event):
    """Handles double-clicking on a subplot to enter fullscreen mode for that plot."""
    global fullscreen_ax
    if event.dblclick and event.inaxes:
        if not fullscreen_ax:
            fullscreen_ax = event.inaxes

canvas.mpl_connect('button_press_event', on_plot_click)

def draw_single_plot(ax, target, now, lower_bound):
    """
    Draws the RTT plot for a single target on a given Matplotlib axis.

    Args:
        ax (matplotlib.axes.Axes): The axis to draw on.
        target (PingTarget): The target whose data should be plotted.
        now (datetime.datetime): The current time, for setting the x-axis limit.
        lower_bound (datetime.datetime or None): The earliest time to display data from.
    """
    ax.clear()
    ax.set_title(target.ip)
    ax.set_ylabel("RTT (ms)")
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    valid_rtts_in_view = [r for t, r in zip(target.time_list, target.rtt_list) if (lower_bound is None or t >= lower_bound) and r is not None]
    if valid_rtts_in_view:
        top_limit = max(error_threshold * 1.5, max(valid_rtts_in_view) * 1.2)
    else:
        top_limit = error_threshold * 1.5
    ax.set_ylim(bottom=0, top=top_limit)

    ax.axhspan(warning_threshold, error_threshold, color='yellow', alpha=0.1, zorder=0)
    ax.axhspan(error_threshold, top_limit, color='red', alpha=0.1, zorder=0)

    color = '#8be9fd'

    filtered_data = [(t, r) for t, r in zip(target.time_list, target.rtt_list) if (lower_bound is None or t >= lower_bound)]
    if not filtered_data:
        ax.text(0.5, 0.5, "No data in view", ha='center', va='center')
        return

    aggregation_threshold_seconds = 300
    use_aggregated_view = view_window is not None and view_window > aggregation_threshold_seconds

    if not use_aggregated_view:
        times = [pt[0] for pt in filtered_data]
        rtts = [pt[1] for pt in filtered_data]
        y_vals = [r if r is not None else np.nan for r in rtts]
        ax.plot(times, y_vals, linestyle='-', color=color)

        fail_times = [times[j] for j, r in enumerate(rtts) if r is None]
        if fail_times:
            ax.scatter(fail_times, [0]*len(fail_times), color=color, marker='x', s=50)
    else:
        num_bins = 150
        time_delta_per_bin = datetime.timedelta(seconds=view_window / num_bins)
        bin_stats = []
        for j in range(num_bins):
            bin_start = lower_bound + j * time_delta_per_bin
            bin_end = bin_start + time_delta_per_bin
            successful_rtts = [r for t, r in filtered_data if bin_start <= t < bin_end and r is not None]
            if successful_rtts:
                avg = sum(successful_rtts) / len(successful_rtts)
                min_val = min(successful_rtts)
                max_val = max(successful_rtts)
                bin_center_time = bin_start + time_delta_per_bin / 2
                bin_stats.append((bin_center_time, avg, min_val, max_val))
        if bin_stats:
            plot_times, plot_avgs, plot_mins, plot_maxs = zip(*bin_stats)
            ax.vlines(plot_times, plot_mins, plot_maxs, color=color, alpha=0.5)
            line, = ax.plot(plot_times, plot_avgs, linestyle='-', marker='o', markersize=2, color=color)

    ax.set_xlim(lower_bound, now)

def update_plot():
    """
    The main plotting loop.

    This function is called periodically to redraw the entire plot area. It handles
    multi-plot layout, single-plot fullscreen, and auto-threshold updates.
    """
    global warning_threshold, error_threshold, auto_thresholds, fullscreen_ax

    now = datetime.datetime.now()
    lower_bound = now - datetime.timedelta(seconds=view_window) if view_window is not None else None

    all_rtts_in_view = [r for target in targets.values() for t, r in zip(target.time_list, target.rtt_list) if (lower_bound is None or t >= lower_bound) and r is not None]
    if auto_thresholds and all_rtts_in_view:
        avg_all = sum(all_rtts_in_view) / len(all_rtts_in_view)
        warning_threshold = avg_all * 1.1
        error_threshold = avg_all * 2
        warning_entry.delete(0, tk.END); warning_entry.insert(0, f"{warning_threshold:.1f}")
        error_entry.delete(0, tk.END); error_entry.insert(0, f"{error_threshold:.1f}")
        status_var.set(f"Auto thresholds: avg={avg_all:.1f} ms, warning={warning_threshold:.1f} ms, error={error_threshold:.1f} ms")

    if fullscreen_ax and fullscreen_ax in fig.axes:
        for ax in fig.axes:
            ax.set_visible(ax == fullscreen_ax)
        ax = fullscreen_ax
        ax.set_position([0.07, 0.1, 0.9, 0.85])
        target = targets.get(ax.get_title())
        if target:
            draw_single_plot(ax, target, now, lower_bound)
    else:
        fullscreen_ax = None
        if len(fig.axes) != len(targets) or not all(ax.get_visible() for ax in fig.axes):
            fig.clear()
            if targets:
                n_targets = len(targets)
                n_cols = 2 if n_targets > 1 else 1
                n_rows = (n_targets + n_cols - 1) // n_cols
                axes = fig.subplots(n_rows, n_cols, squeeze=False).flatten()
                for i in range(len(targets), len(axes)):
                    axes[i].set_visible(False)
            else:
                ax = fig.add_subplot(111)
                ax.text(0.5, 0.5, "Add a target to begin monitoring", ha='center', va='center')
                ax.set_xticks([]); ax.set_yticks([])

        visible_axes = [ax for ax in fig.axes if ax.get_visible()]
        for ax, target in zip(visible_axes, targets.values()):
            draw_single_plot(ax, target, now, lower_bound)
        if targets:
            fig.tight_layout(pad=1.0)

    canvas.draw()
    root.after(1000, update_plot)

update_plot()

def update_status():
    """Periodically updates the status bar text."""
    if not pinging_active:
        status_var.set("Status: Idle")
    else:
        active_ips = ", ".join(targets.keys())
        status_var.set(f"Pinging: {active_ips}")
    root.after(1000, update_status)

update_status()

def add_default_targets():
    """Adds default ping targets (Google DNS and the default gateway) on startup."""
    default_ips = ["8.8.8.8"]
    gateway = get_default_gateway()
    if gateway:
        default_ips.append(gateway)
    for ip in default_ips:
        if ip not in targets:
            new_target = PingTarget(ip)
            targets[ip] = new_target
            target_listbox.insert(tk.END, ip)

add_default_targets()
toggle_pinging()

def on_closing():
    """Handles the application window being closed."""
    for target in targets.values():
        target.stop()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.bind('<Escape>', exit_fullscreen_modes)
apply_theme(current_theme)
root.mainloop()