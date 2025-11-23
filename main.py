# main.py
# GUI that ties monitor/report/traffic modules together.

import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from monitor import Monitor
from report import save_report_png
from traffic_analysis import NetstatAnalyzer, _HAS_SCAPY, ScapySniffer, save_traffic_report
from utils import ensure_results_dir
import ctypes
import sys
import os
import winsound
import threading

# ------------------- Settings -------------------
def load_settings():
    settings = {"sfx_enabled": True}
    try:
        if os.path.exists("settings.yaml"):
            with open("settings.yaml", "r") as f:
                for line in f:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        key = key.strip()
                        val = val.strip().lower()
                        if val == "true":
                            settings[key] = True
                        elif val == "false":
                            settings[key] = False
                        else:
                            settings[key] = val
    except Exception as e:
        print(f"Error loading settings: {e}")
    return settings

SETTINGS = load_settings()

def play_sound(sound_alias):
    if SETTINGS.get("sfx_enabled", True):
        try:
            winsound.MessageBeep(sound_alias)
        except:
            pass


traffic_stop_event = threading.Event()

# ------------------- Admin check -------------------
def is_admin():
    if sys.platform.startswith("win"):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        import os
        return os.geteuid() == 0

# ------------------- Init -------------------
# ------------------- Animation -------------------
class ActivitySpinner(tk.Canvas):
    def __init__(self, parent, width=200, height=6, color="#0078D7"):
        try:
            bg_color = parent.cget("background")
        except:
            try:
                bg_color = ttk.Style().lookup("TFrame", "background")
            except:
                bg_color = "white"
        
        if not bg_color: bg_color = "white"
            
        super().__init__(parent, width=width, height=height, bg=bg_color, highlightthickness=0)
        self.width = width
        self.height = height
        self.color = color
        self.rect = self.create_rectangle(0, 0, 40, height, fill=color, width=0)
        self.pos = 0
        self.direction = 1
        self.running = False
        self._animate()

    def start(self):
        if not self.running:
            self.running = True
            self.pack(side="bottom", fill="x", pady=5)
            self._animate()

    def stop(self):
        self.running = False
        self.pack_forget()

    def _animate(self):
        if not self.running:
            return
        
        # Move
        step = 5
        self.pos += step * self.direction
        
        # Bounce
        if self.pos + 40 >= self.width:
            self.direction = -1
        elif self.pos <= 0:
            self.direction = 1
            
        self.coords(self.rect, self.pos, 0, self.pos + 40, self.height)
        self.after(20, self._animate)

# ------------------- Auto-Close Popup -------------------
class AutoCloseMessageBox(tk.Toplevel):
    def __init__(self, parent, title, message, timeout=10):
        super().__init__(parent)
        play_sound(winsound.MB_ICONQUESTION)  # Popup Open Sound
        self.title(title)
        self.geometry("400x230")
        self.resizable(False, False)
        
        # Center relative to parent
        try:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - 200
            y = parent.winfo_y() + (parent.winfo_height() // 2) - 90
            self.geometry(f"+{x}+{y}")
        except:
            pass
        
        self.timeout = timeout
        self.start_time = time.time()
        self.cancelled = False
        
        # Progress bar (Canvas) at the bottom - "Fine line"
        # We pack this first with side=bottom so it stays at the bottom
        # Use system background color for the canvas background
        bg_color = self.cget("bg")
        self.canvas = tk.Canvas(self, height=4, highlightthickness=0, bg=bg_color)
        self.canvas.pack(side="bottom", fill="x")
        
        # Fill color: a nice blue. #0078D7 is a standard accent blue.
        self.rect = self.canvas.create_rectangle(0, 0, 400, 4, fill="#0078D7", width=0)
        
        # UI Content Frame
        frame = ttk.Frame(self, padding=20)
        frame.pack(side="top", fill="both", expand=True)
        
        ttk.Label(frame, text=message, wraplength=360, justify="center").pack(pady=(10, 20))
        
        self.lbl_timer = ttk.Label(frame, text=f"Auto-closing in {timeout}s...")
        self.lbl_timer.pack(pady=(0, 15))
        
        ttk.Button(frame, text="Close Now", command=self.close).pack()
        
        # Start timer
        self.after(50, self._tick)
        
        # Handle X button
        self.protocol("WM_DELETE_WINDOW", self.close)
        
    def _tick(self):
        if self.cancelled:
            return
            
        elapsed = time.time() - self.start_time
        remaining = self.timeout - elapsed
        
        if remaining <= 0:
            play_sound(winsound.MB_OK)  # Popup Close Sound
            self.destroy()
            return
            
        # Update text (rounded up)
        self.lbl_timer.config(text=f"Auto-closing in {int(remaining) + 1}s...")
        
        # Update bar width
        # Window width is 400
        current_width = 400 * (remaining / self.timeout)
        self.canvas.coords(self.rect, 0, 0, current_width, 4)
        
        self.after(50, self._tick)
            
    def close(self):
        self.cancelled = True
        play_sound(winsound.MB_OK)  # Popup Close Sound
        self.destroy()

# ------------------- Init -------------------
ensure_results_dir()
mon = Monitor()

root = tk.Tk()
root.title("Handshake Detector — Main")
root.geometry("1000x700")

# ------------------- GUI Controls -------------------
# Left Column: Settings & Controls
left_frame = ttk.Frame(root)
left_frame.pack(side="left", fill="y", padx=8, pady=8)

# Settings Group
settings_group = ttk.LabelFrame(left_frame, text="Settings")
settings_group.pack(fill="x", padx=4, pady=4)

ttk.Label(settings_group, text="Duration:").pack(side="left", padx=4, pady=4)
hours_entry = ttk.Entry(settings_group, width=3); hours_entry.insert(0, "0"); hours_entry.pack(side="left")
ttk.Label(settings_group, text="h").pack(side="left")
minutes_entry = ttk.Entry(settings_group, width=3); minutes_entry.insert(0, "0"); minutes_entry.pack(side="left")
ttk.Label(settings_group, text="m").pack(side="left")
seconds_entry = ttk.Entry(settings_group, width=3); seconds_entry.insert(0, "3"); seconds_entry.pack(side="left")
ttk.Label(settings_group, text="s").pack(side="left")

ttk.Label(settings_group, text="Interval (s):").pack(side="left", padx=6)
interval_entry = ttk.Entry(settings_group, width=6); interval_entry.insert(0, "0.5"); interval_entry.pack(side="left", padx=4, pady=4)

# Execution Group
exec_group = ttk.LabelFrame(left_frame, text="Execution")
exec_group.pack(fill="x", padx=4, pady=4)

start_btn = ttk.Button(exec_group, text="Start Test", command=lambda: start_test()); start_btn.pack(side="left", padx=4, pady=4)
stop_btn = ttk.Button(exec_group, text="Stop Test", command=lambda: stop_test()); stop_btn.pack(side="left", padx=4, pady=4)
partial_btn = ttk.Button(exec_group, text="Partial Result", command=lambda: partial_result()); partial_btn.pack(side="left", padx=4, pady=4)
full_btn = ttk.Button(exec_group, text="Full Result", command=lambda: full_result_snapshot()); full_btn.pack(side="left", padx=4, pady=4)

# Analysis Group
analysis_group = ttk.LabelFrame(left_frame, text="Analysis")
analysis_group.pack(fill="x", padx=4, pady=4)

traffic_simple_btn = ttk.Button(analysis_group, text="Netstat (simple)", width=15, command=lambda: show_traffic_simple()); traffic_simple_btn.pack(side="left", padx=4, pady=4)
traffic_advanced_btn = ttk.Button(analysis_group, text="Advanced (scapy)", width=15, command=lambda: show_traffic_advanced()); traffic_advanced_btn.pack(side="left", padx=4, pady=4)

# Admin status
admin_status = tk.Label(analysis_group, text="Admin: ❌", fg="red")
admin_status.pack(side="right", padx=6)
if is_admin():
    admin_status.config(text="Admin: ✅", fg="green")

# Activity Spinner (hidden by default)
spinner = ActivitySpinner(left_frame, width=200, height=6)

# Right Column: Console
right_frame = ttk.Frame(root)
right_frame.pack(side="right", fill="both", expand=True, padx=8, pady=8)

console = scrolledtext.ScrolledText(right_frame, font=("Consolas", 10), state="disabled")
console.pack(fill="both", expand=True)

# ------------------- Console -------------------
last_log_index = 0
def append_console(msg):
    ts = time.strftime("%H:%M:%S")
    console.config(state="normal")
    _, last = console.yview()
    at_bottom = (last == 1.0)
    # Check if msg already has a timestamp (starts with [HH:MM:SS])
    if msg.startswith("[") and msg[9] == "]":
        # Already timestamped (likely from monitor logs)
        console.insert(tk.END, f"{msg}\n")
    else:
        console.insert(tk.END, f"[{ts}] {msg}\n")
    if at_bottom:
        console.see(tk.END)
    console.config(state="disabled")

def update_console_live():
    global last_log_index
    data = mon.get_data()
    logs = data["logs"]
    console.config(state="normal")
    first, last = console.yview()
    at_bottom = (last > 0.99)
    for entry in logs[last_log_index:]:
        console.insert(tk.END, entry + "\n")
    if at_bottom:
        console.see(tk.END)
    last_log_index = len(logs)
    console.config(state="disabled")
    root.after(500, update_console_live)

update_console_live()

# ------------------- Monitor Callback -------------------
from report import save_report_html
import webbrowser

def on_monitor_finished():
    # Ensure UI resets (thread-safe)
    root.after(0, lambda: set_ui_state(False))
    
    data = mon.get_data()
    if data["latencies"]:
        def _task():
            append_console("Generating final result snapshot...")
            try:
                fname = save_report_html(data, prefix="result")
                append_console(f"Final result saved to {fname}")
                play_sound(winsound.MB_ICONASTERISK)  # Report Open Sound
                webbrowser.open(os.path.abspath(fname))
                # Auto-close popup for finished execution
                AutoCloseMessageBox(root, "Execution Finished", f"Report saved to:\n{fname}\n\nOpened in browser.", timeout=10)
            except Exception as e:
                append_console(f"Failed to save final result: {e}")
        threading.Thread(target=_task, daemon=True).start()

mon._finished_callback = on_monitor_finished

# ------------------- Monitor Controls -------------------
def set_ui_state(running):
    state = "disabled" if running else "normal"
    inv_state = "normal" if running else "disabled"
    
    start_btn.config(state=state)
    traffic_simple_btn.config(state=state)
    traffic_advanced_btn.config(state=state)
    
    stop_btn.config(state=inv_state)
    
    if running:
        spinner.start()
    else:
        spinner.stop()

def start_test():
    try:
        h = int(hours_entry.get() or 0)
        m = int(minutes_entry.get() or 0)
        s = int(seconds_entry.get() or 0)
        duration = h*3600 + m*60 + s
        if duration <= 0: raise ValueError("Duration must be > 0")
        interval = float(interval_entry.get())
        if interval <= 0: raise ValueError("Interval must be > 0")
    except Exception as e:
        messagebox.showerror("Invalid input", str(e))
        return

    started = mon.start(duration_seconds=duration, interval_seconds=interval)
    if started:
        play_sound(winsound.MB_ICONASTERISK)  # Start Sound
        set_ui_state(True)
    append_console(f"Monitoring started for {h}h {m}m {s}s (interval {interval}s)" if started else "Monitor already running")

def stop_test():
    mon.stop()
    traffic_stop_event.set()  # Signal traffic analysis to stop
    set_ui_state(False)
    play_sound(winsound.MB_ICONHAND)  # Stop Sound
    append_console("Monitoring/Analysis stopped by user")

def partial_result():
    data = mon.get_data()
    if not data["latencies"]:
        messagebox.showerror("No data", "No samples collected yet.")
        return
    def _task():
        append_console("Generating partial snapshot...")
        try:
            fname = save_report_html(data, prefix="partial")
            append_console(f"Partial snapshot saved to {fname}")
            play_sound(winsound.MB_ICONEXCLAMATION)  # Partial Snapshot Sound
            webbrowser.open(os.path.abspath(fname))
            messagebox.showinfo("Partial Saved", f"Saved to:\n{fname}")
        except Exception as e:
            append_console(f"Failed to save partial snapshot: {e}")
            messagebox.showerror("Error", str(e))
    threading.Thread(target=_task, daemon=True).start()

def full_result_snapshot():
    data = mon.get_data()
    if not data["latencies"]:
        messagebox.showerror("No data", "No samples collected yet.")
        return
    def _task():
        append_console("Generating full snapshot...")
        try:
            fname = save_report_html(data, prefix="full_snapshot")
            append_console(f"Full snapshot saved to {fname}")
            play_sound(winsound.MB_ICONASTERISK)  # Report Open Sound
            webbrowser.open(os.path.abspath(fname))
            AutoCloseMessageBox(root, "Full Snapshot", f"Saved to:\n{fname}", timeout=10)
        except Exception as e:
            append_console(f"Failed to save full snapshot: {e}")
            messagebox.showerror("Error", str(e))
    threading.Thread(target=_task, daemon=True).start()

full_btn.config(command=full_result_snapshot)

# ------------------- Traffic Controls -------------------
def _get_duration_seconds_from_fields():
    try:
        h = int(hours_entry.get() or 0)
        m = int(minutes_entry.get() or 0)
        s = int(seconds_entry.get() or 0)
        return max(0, h*3600 + m*60 + s)
    except Exception:
        return 0

def show_traffic_simple():
    duration = _get_duration_seconds_from_fields()
    if duration <= 0:
        messagebox.showerror("Invalid duration", "Please set a duration > 0 to run traffic sampling.")
        return

    def _task():
        traffic_stop_event.clear()
        set_ui_state(True)
        play_sound(winsound.MB_ICONASTERISK)  # Start Sound
        append_console(f"Netstat sampling for {duration}s (sampling every 1s)...")
        analyzer = NetstatAnalyzer()
        try:
            agg, pmap = analyzer.sample_timed(duration_seconds=duration, sample_interval=1, stop_event=traffic_stop_event)
        except Exception as e:
            append_console(f"netstat sampling failed: {e}")
            messagebox.showerror("Netstat error", str(e))
            set_ui_state(False)
            return
        
        set_ui_state(False)

        if not agg:
            append_console("Netstat sampling returned no data.")
            messagebox.showinfo("Traffic", "No connections found during sampling.")
            return

        try:
            # Try to fetch process names for PIDs (Windows), best-effort
            processes_map = {}
            if sys.platform.startswith("win"):
                for k, pids in pmap.items():
                    procs = []
                    for pid in pids:
                        try:
                            # call tasklist per PID (cheap if few PIDs)
                            from traffic_analysis import get_process_name_windows  # local helper
                            pname = get_process_name_windows(pid)
                        except Exception:
                            pname = "<none>"
                        procs.append(pname)
                    processes_map[k] = list(dict.fromkeys(procs))
            else:
                processes_map = None

            fname = save_traffic_report(agg, mode="netstat", prefix="traffic", info_map=pmap, processes_map=processes_map, duration=duration)
            append_console(f"Netstat traffic report saved to {fname}")
            
            # Auto-close popup
            AutoCloseMessageBox(root, "Traffic Saved", f"Saved to:\n{fname}", timeout=10)
        except Exception as e:
            append_console(f"Failed to save netstat traffic report: {e}")
            messagebox.showerror("Error", str(e))

    threading.Thread(target=_task, daemon=True).start()

def show_traffic_advanced():
    if not _HAS_SCAPY:
        messagebox.showerror("Advanced capture unavailable", "Scapy not installed or not usable.")
        return

    duration = _get_duration_seconds_from_fields()
    if duration <= 0:
        messagebox.showerror("Invalid duration", "Please set a duration > 0 to run traffic sampling.")
        return

    def _task():
        traffic_stop_event.clear()
        set_ui_state(True)
        play_sound(winsound.MB_ICONASTERISK)  # Start Sound
        append_console(f"Advanced scapy capture for {duration}s (requires privileges)...")
        try:
            sniffer = ScapySniffer()
            # capture
            counter_map, info_map, processes_map = sniffer.sample_timed(duration_seconds=duration, console_append=append_console, stop_event=traffic_stop_event)
            
            if info_map:
                append_console(f"Correlation found PIDs for {len(info_map)} remote keys.")
            else:
                append_console("No PID/process mapping found (insufficient privileges or ephemeral sockets).")
            # save report
            from traffic_analysis import save_traffic_report_html
            fname = save_traffic_report_html(counter_map, mode="scapy", prefix="traffic", info_map=info_map, processes_map=processes_map, duration=duration)
            append_console(f"Advanced traffic report saved to {fname}")
            
            # Log summary to console
            try:
                from traffic_analysis import format_traffic_summary
                summary_text = format_traffic_summary(counter_map, info_map, processes_map, mode="scapy")
                append_console(summary_text)
            except Exception as e:
                append_console(f"Error generating summary: {e}")
            
            # Open in browser
            import webbrowser
            play_sound(winsound.MB_ICONASTERISK)  # Report Open Sound
            webbrowser.open(os.path.abspath(fname))
            
            # Auto-close popup
            AutoCloseMessageBox(root, "Traffic Saved", f"Saved to:\n{fname}\n\nOpened in browser.", timeout=10)
        except Exception as e:
            append_console(f"Advanced capture failed: {e}")
            messagebox.showerror("Advanced capture error", str(e))
        finally:
            set_ui_state(False)

    threading.Thread(target=_task, daemon=True).start()

traffic_simple_btn.config(command=show_traffic_simple)
traffic_advanced_btn.config(command=show_traffic_advanced)

append_console("Application started. Ready.")
root.mainloop()
