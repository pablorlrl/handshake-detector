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
# ------------------- Auto-Close Popup -------------------
class AutoCloseMessageBox(tk.Toplevel):
    def __init__(self, parent, title, message, timeout=10):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x180")
        self.resizable(False, False)
        
        # Center relative to parent
        try:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - 200
            y = parent.winfo_y() + (parent.winfo_height() // 2) - 90
            self.geometry(f"+{x}+{y}")
        except:
            pass
        
        self.timeout = timeout
        self.remaining = timeout
        self.cancelled = False
        
        # UI
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text=message, wraplength=360, justify="center").pack(pady=(0, 15))
        
        self.progress = ttk.Progressbar(frame, maximum=timeout, value=timeout, length=300)
        self.progress.pack(pady=(0, 10))
        
        self.lbl_timer = ttk.Label(frame, text=f"Auto-closing in {timeout}s...")
        self.lbl_timer.pack(pady=(0, 10))
        
        ttk.Button(frame, text="Close Now", command=self.close).pack()
        
        # Start timer
        self.after(1000, self._tick)
        
        # Handle X button
        self.protocol("WM_DELETE_WINDOW", self.close)
        
    def _tick(self):
        if self.cancelled:
            return
            
        self.remaining -= 1
        self.progress['value'] = self.remaining
        self.lbl_timer.config(text=f"Auto-closing in {self.remaining}s...")
        
        if self.remaining <= 0:
            self.destroy()
        else:
            self.after(1000, self._tick)
            
    def close(self):
        self.cancelled = True
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
    data = mon.get_data()
    if data["latencies"]:
        def _task():
            append_console("Generating final result snapshot...")
            try:
                fname = save_report_html(data, prefix="result")
                append_console(f"Final result saved to {fname}")
                webbrowser.open(os.path.abspath(fname))
            except Exception as e:
                append_console(f"Failed to save final result: {e}")
        threading.Thread(target=_task, daemon=True).start()

mon._finished_callback = on_monitor_finished

# ------------------- Monitor Controls -------------------
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
    append_console(f"Monitoring started for {h}h {m}m {s}s (interval {interval}s)" if started else "Monitor already running")

def stop_test():
    mon.stop()
    append_console("Monitoring stopped by user")

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
            webbrowser.open(os.path.abspath(fname))
            messagebox.showinfo("Partial Saved", f"Saved to:\n{fname}")
        except Exception as e:
            append_console(f"Failed to save partial snapshot: {e}")
            messagebox.showerror("Error", str(e))
    threading.Thread(target=_task, daemon=True).start()

def full_result_snapshot():
    data = mon.get_data()
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
        append_console(f"Netstat sampling for {duration}s (sampling every 1s)...")
        analyzer = NetstatAnalyzer()
        try:
            agg, pmap = analyzer.sample_timed(duration_seconds=duration, sample_interval=1)
        except Exception as e:
            append_console(f"netstat sampling failed: {e}")
            messagebox.showerror("Netstat error", str(e))
            return

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
            AutoCloseMessageBox(root, "Traffic Saved", f"Saved to:\n{fname}\n\n(Auto-closing in 10s)", timeout=10)
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
        append_console(f"Advanced scapy capture for {duration}s (requires privileges)...")
        try:
            sniffer = ScapySniffer()
            # capture
            counter_map, info_map, processes_map = sniffer.sample_timed(duration_seconds=duration, console_append=append_console)
            
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
                summary_text = format_traffic_summary(counter_map, info_map, processes_map)
                append_console(summary_text)
            except Exception as e:
                append_console(f"Error generating summary: {e}")
            
            # Open in browser
            import webbrowser
            webbrowser.open(os.path.abspath(fname))
            
            # Auto-close popup
            AutoCloseMessageBox(root, "Traffic Saved", f"Saved to:\n{fname}\n\nOpened in browser.\n(Auto-closing in 10s)", timeout=10)
        except Exception as e:
            append_console(f"Advanced capture failed: {e}")
            messagebox.showerror("Advanced capture error", str(e))

    threading.Thread(target=_task, daemon=True).start()

traffic_simple_btn.config(command=show_traffic_simple)
traffic_advanced_btn.config(command=show_traffic_advanced)

append_console("Application started. Ready.")
root.mainloop()
