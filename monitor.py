# monitor.py
# Robust background monitor for ping / public IP / TTL checks.
# Provides Monitor.start(duration_seconds, interval_seconds),
# Monitor.stop(), Monitor.get_data(), and a finished callback.

import threading
import time
import subprocess
import re
import requests
import traceback

PUBLIC_IP_CHECK_URL = "https://api.ipify.org"

class Monitor:
    def __init__(self, ping_target="1.1.1.1"):
        self.ping_target = ping_target
        self._thread = None
        self._stop = threading.Event()
        self._finished_callback = None  # callback when monitoring ends

        # Collected data
        self.timestamps = []
        self.latencies = []
        self.jitters = []
        self.ip_changes = []
        self.ttl_changes = []
        self.loss_events = []
        self.logs = []

        # Internal state
        self._prev_ip = None
        self._prev_ttl = None
        self._first_success = False
        self._last_status = "ok"

    # ----- log helper -----
    def _log(self, msg):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.logs.append(entry)
        if len(self.logs) > 10000:
            self.logs.pop(0)

    # ----- ping -----
    def _ping(self, timeout_secs=2):
        try:
            if subprocess.os.name == "nt":
                cmd = ["ping", "-n", "1", self.ping_target]
            else:
                cmd = ["ping", "-c", "1", self.ping_target]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_secs)
            out = proc.stdout or ""

            latency_m = re.search(r"time[=<]?([\d\.]+)ms", out, re.IGNORECASE) or \
                        re.search(r"time=([\d\.]+) ms", out, re.IGNORECASE)
            ttl_m = re.search(r"TTL[=]?(\d+)", out, re.IGNORECASE) or \
                    re.search(r"ttl=(\d+)", out, re.IGNORECASE)

            lat = float(latency_m.group(1)) if latency_m else None
            ttl = int(ttl_m.group(1)) if ttl_m else None
            return lat, ttl
        except subprocess.TimeoutExpired:
            self._log("ping timed out")
            return None, None
        except Exception as e:
            self._log(f"ping error: {e}")
            return None, None

    # ----- public IP -----
    def _get_public_ip(self, timeout_secs=3):
        try:
            r = requests.get(PUBLIC_IP_CHECK_URL, timeout=timeout_secs)
            if r.status_code == 200:
                return r.text.strip()
            else:
                self._log(f"ip check returned status {r.status_code}")
                return None
        except requests.Timeout:
            self._log("public IP request timed out")
            return None
        except Exception as e:
            self._log(f"public IP error: {e}")
            return None

    # ----- main worker -----
    def _run(self, duration, interval):
        start = time.time()
        try:
            while not self._stop.is_set():
                elapsed = time.time() - start
                if duration > 0 and elapsed >= duration:
                    break

                ip = self._get_public_ip()
                lat, ttl = self._ping(timeout_secs=min(2.0, max(0.5, interval)))

                self.timestamps.append(elapsed)

                if lat is not None and not self._first_success:
                    self._first_success = True

                if self._first_success and lat is None:
                    if self._last_status != "lost":
                        self._log("❌ Connectivity lost — possible tower handoff")
                        self.loss_events.append(elapsed)
                    self._last_status = "lost"
                else:
                    self._last_status = "ok"

                if ip and self._prev_ip and ip != self._prev_ip:
                    self._log(f"⚠ IP changed (old: {self._prev_ip}, new: {ip})")
                    self.ip_changes.append(elapsed)

                if ttl and self._prev_ttl and ttl != self._prev_ttl:
                    self._log(f"⚠ TTL changed (old: {self._prev_ttl}, new: {ttl})")
                    self.ttl_changes.append(elapsed)

                if lat is not None:
                    self.latencies.append(lat)
                    if len(self.latencies) > 1:
                        self.jitters.append(abs(self.latencies[-1] - self.latencies[-2]))

                if lat and lat > 150:
                    self._log(f"⚠ Latency spike: {lat} ms")

                self._log(f"Status | Public IP: {ip} | Latency: {lat} ms | TTL: {ttl}")

                self._prev_ip = ip
                self._prev_ttl = ttl

                stop_until = time.time() + interval
                while time.time() < stop_until and not self._stop.is_set():
                    time.sleep(0.05)

        except Exception as e:
            self._log("Monitor thread exception: " + str(e))
            self._log(traceback.format_exc())
        finally:
            self._log("▶ Monitoring finished")
            # call finished callback
            if callable(self._finished_callback):
                try:
                    self._finished_callback()
                except Exception as e:
                    self._log(f"Finished callback error: {e}")

    # ----- public API -----
    def start(self, duration_seconds=3600, interval_seconds=0.5):
        if self._thread and self._thread.is_alive():
            return False
        self._stop.clear()

        self.timestamps.clear()
        self.latencies.clear()
        self.jitters.clear()
        self.ip_changes.clear()
        self.ttl_changes.clear()
        self.loss_events.clear()
        self.logs.clear()

        self._prev_ip = None
        self._prev_ttl = None
        self._first_success = False
        self._last_status = "ok"

        self._thread = threading.Thread(
            target=self._run,
            args=(duration_seconds, interval_seconds),
            daemon=True
        )
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        return True

    def is_running(self):
        return self._thread and self._thread.is_alive()

    def get_data(self):
        return {
            "timestamps": list(self.timestamps),
            "latencies": list(self.latencies),
            "jitters": list(self.jitters),
            "ip_changes": list(self.ip_changes),
            "ttl_changes": list(self.ttl_changes),
            "loss_events": list(self.loss_events),
            "logs": list(self.logs),
        }
