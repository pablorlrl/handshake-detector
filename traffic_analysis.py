# traffic_analysis.py
import subprocess
import sys
import time
import re
from collections import Counter, defaultdict
import socket
import os
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from utils import ensure_results_dir, timestamp_str
from datetime import datetime
import ctypes
from ctypes import wintypes

# ctypes constants and structures
NO_ERROR = 0
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong)
    ]

class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong)
    ]

def get_tcp_table_ctypes():
    """Get TCP table using GetExtendedTcpTable (Windows)."""
    table = []
    if not sys.platform.startswith("win"):
        return table
        
    try:
        GetExtendedTcpTable = ctypes.windll.iphlpapi.GetExtendedTcpTable
        GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        GetExtendedTcpTable.restype = ctypes.c_ulong
        
        size = ctypes.c_ulong(0)
        # First call to get size
        GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        
        buf = ctypes.create_string_buffer(size.value)
        if GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR:
            # Parse buffer manually to avoid defining variable sized structure
            # DWORD dwNumEntries
            # MIB_TCPROW_OWNER_PID table[ANY_SIZE]
            num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong))[0]
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            offset = ctypes.sizeof(ctypes.c_ulong)
            
            for _ in range(num_entries):
                row = MIB_TCPROW_OWNER_PID.from_buffer(buf, offset)
                table.append((row.dwState, row.dwLocalAddr, row.dwLocalPort, row.dwRemoteAddr, row.dwRemotePort, row.dwOwningPid))
                offset += row_size
    except Exception:
        pass
    return table

def get_udp_table_ctypes():
    """Get UDP table using GetExtendedUdpTable (Windows)."""
    table = []
    if not sys.platform.startswith("win"):
        return table
        
    try:
        GetExtendedUdpTable = ctypes.windll.iphlpapi.GetExtendedUdpTable
        GetExtendedUdpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        GetExtendedUdpTable.restype = ctypes.c_ulong
        
        size = ctypes.c_ulong(0)
        GetExtendedUdpTable(None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
        
        buf = ctypes.create_string_buffer(size.value)
        if GetExtendedUdpTable(buf, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR:
            num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong))[0]
            row_size = ctypes.sizeof(MIB_UDPROW_OWNER_PID)
            offset = ctypes.sizeof(ctypes.c_ulong)
            
            for _ in range(num_entries):
                row = MIB_UDPROW_OWNER_PID.from_buffer(buf, offset)
                table.append((row.dwLocalAddr, row.dwLocalPort, row.dwOwningPid))
                offset += row_size
    except Exception:
        pass
    return table

def ip_to_str(val):
    return socket.inet_ntoa(ctypes.c_ulong(val).value.to_bytes(4, 'little'))

def port_to_int(val):
    return socket.ntohs(val)

# Optional Scapy support
_HAS_SCAPY = False
try:
    from scapy.all import sniff, IP, TCP, UDP
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

# ------------------ Utilities ------------------
try:
    import psutil
except ImportError:
    psutil = None

def safe_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

def get_process_info_windows(pid):
    """Return process name for a PID (Windows) using tasklist CSV output."""
    try:
        out = subprocess.check_output(
            f'tasklist /FI "PID eq {int(pid)}" /FO CSV',
            shell=True, text=True, stderr=subprocess.DEVNULL
        )
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if len(lines) >= 2:
            reader = csv.reader(lines)
            next(reader)
            row = next(reader)
            return row[0]
    except Exception:
        pass
    return "<none>"

def get_process_map_psutil():
    """Return {ip: process_name} and {ip: [pid]} using psutil."""
    ip_proc = {}
    ip_pids = defaultdict(list)
    if not psutil:
        return ip_proc, ip_pids
        
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.raddr and c.pid:
                ip = c.raddr.ip
                try:
                    proc = psutil.Process(c.pid)
                    ip_proc[ip] = proc.name()
                    ip_pids[ip].append(str(c.pid))
                except:
                    pass
    except Exception:
        pass
    return ip_proc, ip_pids

# ------------------ Process Cache ------------------
class ProcessNameCache:
    def __init__(self, ttl=60):
        self.cache = {} # pid -> (name, timestamp)
        self.ttl = ttl
        
    def get(self, pid):
        now = time.time()
        if pid in self.cache:
            name, ts = self.cache[pid]
            if now - ts < self.ttl:
                return name
        return None
        
    def set(self, pid, name):
        self.cache[pid] = (name, time.time())
        
    def resolve(self, pid):
        # 1. Check cache
        cached = self.get(pid)
        if cached:
            return cached
            
        # 2. System PIDs
        if pid == 0:
            name = "Idle"
            self.set(pid, name)
            return name
        if pid == 4 and sys.platform.startswith("win"):
            name = "System"
            self.set(pid, name)
            return name
            
        # 3. Resolve via psutil
        try:
            if psutil:
                proc = psutil.Process(pid)
                name = proc.name()
                self.set(pid, name)
                return name
        except Exception:
            pass
            
        # 4. Fallback (Windows tasklist - slow, avoid if possible, or maybe we already have it?)
        return None

_proc_cache = ProcessNameCache(ttl=60)

# ------------------ IP Process Cache ------------------
class IpProcessCache:
    """Cache to remember which process was last seen on a remote IP."""
    def __init__(self, ttl=60):
        self.cache = {} # ip -> (process_name, timestamp)
        self.ttl = ttl
        
    def update(self, ip, name):
        if name and name not in ("<none>", "<unknown>", ""):
            self.cache[ip] = (name, time.time())
            
    def get(self, ip):
        if ip in self.cache:
            name, ts = self.cache[ip]
            if time.time() - ts < self.ttl:
                return name
        return None

_ip_cache = IpProcessCache(ttl=60)

def get_process_map_combined():
    """Return {ip: process_name} and {ip: [pid]} using both psutil and ctypes (Windows)."""
    # 1. Start with psutil (fast, accurate names)
    ip_proc, ip_pids = get_process_map_psutil()
    
    # 2. If Windows, augment with ctypes (much faster than netstat subprocess)
    if sys.platform.startswith("win"):
        try:
            # TCP
            tcp_rows = get_tcp_table_ctypes()
            for state, local_addr, local_port, remote_addr, remote_port, pid in tcp_rows:
                # Filter states if needed, but we want most
                # MIB_TCP_STATE_ESTAB = 5, etc.
                # Just take all for now to be safe, or filter 0 (CLOSED)
                if state != 0 and remote_addr != 0:
                    remote_ip = ip_to_str(remote_addr)
                    # remote_port_val = port_to_int(remote_port) # Not strictly needed for key if we use IP only, but usually we key by IP
                    # Wait, our keys are IPs? Or IP:Port?
                    # Previous code used IP as key if psutil, but netstat parsing used IP:Port?
                    # psutil: ip_proc[ip] = name. IP is just string.
                    # netstat: regex parsed foreign as IP:Port.
                    # Let's standardize on IP string for now to match psutil, OR handle both.
                    # If we use IP only, we might have collisions.
                    # The existing code seems to mix. psutil uses `c.raddr.ip`.
                    # Let's stick to IP string for consistency with psutil map.
                    
                    if pid > 0:
                        pid_str = str(pid)
                        if pid_str not in ip_pids[remote_ip]:
                            ip_pids[remote_ip].append(pid_str)
                        
                        if remote_ip not in ip_proc or ip_proc[remote_ip] in ("<none>", ""):
                            name = _proc_cache.resolve(pid)
                            if name:
                                ip_proc[remote_ip] = name

            # UDP
            udp_rows = get_udp_table_ctypes()
            # UDP table doesn't have remote address in the owner-pid table!
            # It only has local address. 
            # This is a limitation of GetExtendedUdpTable. It binds local port to PID.
            # But we need to map REMOTE IP to PID.
            # If we are a client, we have a local port.
            # Scapy sees the packet (SrcIP, DstIP).
            # If we are sending to RemoteIP, we use LocalPort.
            # We can map LocalPort -> PID.
            # Then Scapy can look up PID by LocalPort?
            # But get_process_map_combined is supposed to return {RemoteIP: PID}.
            # Without remote IP in UDP table, we can't map RemoteIP -> PID directly from this table alone.
            # However, `netstat -ano` ALSO doesn't show remote IP for UDP usually (*:*).
            # So `netstat` parsing for UDP was likely only working if it showed the remote IP, which is rare for connected UDP.
            # Wait, `psutil` DOES give remote IP for connected UDP.
            # For unconnected UDP (common), we can't map RemoteIP -> PID easily without inspecting packets + local port.
            # BUT, if we have a "connected" UDP socket, psutil should catch it.
            # If `netstat` showed it, it means it was connected?
            # Actually, `netstat` output for UDP is often `UDP 0.0.0.0:123 *:* 1234`. No remote.
            # So my previous fix for netstat UDP might have been parsing `*:*` as foreign and adding it?
            # If foreign is `*:*`, it's useless for map {RemoteIP: PID}.
            # So `ctypes` here is fine, it just confirms we can't get RemoteIP from standard UDP table.
            # We will rely on psutil for connected UDP.
            pass

        except Exception:
            pass
            
    # Update IP Cache
    for ip, name in ip_proc.items():
        _ip_cache.update(ip, name)
        
    return ip_proc, ip_pids

def get_local_ips():
    """Return a set of local IP addresses."""
    ips = set()
    try:
        # psutil is preferred
        if psutil:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ips.add(addr.address)
        else:
            # fallback
            ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return ips

# ------------------ Netstat Analyzer ------------------
class NetstatAnalyzer:
    """Timed netstat sampling with PID and process mapping."""

    _win_regex = re.compile(r'^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$', re.IGNORECASE)

    def _parse_windows(self, raw):
        c = Counter()
        pids_map = defaultdict(list)
        processes_map = defaultdict(list)

        for line in raw.splitlines():
            m = self._win_regex.match(line)
            if not m:
                continue
            proto, local, foreign, state, pid = m.groups()
            if state.upper() in ("ESTABLISHED", "ESTAB", "SYN_SENT", "SYN_RECEIVED"):
                key = foreign
                c[key] += 1
                pids_map[key].append(pid)
                proc_name = get_process_info_windows(pid)
                processes_map[key].append(proc_name)

        for r in list(pids_map.keys()):
            pids_map[r] = list(dict.fromkeys(pids_map[r]))
            processes_map[r] = list(dict.fromkeys(processes_map[r]))

        return c, pids_map, processes_map

    def _parse_unix(self, raw):
        c = Counter()
        pids_map = defaultdict(list)
        processes_map = defaultdict(list)
        for line in raw.splitlines():
            parts = line.split()
            for token in reversed(parts):
                if ':' in token and any(ch.isdigit() for ch in token):
                    remote = token
                    c[remote] += 1
                    break
        return c, pids_map, processes_map

    def sample_once(self):
        try:
            if sys.platform.startswith("win"):
                out = subprocess.check_output("netstat -ano", shell=True, text=True, stderr=subprocess.DEVNULL)
                return self._parse_windows(out)
            else:
                try:
                    out = subprocess.check_output("ss -ntp", shell=True, text=True, stderr=subprocess.DEVNULL)
                except Exception:
                    out = subprocess.check_output("netstat -ntp", shell=True, text=True, stderr=subprocess.DEVNULL)
                return self._parse_unix(out)
        except Exception:
            return Counter(), defaultdict(list), defaultdict(list)

    def sample_timed(self, duration_seconds, sample_interval=1, console_append=None):
        total_counter = Counter()
        total_pids = defaultdict(list)
        total_procs = defaultdict(list)

        end_at = time.time() + max(0, duration_seconds)
        if duration_seconds <= 0:
            return self.sample_once()

        while time.time() < end_at:
            if console_append:
                console_append(f"[{datetime.now().strftime('%H:%M:%S')}] Sampling netstat...")
            c, pmap, procs = self.sample_once()
            total_counter.update(c)
            for k, v in pmap.items():
                total_pids[k].extend(v)
            for k, v in procs.items():
                total_procs[k].extend(v)
            wait_until = time.time() + sample_interval
            while time.time() < wait_until:
                time.sleep(0.05)

        for r in list(total_pids.keys()):
            total_pids[r] = list(dict.fromkeys(str(x) for x in total_pids[r]))
            total_procs[r] = list(dict.fromkeys(total_procs[r]))

        return total_counter, total_pids, total_procs

# ------------------ Scapy Sniffer ------------------
class ScapySniffer:
    """Advanced scapy sniffer (packets count / bytes only)."""
    def __init__(self, iface=None):
        if not _HAS_SCAPY:
            raise RuntimeError("scapy not available")
        self.iface = iface

    def sample_timed(self, duration_seconds, console_append=None):
        counter = {}
        start_time = time.time()
        if console_append:
            console_append(f"Starting packet capture...")
            
        local_ips = get_local_ips()
        if console_append:
            console_append(f"Local IPs identified: {local_ips}")

        # Continuous Process Sampling
        import threading
        stop_sampling = threading.Event()
        collected_snapshots = []

        def _background_sampler():
            while not stop_sampling.is_set():
                try:
                    collected_snapshots.append(get_process_map_combined())
                except Exception:
                    pass
                stop_sampling.wait(0.1) # Sample every 0.1s (was 0.5s)

        sampler_thread = threading.Thread(target=_background_sampler, daemon=True)
        sampler_thread.start()

        # Snapshot 1: Before capture (explicit)
        if console_append:
            console_append(f"Taking pre-capture process snapshot...")
        pre_proc_map, pre_pids_map = get_process_map_combined()

        def pkt_cb(pkt):
            try:
                if IP in pkt and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    length = len(pkt)
                    
                    # Determine remote endpoint
                    remote = None
                    if src in local_ips and dst not in local_ips:
                        remote = dst # Upload
                    elif dst in local_ips and src not in local_ips:
                        remote = src # Download
                    elif dst not in local_ips and src not in local_ips:
                        remote = dst # Transit?
                    
                    if remote:
                        counter[remote] = counter.get(remote, 0) + length
            except Exception:
                pass

        sniff(count=0, prn=pkt_cb, timeout=duration_seconds, iface=self.iface)

        # Stop sampler
        stop_sampling.set()
        sampler_thread.join(timeout=1.0)

        if console_append:
            console_append(f"Captured {len(counter)} unique remote keys.")

        # Snapshot 2: After capture
        if console_append:
            console_append(f"Taking post-capture process snapshot...")
        
        post_proc_map, post_pids_map = get_process_map_combined()
        
        # Merge ALL snapshots
        # Start with pre, then merge all background samples, then post
        all_proc_maps = [pre_proc_map] + [s[0] for s in collected_snapshots] + [post_proc_map]
        all_pids_maps = [pre_pids_map] + [s[1] for s in collected_snapshots] + [post_pids_map]

        ip_proc_map = {}
        for m in all_proc_maps:
            ip_proc_map.update(m) # Later snapshots overwrite earlier ones (usually fine, or we could collect all unique names)
        
        # Merge PIDs lists
        ip_pids_map = defaultdict(list)
        for m in all_pids_maps:
            for k, v in m.items():
                ip_pids_map[k].extend(v)

        # Deduplicate PIDs
        for k in ip_pids_map:
            ip_pids_map[k] = list(set(ip_pids_map[k]))
        
        pids_map = defaultdict(list)
        procs_map = defaultdict(list)
        
        matched_any = False
        for dst in list(counter.keys()):
            # 1. Direct Map
            if dst in ip_proc_map:
                matched_any = True
                procs_map[dst].append(ip_proc_map[dst])
            # 2. Fallback to IP Cache
            else:
                cached_name = _ip_cache.get(dst)
                if cached_name:
                    matched_any = True
                    procs_map[dst].append(cached_name)
                    # Also try to backfill PID if possible? (Hard without PID in cache, maybe add PID to cache too?)
                    # For now just name is good.
            
            if dst in ip_pids_map:
                pids_map[dst].extend(ip_pids_map[dst])
                
        if not matched_any and console_append:
            console_append(f"No PID/process mapping found (insufficient privileges or ephemeral sockets).")

        return counter, pids_map, procs_map

# ------------------ Traffic Report ------------------
def save_traffic_report(counter_map,
                        mode="netstat",
                        prefix="traffic",
                        info_map=None,
                        processes_map=None,
                        top_n=20,
                        duration=None):
    ensure_results_dir()
    ts = timestamp_str()
    filename = os.path.join("results", f"{prefix}-{mode}-{ts}.png")

    total = sum(counter_map.values())
    top = sorted(counter_map.items(), key=lambda x: x[1], reverse=True)[:top_n]
    labels = [k for k, _ in top]
    values = [v for _, v in top]

    fig = plt.figure(figsize=(12, 8))
    gs = fig.add_gridspec(6, 1)

    ax_bar = fig.add_subplot(gs[0:3, 0])
    y_pos = list(range(len(labels)))[::-1]
    ax_bar.barh(y_pos, values, edgecolor='black')
    ax_bar.set_yticks(y_pos)
    ax_bar.set_yticklabels(labels)
    ax_bar.set_title(f"Top {len(labels)} remote endpoints ({mode})")
    ax_bar.set_xlabel("Connections / Bytes (aggregated)")

    ax_table = fig.add_subplot(gs[3:5, 0])
    ax_table.axis('off')
    table_data = []
    for i, (label, val) in enumerate(top):
        try:
            ip_part = (label.split(':')[0] if ':' in label else label)
        except Exception:
            ip_part = label
        rev = safe_reverse_dns(ip_part)
        pids = ", ".join(info_map.get(label, [])) if info_map else "<none>"
        procs = ", ".join(processes_map.get(label, [])) if processes_map else "<none>"
        table_data.append([str(i+1), label, rev, pids or "<none>", procs or "<none>", str(val)])

    col_labels = ["#", "Remote", "Reverse", "PIDs", "Processes", "Count"]
    table = ax_table.table(cellText=table_data, colLabels=col_labels, loc='center', cellLoc='left')
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.2)
    table.auto_set_column_width([0, 1, 2])

    ax_text = fig.add_subplot(gs[5, 0])
    ax_text.axis('off')
    summary = (
        f"Mode: {mode}\n"
        f"Duration: {duration}s\n" if duration else f"Mode: {mode}\n"
        f"Total unique endpoints: {len(counter_map)}\n"
        f"Total aggregated value: {total}\n"
        f"Top entry: {top[0][0] if top else 'N/A'} -> {top[0][1] if top else 0}"
    )
    ax_text.text(0, 0.8, summary, fontsize=10, va='top', ha='left')

    fig.tight_layout(pad=2)
    fig.savefig(filename, bbox_inches='tight')
    plt.close(fig)
    return filename

def format_traffic_summary(counter_map, info_map=None, processes_map=None, top_n=10):
    """Generate a text summary of the traffic analysis with dynamic column widths."""
    
    # Prepare data rows
    rows = []
    top = sorted(counter_map.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    for ip, val in top:
        proc = "<unknown>"
        if processes_map and ip in processes_map:
            proc = ",".join(processes_map[ip])
        elif info_map and ip in info_map:
             proc = f"PID:{','.join(info_map[ip])}"
        rows.append((str(ip), str(val), str(proc)))

    # Calculate max widths (min width is header length)
    w_ip = max([len(r[0]) for r in rows] + [len("Remote IP")]) + 2
    w_val = max([len(r[1]) for r in rows] + [len("Count/Bytes")]) + 2
    w_proc = max([len(r[2]) for r in rows] + [len("Process")]) + 2
    
    total_width = w_ip + w_val + w_proc + 6 # +6 for separators

    lines = []
    lines.append(f"--- Traffic Analysis Summary (Top {top_n}) ---")
    lines.append(f"Total unique endpoints: {len(counter_map)}")
    lines.append(f"Total aggregated value: {sum(counter_map.values())}")
    lines.append("-" * total_width)
    
    # Header
    lines.append(f"{'Remote IP':<{w_ip}} | {'Count/Bytes':<{w_val}} | {'Process':<{w_proc}}")
    lines.append("-" * total_width)
    
    # Rows
    for ip, val, proc in rows:
        lines.append(f"{ip:<{w_ip}} | {val:<{w_val}} | {proc:<{w_proc}}")
    
    lines.append("-" * total_width)
    return "\n".join(lines)

def save_traffic_report_html(counter_map, mode="netstat", prefix="traffic", info_map=None, processes_map=None, top_n=50, duration=None):
    """Generate an HTML traffic report."""
    ensure_results_dir()
    ts = timestamp_str()
    filename = os.path.join("results", f"{prefix}-{mode}-{ts}.html")
    
    total = sum(counter_map.values())
    top = sorted(counter_map.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    # Parallel Reverse DNS
    import concurrent.futures
    ip_to_dns = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # Helper to extract IP part if port is present
        def _resolve(full_ip):
            try:
                ip_part = (full_ip.split(':')[0] if ':' in full_ip else full_ip)
            except:
                ip_part = full_ip
            return safe_reverse_dns(ip_part)

        future_to_ip = {executor.submit(_resolve, ip): ip for ip, _ in top}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ip_to_dns[ip] = future.result()
            except Exception:
                ip_to_dns[ip] = ip

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Traffic Analysis Report - {ts}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f9f9f9; }}
        h1 {{ color: #333; }}
        .summary {{ margin-bottom: 20px; padding: 15px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ border-collapse: collapse; width: 100%; background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007bff; color: white; font-weight: 600; text-transform: uppercase; font-size: 0.85rem; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        tr:hover {{ background-color: #e9ecef; }}
        .val {{ font-family: monospace; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Traffic Analysis Report ({mode})</h1>
    <div class="summary">
        <p><strong>Timestamp:</strong> {ts}</p>
        <p><strong>Duration:</strong> {duration}s</p>
        <p><strong>Total Unique Endpoints:</strong> {len(counter_map)}</p>
        <p><strong>Total Aggregated Value:</strong> {total}</p>
    </div>
    
    <h2>Top {len(top)} Remote Endpoints</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Remote IP</th>
                <th>Reverse DNS</th>
                <th>PIDs</th>
                <th>Process</th>
                <th>Count/Bytes</th>
            </tr>
        </thead>
        <tbody>
"""
    
    for i, (ip, val) in enumerate(top):
        rev = ip_to_dns.get(ip, ip)
        pids = ", ".join(info_map.get(ip, [])) if info_map else ""
        procs = ", ".join(processes_map.get(ip, [])) if processes_map else ""
        
        html_content += f"""            <tr>
                <td>{i+1}</td>
                <td>{ip}</td>
                <td>{rev}</td>
                <td>{pids}</td>
                <td>{procs}</td>
                <td class="val">{val}</td>
            </tr>
"""
        
    html_content += """        </tbody>
    </table>
</body>
</html>
"""
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return filename
