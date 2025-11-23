# utils.py
import os
from datetime import datetime
import socket

RESULTS_DIR = "results"

def ensure_results_dir():
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    return RESULTS_DIR

def timestamp_str():
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def safe_reverse_dns(ip):
    """Try reverse DNS, fallback to IP."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ip
