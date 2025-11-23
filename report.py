# report.py
# Latency + jitter report generator (PNG).

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from utils import ensure_results_dir, timestamp_str
import os

def format_text_report(data):
    lat = data.get("latencies", [])
    logs = data.get("logs", [])
    avg = sum(lat)/len(lat) if lat else 0
    mx = max(lat) if lat else 0
    spikes = sum(1 for x in lat if x>150)
    return (
        f"Total log entries: {len(logs)}\n"
        f"Samples: {len(lat)}\n"
        f"Average latency: {avg:.2f} ms\n"
        f"Max latency: {mx} ms\n"
        f"Latency spikes (>150 ms): {spikes}\n"
        f"IP changes: {len(data.get('ip_changes',[]))}\n"
        f"TTL changes: {len(data.get('ttl_changes',[]))}\n"
        f"Connectivity losses: {len(data.get('loss_events',[]))}\n"
    )

def save_report_png(data, prefix="result"):
    ensure_results_dir()
    ts = timestamp_str()
    filename = os.path.join("results", f"{prefix}-{ts}.png")

    t = data.get("timestamps", [])
    lat = data.get("latencies", [])
    jit = data.get("jitters", [])
    ip_changes = data.get("ip_changes", [])
    ttl_changes = data.get("ttl_changes", [])
    loss_events = data.get("loss_events", [])
    report_text = format_text_report(data)

    fig = plt.figure(figsize=(10,14))
    gs = fig.add_gridspec(7,1)

    # LATENCY TIMELINE
    ax_latency = fig.add_subplot(gs[0:2,0])
    colors = ['green' if l<80 else 'orange' if l<150 else 'red' for l in lat]
    ax_latency.scatter(t[:len(lat)], lat, c=colors, s=8)
    ax_latency.set_title("Latency Timeline")
    ax_latency.set_ylabel("Latency (ms)")
    ax_latency.set_xlabel("Time (s)")

    for tt in ip_changes:
        ax_latency.axvline(tt, color="purple", linestyle="--", linewidth=1)
    for tt in ttl_changes:
        ax_latency.axvline(tt, color="blue", linestyle="--", linewidth=1)
    for tt in loss_events:
        ax_latency.axvline(tt, color="brown", linestyle="--", linewidth=1)

    # HISTOGRAM
    ax_hist = fig.add_subplot(gs[2,0])
    ax_hist.hist(lat, bins=40, color='skyblue', edgecolor='black')
    ax_hist.set_title("Latency Histogram")
    ax_hist.set_xlabel("Latency (ms)")
    ax_hist.set_ylabel("Count")

    # JITTER TIMELINE
    ax_jitter = fig.add_subplot(gs[3,0])
    if jit:
        x_j = t[1:len(jit)+1] if len(jit)+1 <= len(t) else t
        ax_jitter.plot(x_j, jit)
    ax_jitter.set_title("Jitter Timeline")
    ax_jitter.set_xlabel("Time (s)")
    ax_jitter.set_ylabel("Jitter (ms)")

    # LEGEND
    ax_legend = fig.add_subplot(gs[4,0])
    ax_legend.axis('off')
    patches = [
        mpatches.Patch(color='green', label='0–80 ms'),
        mpatches.Patch(color='orange', label='80–150 ms'),
        mpatches.Patch(color='red', label='>150 ms'),
        mpatches.Patch(color='purple', label='IP change'),
        mpatches.Patch(color='blue', label='TTL change'),
        mpatches.Patch(color='brown', label='Connectivity lost'),
    ]
    ax_legend.legend(handles=patches, loc='center', ncol=3, fontsize=9)

    # TEXT REPORT
    ax_report = fig.add_subplot(gs[5:7,0])
    ax_report.axis('off')
    combined_text = "Jitter Explanation:\nJitter = |current latency − previous latency|\n\nTest Report:\n" + report_text
    ax_report.text(0,1, combined_text, fontsize=9, va='top', ha='left', wrap=True, multialignment='left')

    fig.tight_layout(pad=3)
    fig.savefig(filename, bbox_inches='tight')
    plt.close(fig)
    return filename

import io
import base64

def save_report_html(data, prefix="result"):
    """Generate an HTML report with embedded images."""
    ensure_results_dir()
    ts = timestamp_str()
    filename = os.path.join("results", f"{prefix}-{ts}.html")

    t = data.get("timestamps", [])
    lat = data.get("latencies", [])
    jit = data.get("jitters", [])
    ip_changes = data.get("ip_changes", [])
    ttl_changes = data.get("ttl_changes", [])
    loss_events = data.get("loss_events", [])
    report_text = format_text_report(data)

    # Helper to create base64 image
    def fig_to_base64(fig):
        buf = io.BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        return base64.b64encode(buf.read()).decode('utf-8')

    # 1. Latency Timeline
    fig1 = plt.figure(figsize=(10, 4))
    colors = ['green' if l<80 else 'orange' if l<150 else 'red' for l in lat]
    plt.scatter(t[:len(lat)], lat, c=colors, s=8)
    plt.title("Latency Timeline")
    plt.ylabel("Latency (ms)")
    plt.xlabel("Time (s)")
    for tt in ip_changes: plt.axvline(tt, color="purple", linestyle="--", linewidth=1)
    for tt in ttl_changes: plt.axvline(tt, color="blue", linestyle="--", linewidth=1)
    for tt in loss_events: plt.axvline(tt, color="brown", linestyle="--", linewidth=1)
    img_latency = fig_to_base64(fig1)
    plt.close(fig1)

    # 2. Histogram
    fig2 = plt.figure(figsize=(6, 4))
    plt.hist(lat, bins=40, color='skyblue', edgecolor='black')
    plt.title("Latency Histogram")
    plt.xlabel("Latency (ms)")
    plt.ylabel("Count")
    img_hist = fig_to_base64(fig2)
    plt.close(fig2)

    # 3. Jitter
    fig3 = plt.figure(figsize=(10, 3))
    if jit:
        x_j = t[1:len(jit)+1] if len(jit)+1 <= len(t) else t
        plt.plot(x_j, jit)
    plt.title("Jitter Timeline")
    plt.xlabel("Time (s)")
    plt.ylabel("Jitter (ms)")
    img_jitter = fig_to_base64(fig3)
    plt.close(fig3)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Monitor Report - {ts}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; background: #f4f4f4; }}
        .container {{ max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        pre {{ background: #eee; padding: 10px; border-radius: 5px; }}
        .chart {{ margin-bottom: 20px; text-align: center; }}
        img {{ max-width: 100%; height: auto; border: 1px solid #ddd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Monitoring Report</h1>
        <p><strong>Timestamp:</strong> {ts}</p>
        
        <h2>Statistics</h2>
        <pre>{report_text}</pre>
        
        <h2>Latency Timeline</h2>
        <div class="chart"><img src="data:image/png;base64,{img_latency}" /></div>
        
        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 300px;">
                <h2>Latency Distribution</h2>
                <div class="chart"><img src="data:image/png;base64,{img_hist}" /></div>
            </div>
            <div style="flex: 1; min-width: 300px;">
                <h2>Jitter</h2>
                <div class="chart"><img src="data:image/png;base64,{img_jitter}" /></div>
            </div>
        </div>
    </div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename
