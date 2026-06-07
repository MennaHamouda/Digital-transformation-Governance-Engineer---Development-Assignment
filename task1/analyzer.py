
#Advanced Network Log Analyzer

import os
import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec


# 1. PARSE ALL LOG FILES

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "network_report.csv")
OUTPUT_CHART = os.path.join(os.path.dirname(__file__), "network_chart.png")

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>R\d+)\s+"
    r"(?P<level>INFO|WARNING|ERROR|DEBUG|CRITICAL)\s+"
    r"(?P<message>.+)$"
)

def classify_event(message):
    """Return (event_type, key_detail) from a log message."""
    msg = message.strip()

    # Interface events
    m = re.search(r"Interface\s+([\w/]+)\s+(.+)", msg)
    if m:
        iface = m.group(1)
        action = m.group(2).strip()
        if "input errors" in action:
            return "Interface Error", f"{iface}: input errors"
        elif "changed state to down" in action:
            return "Interface Flap", f"{iface}: went down"
        elif "changed state to up" in action:
            return "Interface Flap", f"{iface}: came up"
        elif "line protocol is down" in action:
            return "Interface Flap", f"{iface}: protocol down"
        elif "line protocol is up" in action:
            return "Interface Flap", f"{iface}: protocol up"
        return "Interface", f"{iface}: {action}"

    # BGP events
    m = re.search(r"BGP neighbor ([\d\.]+) (established|went down)", msg)
    if m:
        neighbor = m.group(1)
        state = m.group(2)
        return "BGP Flap", f"neighbor {neighbor} {state}"

    # CPU events
    m = re.search(r"CPU utilization exceeded (\d+)%", msg)
    if m:
        pct = int(m.group(1))
        return "CPU High", f"CPU at {pct}%"
    if "CPU utilization returned to normal" in msg:
        return "CPU Normal", "CPU returned to normal"

    # Temperature events
    m = re.search(r"Temperature sensor (\d+) exceeded threshold", msg)
    if m:
        return "Temperature High", f"Sensor {m.group(1)} over threshold"
    if "Temperature sensor" in msg and "returned to normal" in msg:
        return "Temperature Normal", "Temperature normalized"

    # SNMP events
    m = re.search(r"SNMP authentication failure from ([\d\.]+)", msg)
    if m:
        return "SNMP Auth Failure", f"from {m.group(1)}"

    return "Other", msg[:60]


def parse_logs(log_dir):
    """Parse all .log files and return list of event dicts."""
    events = []
    for fname in sorted(os.listdir(log_dir)):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(log_dir, fname)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                m = LOG_PATTERN.match(line)
                if not m:
                    continue
                ts = datetime.strptime(m.group("timestamp"), "%Y-%m-%d %H:%M:%S")
                device = m.group("device")
                level = m.group("level")
                message = m.group("message")
                event_type, key_detail = classify_event(message)
                events.append({
                    "timestamp": ts,
                    "device": device,
                    "level": level,
                    "event_type": event_type,
                    "key_detail": key_detail,
                    "raw": message,
                })
    return sorted(events, key=lambda e: e["timestamp"])




# 2. DETECT ANOMALIES

def detect_interface_flaps(events, window_minutes=10, threshold=3):
    """
    Detect devices with interface 'changed state to down' events
    (proxy for BGP-style flaps) > threshold within window_minutes.
    Returns dict: device -> list of flap-burst datetimes
    """
    flap_events = defaultdict(list)
    for e in events:
        if e["event_type"] == "Interface Flap" and "went down" in e["key_detail"]:
            flap_events[e["device"]].append(e["timestamp"])

    alerts = {}
    for device, times in flap_events.items():
        bursts = []
        times = sorted(times)
        window = timedelta(minutes=window_minutes)
        i = 0
        while i < len(times):
            count = 1
            j = i + 1
            while j < len(times) and (times[j] - times[i]) <= window:
                count += 1
                j += 1
            if count > threshold:
                bursts.append((times[i], count))
            i = j if j > i else i + 1
        if bursts:
            alerts[device] = bursts
    return alerts


def detect_cpu_spikes(events, window_hours=1, threshold=2):
    """
    Detect devices where CPU >80% occurs more than `threshold` times in `window_hours`.
    Returns dict: device -> list of spike windows
    """
    cpu_events = defaultdict(list)
    for e in events:
        if e["event_type"] == "CPU High":
            cpu_events[e["device"]].append(e["timestamp"])

    alerts = {}
    for device, times in cpu_events.items():
        times = sorted(times)
        window = timedelta(hours=window_hours)
        bursts = []
        i = 0
        while i < len(times):
            count = 1
            j = i + 1
            while j < len(times) and (times[j] - times[i]) <= window:
                count += 1
                j += 1
            if count > threshold:
                bursts.append((times[i], count))
            i = j if j > i else i + 1
        if bursts:
            alerts[device] = bursts
    return alerts



# 3. BUILD REPORT DATA

def build_report(events, flap_alerts, cpu_alerts):
    """
    Aggregate events per (device, event_type) and compute risk level.
    Returns list of report row dicts.
    """
    # Count events per device+type
    summary = defaultdict(lambda: {"count": 0, "last_seen": None})
    for e in events:
        key = (e["device"], e["event_type"])
        summary[key]["count"] += 1
        if summary[key]["last_seen"] is None or e["timestamp"] > summary[key]["last_seen"]:
            summary[key]["last_seen"] = e["timestamp"]

    rows = []
    for (device, event_type), data in summary.items():
        count = data["count"]
        last_seen = data["last_seen"].strftime("%Y-%m-%d %H:%M:%S")

        # Risk scoring
        risk = "LOW"
        if event_type == "SNMP Auth Failure":
            risk = "HIGH" if count >= 3 else "MEDIUM"
        elif event_type == "Interface Flap":
            if device in flap_alerts:
                risk = "HIGH"
            elif count >= 4:
                risk = "MEDIUM"
        elif event_type == "BGP Flap":
            risk = "MEDIUM" if count >= 2 else "LOW"
        elif event_type == "CPU High":
            if device in cpu_alerts:
                risk = "HIGH"
            elif count >= 2:
                risk = "MEDIUM"
        elif event_type == "Interface Error":
            risk = "MEDIUM" if count >= 2 else "LOW"
        elif event_type == "Temperature High":
            risk = "MEDIUM" if count >= 2 else "LOW"

        rows.append({
            "Device": device,
            "Event": event_type,
            "Count": count,
            "Last_Seen": last_seen,
            "Risk_Level": risk,
        })

    # Sort: HIGH first, then MEDIUM, then LOW; within same risk sort by count desc
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    rows.sort(key=lambda r: (risk_order[r["Risk_Level"]], -r["Count"]))
    return rows


def write_csv(rows, output_path):
    fieldnames = ["Device", "Event", "Count", "Last_Seen", "Risk_Level"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  ✓ CSV report saved → {output_path}")




# 4. VISUALIZATION

RISK_COLORS = {"HIGH": "#FF4C4C", "MEDIUM": "#FFA500", "LOW": "#4CAF50"}

def generate_chart(events, report_rows, output_path):
    """Generate a multi-panel chart and save to output_path."""

    # ── Data prep ──────────────────────────────
    # Panel 1: Top 5 devices by total event count
    device_counts = defaultdict(int)
    for e in events:
        device_counts[e["device"]] += 1
    top5 = sorted(device_counts.items(), key=lambda x: -x[1])[:5]
    top5_devices = [d for d, _ in top5]
    top5_counts  = [c for _, c in top5]

    # Panel 2: Event type distribution (stacked by risk)
    type_risk = defaultdict(lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
    for row in report_rows:
        type_risk[row["Event"]][row["Risk_Level"]] += row["Count"]
    event_types = sorted(type_risk.keys(), key=lambda t: -sum(type_risk[t].values()))[:7]

    # Panel 3: Timeline heatmap – events per device per hour
    from collections import Counter
    device_hour = defaultdict(Counter)
    for e in events:
        hour_key = e["timestamp"].strftime("%m-%d %Hh")
        device_hour[e["device"]][hour_key] += 1
    all_hours = sorted({h for dh in device_hour.values() for h in dh})
    devices_sorted = sorted(device_counts.keys())

    # Panel 4: Risk level pie
    risk_totals = Counter()
    for row in report_rows:
        risk_totals[row["Risk_Level"]] += row["Count"]

    # ── Figure setup ──────────────────────────
    fig = plt.figure(figsize=(18, 14), facecolor="#0D1117")
    fig.suptitle(
        "Network Log Analysis  ·  Oct 17–20, 2025",
        fontsize=20, fontweight="bold", color="#E6EDF3",
        y=0.97, fontfamily="monospace"
    )

    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.55, wspace=0.38,
                           left=0.06, right=0.97, top=0.91, bottom=0.07)

    ax1 = fig.add_subplot(gs[0, 0])   # Top 5 devices
    ax2 = fig.add_subplot(gs[0, 1:])  # Event type stacked bar
    ax3 = fig.add_subplot(gs[1, :2])  # Timeline heatmap
    ax4 = fig.add_subplot(gs[1, 2])   # Risk pie

    DARK_BG = "#161B22"
    GRID_C  = "#30363D"
    TEXT_C  = "#C9D1D9"
    ACCENT  = "#58A6FF"

    for ax in [ax1, ax2, ax3, ax4]:
        ax.set_facecolor(DARK_BG)
        ax.tick_params(colors=TEXT_C, labelsize=9)
        for spine in ax.spines.values():
            spine.set_color(GRID_C)

    # ── Panel 1: Top 5 Devices bar ────────────
    bar_colors = [RISK_COLORS["HIGH"] if c == max(top5_counts) else ACCENT for c in top5_counts]
    bars = ax1.barh(top5_devices[::-1], top5_counts[::-1], color=bar_colors[::-1],
                    edgecolor="#30363D", linewidth=0.5, height=0.6)
    ax1.set_xlabel("Total Events", color=TEXT_C, fontsize=9)
    ax1.set_title("Top Devices by Event Count", color=TEXT_C, fontsize=11,
                  fontweight="bold", pad=10, fontfamily="monospace")
    ax1.xaxis.set_tick_params(labelcolor=TEXT_C)
    ax1.yaxis.set_tick_params(labelcolor=TEXT_C)
    ax1.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax1.grid(axis="x", color=GRID_C, linewidth=0.5, linestyle="--", alpha=0.6)
    for bar, val in zip(bars, top5_counts[::-1]):
        ax1.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                 str(val), va="center", ha="left", color=TEXT_C, fontsize=9,
                 fontfamily="monospace")

    # ── Panel 2: Stacked bar by event type ───
    x = range(len(event_types))
    bottoms = [0] * len(event_types)
    for risk_level in ["LOW", "MEDIUM", "HIGH"]:
        vals = [type_risk[et][risk_level] for et in event_types]
        ax2.bar(x, vals, bottom=bottoms, color=RISK_COLORS[risk_level],
                label=risk_level, edgecolor="#30363D", linewidth=0.4)
        bottoms = [b + v for b, v in zip(bottoms, vals)]

    ax2.set_xticks(list(x))
    ax2.set_xticklabels(event_types, rotation=25, ha="right", color=TEXT_C, fontsize=8.5,
                        fontfamily="monospace")
    ax2.set_ylabel("Event Count", color=TEXT_C, fontsize=9)
    ax2.set_title("Event Types by Risk Level", color=TEXT_C, fontsize=11,
                  fontweight="bold", pad=10, fontfamily="monospace")
    ax2.yaxis.set_tick_params(labelcolor=TEXT_C)
    ax2.grid(axis="y", color=GRID_C, linewidth=0.5, linestyle="--", alpha=0.6)
    legend = ax2.legend(title="Risk", title_fontsize=9, fontsize=8,
                        facecolor="#0D1117", edgecolor=GRID_C, labelcolor=TEXT_C)
    legend.get_title().set_color(TEXT_C)

    # ── Panel 3: Heatmap ──────────────────────
    # build matrix
    import numpy as np
    matrix = np.zeros((len(devices_sorted), len(all_hours)))
    for di, dev in enumerate(devices_sorted):
        for hi, hour in enumerate(all_hours):
            matrix[di, hi] = device_hour[dev].get(hour, 0)

    im = ax3.imshow(matrix, aspect="auto", cmap="YlOrRd", interpolation="nearest",
                    vmin=0, vmax=matrix.max() or 1)
    ax3.set_yticks(range(len(devices_sorted)))
    ax3.set_yticklabels(devices_sorted, color=TEXT_C, fontsize=9, fontfamily="monospace")
    step = max(1, len(all_hours) // 12)
    ax3.set_xticks(range(0, len(all_hours), step))
    ax3.set_xticklabels([all_hours[i] for i in range(0, len(all_hours), step)],
                        rotation=35, ha="right", color=TEXT_C, fontsize=7.5,
                        fontfamily="monospace")
    ax3.set_title("Event Density Heatmap  (per device × hour)",
                  color=TEXT_C, fontsize=11, fontweight="bold", pad=10, fontfamily="monospace")
    cbar = plt.colorbar(im, ax=ax3, pad=0.01)
    cbar.ax.tick_params(colors=TEXT_C)
    cbar.set_label("Events", color=TEXT_C, fontsize=8)
    cbar.outline.set_edgecolor(GRID_C)

    # ── Panel 4: Risk pie ─────────────────────
    risk_labels = [k for k in ["HIGH", "MEDIUM", "LOW"] if risk_totals[k] > 0]
    risk_vals   = [risk_totals[k] for k in risk_labels]
    risk_col    = [RISK_COLORS[k] for k in risk_labels]
    explode     = [0.06 if k == "HIGH" else 0 for k in risk_labels]

    wedges, texts, autotexts = ax4.pie(
        risk_vals, labels=risk_labels, colors=risk_col, explode=explode,
        autopct="%1.1f%%", startangle=140,
        textprops={"color": TEXT_C, "fontsize": 9, "fontfamily": "monospace"},
        wedgeprops={"edgecolor": DARK_BG, "linewidth": 2},
        pctdistance=0.75
    )
    for at in autotexts:
        at.set_fontsize(8)
        at.set_color("#E6EDF3")
    ax4.set_title("Risk Distribution", color=TEXT_C, fontsize=11,
                  fontweight="bold", pad=10, fontfamily="monospace")
    ax4.set_facecolor(DARK_BG)

    # ── Save ──────────────────────────────────
    plt.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Chart saved → {output_path}")



# 5. PRINT CONSOLE SUMMARY

def print_summary(events, flap_alerts, cpu_alerts, report_rows):
    total = len(events)
    errors = sum(1 for e in events if e["level"] == "ERROR")
    warnings = sum(1 for e in events if e["level"] == "WARNING")
    devices = len({e["device"] for e in events})

    print("\n" + "═"*60)
    print("  NETWORK LOG ANALYSIS SUMMARY")
    print("═"*60)
    print(f"  Total events parsed  : {total}")
    print(f"  Unique devices       : {devices}")
    print(f"  ERROR events         : {errors}")
    print(f"  WARNING events       : {warnings}")
    print(f"  Log files processed  : 4  (Oct 17–20, 2025)")
    print("─"*60)

    if flap_alerts:
        print("\n  ⚠  INTERFACE FLAP ALERTS (>3 downs within 10 min):")
        for dev, bursts in flap_alerts.items():
            for ts, count in bursts:
                print(f"     {dev}  →  {count} flaps starting {ts.strftime('%Y-%m-%d %H:%M')}")
    else:
        print("\n  ✓  No interface flap bursts detected")

    if cpu_alerts:
        print("\n  ⚠  CPU SPIKE ALERTS (>2 spikes >80% within 1 hour):")
        for dev, bursts in cpu_alerts.items():
            for ts, count in bursts:
                print(f"     {dev}  →  {count} spikes starting {ts.strftime('%Y-%m-%d %H:%M')}")
    else:
        print("\n  ✓  No CPU spike bursts detected")

    high_rows = [r for r in report_rows if r["Risk_Level"] == "HIGH"]
    if high_rows:
        print(f"\n  HIGH-RISK ENTRIES ({len(high_rows)}):")
        for r in high_rows:
            print(f"     {r['Device']:4s}  {r['Event']:<22s}  count={r['Count']:>3d}  last={r['Last_Seen']}")
    print("═"*60 + "\n")



# MAIN


if __name__ == "__main__":
    print("\n[1/5] Parsing log files …")
    events = parse_logs(LOG_DIR)
    print(f"      {len(events)} events loaded from {LOG_DIR}")

    print("[2/5] Detecting interface flap bursts …")
    flap_alerts = detect_interface_flaps(events, window_minutes=10, threshold=3)

    print("[3/5] Detecting CPU spike bursts …")
    cpu_alerts = detect_cpu_spikes(events, window_hours=1, threshold=2)

    print("[4/5] Building report …")
    report_rows = build_report(events, flap_alerts, cpu_alerts)
    write_csv(report_rows, OUTPUT_CSV)

    print("[5/5] Generating chart …")
    generate_chart(events, report_rows, OUTPUT_CHART)

    print_summary(events, flap_alerts, cpu_alerts, report_rows)