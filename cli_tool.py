#!/usr/bin/env python3

import argparse
import os
import re
import csv
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px

# -------------------------------
# CONFIG
# -------------------------------
log_files = [
    "session_1.vlog", "session_2.vlog", "session_3.vlog",
    "session_4.vlog", "session_5.vlog", "corrupt.vlog"
]

log_pattern = re.compile(
    r"^(0x[\da-fA-F]+)\[ts:(\d+)\]\|EVNT:(XR-[A-Z\-]+)!@([A-Z_]+)_(usr|IP):([a-zA-Z0-9\.\:]+)=?>?(.+)?"
)

def categorize(event_type):
    if event_type == "XR-EXEC":
        return "process"
    elif event_type == "XR-FILE":
        return "file"
    elif event_type == "XR-USER":
        return "user"
    else:
        return "unknown"

# -------------------------------
# Timeline logic (timeline.py)
# -------------------------------
def generate_timeline(logdir):
    timeline_entries = []
    invalid_entries = []

    for file_name in log_files:
        full_path = os.path.join(logdir, file_name)
        try:
            with open(full_path, "r", encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    match = log_pattern.match(line)
                    if match:
                        log_id, timestamp, event_type, action, user_type, user, target_path = match.groups()
                        timeline_entries.append({
                            "timestamp": int(timestamp),
                            "event_type": event_type,
                            "category": categorize(event_type),
                            "action": action,
                            "user_type": user_type,
                            "user": user,
                            "target_path": target_path if target_path else "",
                            "log_id": log_id
                        })
                    else:
                        ts_match = re.search(r"\[ts:(\d+)\]", line)
                        timestamp = int(ts_match.group(1)) if ts_match else None
                        invalid_entries.append({
                            "timestamp": timestamp,
                            "invalid": line
                        })
        except FileNotFoundError:
            print(f"File {file_name} not found!")

    timeline_entries.sort(key=lambda x: x["timestamp"])

    if timeline_entries:
        with open("timeline.csv", "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=timeline_entries[0].keys())
            writer.writeheader()
            writer.writerows(timeline_entries)
        print("timeline.csv generated.")
    else:
        print("No valid entries found.")

    with open("invalid_logs.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["timestamp", "invalid"])
        writer.writeheader()
        writer.writerows(invalid_entries)
    print("invalid_logs.csv generated.")

# -------------------------------
# Anomaly logic (anomaly_script.py)
# -------------------------------
def parse_custom_log_line(line, filename):
    match = re.match(r'0x[\da-fA-F]+\[ts:(\d+)\]\|EVNT:([A-Z\-]+)!@([A-Z_]+)_(\w+):(.+)', line)
    if match:
        return {
            "timestamp": int(match.group(1)),
            "event_type": match.group(2),
            "operation": match.group(3),
            "actor": match.group(4),
            "target": match.group(5).strip("=>"),
            "file": filename
        }
    return None

def parse_all_logs(logdir):
    events = []
    for file in log_files:
        full_path = os.path.join(logdir, file)
        try:
            with open(full_path, "r") as f:
                for line in f:
                    parsed = parse_custom_log_line(line.strip(), file)
                    if parsed:
                        events.append(parsed)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    return sorted(events, key=lambda x: x["timestamp"])

def detect_anomalies(events):
    anomalies = []
    for i in range(len(events) - 1):
        e1 = events[i]
        e2 = events[i + 1]
        time_diff = e2["timestamp"] - e1["timestamp"]

        if e1["event_type"] == "XR-SHDW" and e1["operation"] == "KILL" and \
           e2["event_type"] == "XR-DEL" and time_diff <= 10:
            anomalies.append({
                "kill_time": e1["timestamp"],
                "killer": e1["actor"],
                "killed_proc": e1["target"],
                "delete_time": e2["timestamp"],
                "deleter": e2["actor"],
                "deleted_target": e2["target"],
                "file_source": e1["file"]
            })
    return anomalies

def save_anomalies(anomalies):
    with open("suspected_anomalies.csv", "w", newline='') as csvfile:
        fieldnames = ["kill_time", "killer", "killed_proc", "delete_time", "deleter", "deleted_target", "file_source"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in anomalies:
            writer.writerow(row)
    print(f"{len(anomalies)} anomalies saved to suspected_anomalies.csv")

# -------------------------------
# Visualization logic (visualization.py)
# -------------------------------
def generate_visuals():
    timeline_df = pd.read_csv("timeline.csv")
    anomalies_df = pd.read_csv("suspected_anomalies.csv")

    timeline_df["timestamp"] = pd.to_numeric(timeline_df["timestamp"], errors="coerce")

    # Event Frequency
    plt.figure(figsize=(10, 5))
    plt.hist(timeline_df["timestamp"], bins=30, color='skyblue', edgecolor='black')
    plt.title("Event Frequency Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Event Count")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("event_frequency.png")

    px.histogram(timeline_df, x="timestamp", nbins=30, title="Event Frequency Over Time") \
        .write_html("event_frequency.html")

    # User Activity
    user_counts = timeline_df["user"].value_counts().reset_index()
    user_counts.columns = ["user", "event_count"]

    plt.figure(figsize=(10, 5))
    plt.bar(user_counts["user"], user_counts["event_count"], color='orange')
    plt.title("User Activity")
    plt.xlabel("User")
    plt.ylabel("Number of Events")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("user_activity.png")

    px.bar(user_counts, x="user", y="event_count", title="User Activity") \
        .write_html("user_activity.html")

    # Anomalies Highlight
    if anomalies_df.empty:
        print("No anomalies found, skipping highlight.")
        timeline_df["is_anomaly"] = False
    else:
        timeline_df["is_anomaly"] = timeline_df["timestamp"].isin(
            anomalies_df["kill_time"].tolist() + anomalies_df["delete_time"].tolist()
        )

    plt.figure(figsize=(12, 6))
    plt.scatter(timeline_df["timestamp"], timeline_df["user"],
                c=timeline_df["is_anomaly"].map({True: "red", False: "green"}))
    plt.title("Timeline with Anomalies Highlighted")
    plt.xlabel("Timestamp")
    plt.ylabel("User")
    plt.tight_layout()
    plt.savefig("anomalies_highlighted.png")

    px.scatter(timeline_df, x="timestamp", y="user", color="is_anomaly",
               title="Timeline with Anomalies Highlighted") \
        .write_html("anomalies_highlighted.html")

    print("All visualizations created (PNG + HTML)")

# -------------------------------
# MAIN CLI
# -------------------------------
def main():
    parser = argparse.ArgumentParser(description="Forensic Parser CLI")
    parser.add_argument("logdir", nargs="?", default=r"C:\Users\Sanjana Yoga\OneDrive\Desktop\log_files",
                        help="Directory with .vlog files (default: your Desktop log_files)")
    parser.add_argument("--summary", action="store_true", help="Show summary of timeline")
    parser.add_argument("--timeline", action="store_true", help="Parse logs and generate timeline/invalid csv")
    parser.add_argument("--alerts", action="store_true", help="Detect anomalies and generate plots")

    args = parser.parse_args()

    print(f"Using log directory: {args.logdir}")

    if args.timeline:
        generate_timeline(args.logdir)

    if args.alerts:
        all_events = parse_all_logs(args.logdir)
        anomalies = detect_anomalies(all_events)
        save_anomalies(anomalies)
        generate_visuals()

    if args.summary:
        df = pd.read_csv("timeline.csv")
        print("\n=== SUMMARY ===")
        print(f"Total valid events: {len(df)}")
        print("Event types:\n", df["event_type"].value_counts())
        print("Top users:\n", df["user"].value_counts().head())

if __name__ == "__main__":
    main()
