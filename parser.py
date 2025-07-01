import re

# List of log file paths
log_files = ["session_1.vlog", "session_2.vlog", "session_3.vlog", "session_4.vlog", "session_5.vlog", "corrupt.vlog"]

# Pattern to match structured log lines
log_pattern = re.compile(
    r"^(0x[\da-fA-F]+)\[ts:(\d+)\]\|EVNT:(XR-[A-Z]+)!@([A-Z]+)_(usr|IP):([a-zA-Z0-9\.\:]+)=?>?(.+)?"
)

# Lists to hold parsed data
valid_entries = []
malformed_entries = []

# Parse each file line by line
for file_name in log_files:
    try:
        with open(file_name, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                match = log_pattern.match(line)
                if match:
                    log_id, timestamp, event_type, action, user_type, user, target_path = match.groups()
                    valid_entries.append({
                        "log_id": log_id,
                        "timestamp": int(timestamp),
                        "event_type": event_type,
                        "action": action,
                        "user_type": user_type,
                        "user": user,
                        "target_path": target_path if target_path else ""
                    })
                else:
                    malformed_entries.append({"malformed": line})
    except FileNotFoundError:
        print(f"File {file_name} not found!")

# Show samples
print("✅ Valid Entries (Preview):")
for entry in valid_entries[:5]:
    print(entry)

print("\n❌ Malformed Entries (Preview):")
for bad in malformed_entries[:5]:
    print(bad)

import csv

# Save malformed entries to a CSV file
with open("malformed_logs.csv", mode="w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=["malformed"])
    writer.writeheader()
    writer.writerows(malformed_entries)

if valid_entries:
    with open("parsed_logs.csv", mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=valid_entries[0].keys())
        writer.writeheader()
        writer.writerows(valid_entries)
else:
    print("No valid entries found. Skipping parsed_logs.csv generation.")
