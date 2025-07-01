# Log-analyser

Building a Python-based command-line tool to process .vlog system session logs, parsing each log, generate structured timelines, and detect suspicious or unusual behavior.

**Description**
Log Analyser CLI Tool

1. Parse .vlog session logs
2. Build a clean, structured event timeline
3. Spot suspicious patterns (e.g., shadow copy removal and file deletion)
4. Visualize user actions and detected anomalies

**Input**
Log Entry Example:

0x1A2B[ts:1719462390]|EVNT:XR-EXEC!@KILL_usr:admin=>C:\Windows\cmd.exe

**Output**

timeline.csv — Contains all valid and structured log entries
invalid.csv — Lists malformed or invalid log lines
suspected_anomalies.csv — Flags detected suspicious actions

**Visual Reports**

event_frequency.png/html — Shows frequency of different event types over time
user_activity.png/html — Highlights actions performed by each user
anomalies_highlighted.png/html — Visual emphasis on potentially malicious behavior
