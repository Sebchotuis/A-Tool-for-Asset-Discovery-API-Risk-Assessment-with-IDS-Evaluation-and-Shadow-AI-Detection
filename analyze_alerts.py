import json
from collections import Counter
import os

def get_latest_run():
    runs = [d for d in os.listdir() if d.startswith("run_") and os.path.isdir(d)]
    if not runs:
        print("No run folders found. Run collect_logs.sh first.")
        return None
    runs.sort(reverse=True)
    return runs[0]

latest_run = get_latest_run()

if latest_run is None:
    exit()

log_file = os.path.join(latest_run, "eve.json")

if not os.path.exists(log_file):
    print(f"Missing eve.json in {latest_run}")
    exit()

print(f"\n[OK] Using latest run: {latest_run}\n")

alert_types = Counter()
source_ips = Counter()
categories = Counter()

with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") == "alert":
            alert = event["alert"]["signature"]
            category = event["alert"].get("category", "Unknown")
            src_ip = event.get("src_ip", "unknown")

            alert_types[alert] += 1
            source_ips[src_ip] += 1
            categories[category] += 1


# ==============================
# OUTPUT
# ==============================

print("=== Alert Types Detected ===")
for alert, count in alert_types.most_common(10):
    print(f"{alert}: {count}")

print("\n=== Top Source IPs ===")
for ip, count in source_ips.most_common(10):
    print(f"{ip}: {count}")

print("\n=== Alert Categories ===")
for cat, count in categories.most_common(5):
    print(f"{cat}: {count}")


# ==============================
# BASIC ANALYSIS
# ==============================

print("\n=== Basic Analysis ===")

top_ip = None
top_count = 0

if source_ips:
    top_ip, top_count = source_ips.most_common(1)[0]
    print(f"- Most active IP: {top_ip} ({top_count} alerts)")

if alert_types:
    top_alert, alert_count = alert_types.most_common(1)[0]
    print(f"- Most common alert: {top_alert} ({alert_count} occurrences)")

if categories:
    top_category, cat_count = categories.most_common(1)[0]
    print(f"- Dominant category: {top_category} ({cat_count})")

if top_count > 1000:
    print("- High-volume traffic detected (possible automated scanning or attack)")


# ==============================
# 🔥 PRIORITISED COUNTERMEASURES
# ==============================

print("\n=== Recommended Countermeasures (Prioritised) ===")

priority_actions = []

# 1. HIGH PRIORITY: Traffic source
if top_ip and top_count > 1000:
    priority_actions.append(
        f"[HIGH] Investigate and rate-limit/block IP {top_ip} ({top_count} alerts)"
    )

# 2. Category-based decision (ONLY ONE, most relevant)
if categories:
    top_category, _ = categories.most_common(1)[0]

    if "Web Application" in top_category:
        priority_actions.append(
            "[HIGH] Patch web vulnerabilities and deploy a Web Application Firewall (WAF)"
        )

    elif "Administrator" in top_category:
        priority_actions.append(
            "[HIGH] Enforce strong authentication and review admin access controls"
        )

    elif "Protocol" in top_category:
        priority_actions.append(
            "[MEDIUM] Inspect malformed protocol traffic and tune IDS rules"
        )

    elif "Bad Traffic" in top_category or "Suspicious" in top_category:
        priority_actions.append(
            "[MEDIUM] Investigate suspicious outbound traffic and review DNS/HTTP logs"
        )

# 3. Always include ONE general improvement
priority_actions.append(
    "[LOW] Update IDS signatures and continue monitoring network activity"
)

# ==============================
# PRINT ONLY TOP 3 ACTIONS
# ==============================

for action in priority_actions[:3]:
    print(f"- {action}")

print("\n[OK] Analysis complete\n")
