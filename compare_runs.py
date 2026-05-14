import os
import json
from collections import Counter

BASELINE = "run_baseline/eve.json"
ATTACK = "run_attack/eve.json"

def load_alerts(file_path):
    alerts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        alerts.append(data)
                except:
                    continue
    except:
        print(f"Missing file: {file_path}")
    return alerts

def extract_features(alerts):
    alert_types = Counter()
    source_ips = Counter()

    for alert in alerts:
        sig = alert.get("alert", {}).get("signature", "unknown")
        ip = alert.get("src_ip", "unknown")

        alert_types[sig] += 1
        source_ips[ip] += 1

    return alert_types, source_ips

def main():
    print("\n=== Run Comparison ===\n")

    baseline_alerts = load_alerts(BASELINE)
    attack_alerts = load_alerts(ATTACK)

    b_count = len(baseline_alerts)
    a_count = len(attack_alerts)

    print(f"Baseline alerts: {b_count}")
    print(f"Attack alerts: {a_count}")

    if b_count == 0:
        print("\n[!] Cannot compare – baseline is empty")
        return

    diff = a_count - b_count
    percent = (diff / b_count) * 100

    print(f"\nChange: {diff:+} alerts ({percent:.2f}%)")

    # Extract deeper info
    b_types, b_ips = extract_features(baseline_alerts)
    a_types, a_ips = extract_features(attack_alerts)

    print("\n=== Insight ===")

    if percent > 20:
        print("Significant increase detected → likely attack scenario")
    elif percent > 5:
        print("Moderate increase detected → possible suspicious activity")
    else:
        print("Minimal change → no major anomaly detected")

    # New IP detection
    new_ips = set(a_ips.keys()) - set(b_ips.keys())
    if new_ips:
        print("\nNew source IPs detected:")
        for ip in list(new_ips)[:3]:
            print(f"- {ip}")

    # New alert types
    new_alerts = set(a_types.keys()) - set(b_types.keys())
    if new_alerts:
        print("\nNew alert types detected:")
        for a in list(new_alerts)[:3]:
            print(f"- {a}")

    print("\n=== Recommended Actions ===")

    if percent > 20:
        print("[HIGH] Investigate spike in alerts – possible active attack")
        print("[HIGH] Block or rate-limit suspicious IPs")
        print("[MEDIUM] Inspect IDS logs for attack patterns")

    elif percent > 5:
        print("[MEDIUM] Review increased activity for anomalies")
        print("[LOW] Monitor traffic for escalation")

    else:
        print("[LOW] Maintain monitoring – system appears stable")

    print("\n[OK] Comparison complete\n")

if __name__ == "__main__":
    main()
