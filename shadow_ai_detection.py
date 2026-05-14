import json
from collections import Counter

EVE_FILE = "/home/ubuntu/ids_analysis/run_baseline/eve.json"

AI_KEYWORDS = ["openai", "chatgpt", "gpt", "llm", "gemini"]

def load_alerts():
    alerts = []
    try:
        with open(EVE_FILE, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        alerts.append(data)
                except:
                    continue
    except FileNotFoundError:
        print("[!] eve.json not found")
    return alerts


def detect_shadow_ai(alerts):
    matches = []
    source_ips = []

    for alert in alerts:
        alert_text = str(alert).lower()

        for keyword in AI_KEYWORDS:
            if keyword in alert_text:
                matches.append(keyword)
                source_ips.append(alert.get("src_ip", "unknown"))

    return matches, source_ips


def calculate_risk(matches):
    unique = len(set(matches))
    total = len(matches)

    if total > 20:
        return "HIGH", 9
    elif total > 5:
        return "MEDIUM", 6
    elif total > 0:
        return "LOW", 3
    else:
        return "NONE", 0


def main():
    print("\n=== Shadow AI Detection ===\n")

    alerts = load_alerts()
    matches, source_ips = detect_shadow_ai(alerts)

    if not matches:
        print("[OK] No Shadow AI activity detected\n")
        return

    risk_level, score = calculate_risk(matches)

    print("[!] Potential Shadow AI activity detected")
    print(f"Risk level: {risk_level}")
    print(f"Risk score: {score}\n")

    keyword_counts = Counter(matches)
    ip_counts = Counter(source_ips)

    print("Top indicators:")
    for k, v in keyword_counts.most_common():
        print(f"- {k}: {v}")

    print("\nTop source IPs:")
    for ip, v in ip_counts.most_common(3):
        print(f"- {ip}: {v} events")

    # Save report
    with open("shadow_ai_report.txt", "w") as f:
        f.write("Shadow AI Detection Report\n")
        f.write("=========================\n")
        f.write(f"Risk Level: {risk_level}\n")
        f.write(f"Risk Score: {score}\n\n")

        f.write("Indicators:\n")
        for k, v in keyword_counts.items():
            f.write(f"{k}: {v}\n")

        f.write("\nTop Source IPs:\n")
        for ip, v in ip_counts.most_common(3):
            f.write(f"{ip}: {v}\n")

    print("\n[OK] Report saved to shadow_ai_report.txt\n")


if __name__ == "__main__":
    main()
