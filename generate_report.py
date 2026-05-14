#!/usr/bin/env python3

import json
import os
from collections import Counter

BASELINE_RUN = "run_baseline"
ATTACK_RUN = "run_attack"


def load_alerts(eve_path):
    alerts = []

    if not os.path.exists(eve_path):
        print(f"[ERROR] Missing file: {eve_path}")
        return alerts

    with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if obj.get("event_type") == "alert":
                alerts.append(obj)

    return alerts


def summarise(alerts):
    signatures = Counter()
    sources = Counter()
    categories = Counter()

    for alert in alerts:
        sig = alert.get("alert", {}).get("signature", "UNKNOWN")
        src = alert.get("src_ip", "UNKNOWN")
        cat = alert.get("alert", {}).get("category", "UNKNOWN")

        signatures[sig] += 1
        sources[src] += 1
        categories[cat] += 1

    top_signature = signatures.most_common(1)[0] if signatures else ("None", 0)
    top_source = sources.most_common(1)[0] if sources else ("None", 0)
    top_category = categories.most_common(1)[0] if categories else ("None", 0)

    return {
        "count": len(alerts),
        "top_signature": top_signature,
        "top_source": top_source,
        "top_category": top_category,
    }


def calculate_risk_score(baseline, attack, difference):
    score = 0
    reasons = []

    baseline_count = baseline["count"]
    attack_count = attack["count"]

    percent_change = 0
    if baseline_count > 0:
        percent_change = (difference / baseline_count) * 100

    if percent_change > 20:
        score += 4
        reasons.append("Large increase from baseline alert volume")
    elif percent_change > 5:
        score += 3
        reasons.append("Moderate increase from baseline alert volume")
    elif percent_change > 0:
        score += 1
        reasons.append("Small increase from baseline alert volume")

    if attack["top_source"][1] > 10000:
        score += 4
        reasons.append("Very high alert concentration from a single source IP")
    elif attack["top_source"][1] > 1000:
        score += 3
        reasons.append("High alert concentration from a single source IP")
    elif attack["top_source"][1] > 100:
        score += 1
        reasons.append("Noticeable concentration from one source IP")

    top_sig = attack["top_signature"][0].upper()
    if "EXPLOIT" in top_sig or "CVE" in top_sig:
        score += 4
        reasons.append("Exploit-related alert signature detected")
    elif "SCAN" in top_sig:
        score += 3
        reasons.append("Scanning-related alert signature detected")
    elif "STREAM" in top_sig or "INVALID" in top_sig:
        score += 2
        reasons.append("Abnormal stream/protocol behaviour detected")

    top_cat = attack["top_category"][0].upper()
    if "WEB APPLICATION" in top_cat:
        score += 3
        reasons.append("Web application attack category detected")
    elif "PRIVILEGE" in top_cat or "ADMINISTRATOR" in top_cat:
        score += 3
        reasons.append("Privilege-related attack category detected")
    elif "BAD TRAFFIC" in top_cat or "SUSPICIOUS" in top_cat:
        score += 2
        reasons.append("Suspicious traffic category detected")
    elif "PROTOCOL" in top_cat:
        score += 1
        reasons.append("Protocol anomaly category detected")

    if score >= 9:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"

    return score, level, reasons, percent_change


def generate_recommendations(attack, difference, risk_level):
    recommendations = []

    top_signature = attack["top_signature"][0].upper()
    top_category = attack["top_category"][0]
    top_ip = attack["top_source"][0]
    top_ip_count = attack["top_source"][1]

    if risk_level == "HIGH":
        recommendations.append("[HIGH] Significant deviation from baseline behaviour detected – investigate immediately")
    elif risk_level == "MEDIUM":
        recommendations.append("[MEDIUM] Moderate deviation from baseline detected – review alerts and monitor closely")
    elif risk_level == "LOW":
        recommendations.append("[LOW] Limited deviation from baseline detected – maintain monitoring")

    if top_ip_count > 1000:
        recommendations.append(f"[HIGH] Block or rate-limit IP {top_ip} ({top_ip_count} alerts)")

    if "SCAN" in top_signature:
        recommendations.append("[MEDIUM] Possible scanning detected – tighten firewall policy and restrict exposed services")

    if "EXPLOIT" in top_signature or "CVE" in top_signature:
        recommendations.append("[HIGH] Exploit attempt indicators detected – patch vulnerable services immediately")

    if "STREAM" in top_signature or "INVALID" in top_signature:
        recommendations.append("[MEDIUM] Investigate abnormal TCP/protocol behaviour and tune IDS rules")

    if "Web Application" in top_category:
        recommendations.append("[MEDIUM] Review web application hardening and deploy or tune a Web Application Firewall")

    if not recommendations:
        recommendations.append("[LOW] No major anomalies detected – maintain monitoring")

    return recommendations[:4]


def build_conclusion(risk_level, percent_change, attack):
    top_ip = attack["top_source"][0]
    top_sig = attack["top_signature"][0]

    if risk_level == "HIGH":
        return (
            f"The comparison indicates a high-risk condition. Alert activity increased by {percent_change:.2f}% "
            f"relative to baseline, with the most prominent activity associated with {top_ip}. "
            f"The dominant signature was '{top_sig}', suggesting that the environment should be investigated promptly."
        )
    elif risk_level == "MEDIUM":
        return (
            f"The comparison indicates a medium-risk condition. Alert activity rose by {percent_change:.2f}% "
            f"relative to baseline, and further review is recommended to determine whether the observed behaviour "
            f"represents an emerging attack pattern or benign variation."
        )
    elif risk_level == "LOW":
        return (
            f"The comparison indicates a low-risk condition. Alert activity changed by {percent_change:.2f}% "
            f"relative to baseline, suggesting limited deviation from normal behaviour."
        )
    else:
        return (
            "The comparison indicates no material deviation from baseline behaviour."
        )


def main():
    baseline_path = os.path.join(BASELINE_RUN, "eve.json")
    attack_path = os.path.join(ATTACK_RUN, "eve.json")

    baseline_alerts = load_alerts(baseline_path)
    attack_alerts = load_alerts(attack_path)

    baseline = summarise(baseline_alerts)
    attack = summarise(attack_alerts)

    difference = attack["count"] - baseline["count"]

    risk_score, risk_level, risk_reasons, percent_change = calculate_risk_score(
        baseline, attack, difference
    )

    recommendations = generate_recommendations(attack, difference, risk_level)
    conclusion = build_conclusion(risk_level, percent_change, attack)

    report = f"""
========================================
IDS Security Monitoring Report
========================================

Experiment: IDS Traffic Comparison

Baseline Alerts: {baseline['count']}
Attack Alerts: {attack['count']}
Alert Difference: {difference}
Percentage Change: {percent_change:.2f}%

Top Alert Signature:
{attack['top_signature'][0]} ({attack['top_signature'][1]})

Top Source IP:
{attack['top_source'][0]} ({attack['top_source'][1]})

Top Alert Category:
{attack['top_category'][0]} ({attack['top_category'][1]})

========================================
Risk Assessment
========================================
Risk Score: {risk_score}
Risk Level: {risk_level}

Risk Rationale:
"""

    for reason in risk_reasons:
        report += f"- {reason}\n"

    report += """
========================================
Recommended Countermeasures
========================================
"""

    for r in recommendations:
        report += f"{r}\n"

    report += f"""
========================================
Conclusion
========================================
{conclusion}
"""

    print(report)

    with open("ids_security_report.txt", "w", encoding="utf-8") as f:
        f.write(report)

    print("Saved report to ids_security_report.txt")


if __name__ == "__main__":
    main()
