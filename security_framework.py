#!/usr/bin/env python3

import subprocess
import requests
import re
import os
import glob
import json
from collections import Counter


def run_command(command):
    print("\n" + "=" * 60)
    print(f"Running: {command}")
    print("=" * 60 + "\n")
    subprocess.run(command, shell=True)


def enrich_ip(ip):
    print("\n--- API Enrichment ---")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()

        print(f"IP: {ip}")
        print(f"Country: {data.get('country', 'Unknown')}")
        print(f"Organisation: {data.get('org', 'Unknown')}")
        print(f"ISP: {data.get('isp', 'Unknown')}")
    except Exception:
        print("API enrichment failed")


def extract_top_ip(report_path="ids_security_report.txt"):
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()

        match = re.search(r"Top Source IP:\s*\n([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", content)
        if match:
            return match.group(1)
    except Exception:
        pass

    return None


def latest_eve_json():
    candidates = sorted(glob.glob("run_*/eve.json"))
    if candidates:
        return candidates[-1]
    return None


def detect_shadow_ai():
    print("\n--- Shadow AI Detection ---")

    indicators = {
        "openai": 2,
        "api.openai.com": 3,
        "chatgpt": 2,
        "gpt": 1,
        "anthropic": 2,
        "claude": 2,
        "cohere": 2,
        "huggingface": 2,
        "replicate": 2,
        "perplexity": 2,
        "gemini": 2,
        "llm": 1,
        "/v1/chat/completions": 3,
        "/v1/embeddings": 3,
        "/v1/models": 2,
    }

    evidence = []
    indicator_counts = Counter()
    src_ip_counts = Counter()
    risk_score = 0

    # Check local scan / report outputs
    files_to_check = [
        "asset_services.txt",
        "api_web_scan.txt",
        "ids_security_report.txt",
    ]

    for path in files_to_check:
        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()

            matched_here = set()
            for indicator, weight in indicators.items():
                if indicator.lower() in content:
                    indicator_counts[indicator] += 1
                    matched_here.add(indicator)
                    evidence.append(f"{path}: matched indicator '{indicator}'")

            if matched_here:
                risk_score += sum(indicators[i] for i in matched_here)

        except Exception:
            continue

    # Check latest Suricata eve.json traffic metadata
    eve_path = latest_eve_json()
    if eve_path and os.path.exists(eve_path):
        try:
            with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    fields_to_check = []

                    # DNS
                    dns = obj.get("dns", {})
                    if isinstance(dns, dict):
                        fields_to_check.append(str(dns.get("rrname", "")))

                    # HTTP
                    http = obj.get("http", {})
                    if isinstance(http, dict):
                        fields_to_check.append(str(http.get("hostname", "")))
                        fields_to_check.append(str(http.get("url", "")))
                        fields_to_check.append(str(http.get("http_user_agent", "")))

                    # TLS
                    tls = obj.get("tls", {})
                    if isinstance(tls, dict):
                        fields_to_check.append(str(tls.get("sni", "")))

                    combined = " ".join(fields_to_check).lower()
                    if not combined.strip():
                        continue

                    matched_here = set()
                    for indicator, weight in indicators.items():
                        if indicator.lower() in combined:
                            indicator_counts[indicator] += 1
                            matched_here.add(indicator)

                    if matched_here:
                        src_ip = obj.get("src_ip", "unknown")
                        src_ip_counts[src_ip] += 1
                        evidence.append(
                            f"{eve_path}: matched {', '.join(sorted(matched_here))} "
                            f"(src_ip={src_ip})"
                        )
                        risk_score += sum(indicators[i] for i in matched_here)

        except Exception:
            pass

    # Remove duplicates while preserving order
    unique_evidence = []
    seen = set()
    for item in evidence:
        if item not in seen:
            unique_evidence.append(item)
            seen.add(item)

    # Risk classification
    if risk_score == 0:
        risk_level = "NONE"
    elif risk_score <= 3:
        risk_level = "LOW"
    elif risk_score <= 8:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    # Console output
    if unique_evidence:
        print("[!] Potential Shadow AI activity detected")
        print(f"Risk level: {risk_level}")
        print(f"Risk score: {risk_score}\n")

        print("Top indicators:")
        for indicator, count in indicator_counts.most_common():
            print(f"- {indicator}: {count}")

        print("\nTop source IPs:")
        if src_ip_counts:
            for ip, count in src_ip_counts.most_common(3):
                print(f"- {ip}: {count} events")
        else:
            print("- No source IP evidence captured")

        print("\nEvidence:")
        for item in unique_evidence[:8]:
            print(f"- {item}")
    else:
        print("[OK] No AI-related indicators detected in current artifacts/logs.")
        print("Risk level: NONE")
        print("Risk score: 0")

    # Recommendations
    if risk_level == "HIGH":
        recommendations = [
            "Investigate outbound AI-related traffic immediately.",
            "Review firewall, proxy and DNS logs for unapproved AI service access.",
            "Validate whether AI tool usage is authorised under organisational policy.",
            "Restrict or block unapproved AI endpoints if sensitive data is involved.",
        ]
    elif risk_level == "MEDIUM":
        recommendations = [
            "Monitor matched hosts and destinations for repeated AI-related traffic.",
            "Review acceptable-use policy coverage for external AI services.",
            "Confirm whether detected activity is legitimate or experimental.",
        ]
    elif risk_level == "LOW":
        recommendations = [
            "Record the finding and continue monitoring.",
            "Confirm whether the matched references are benign or test-related.",
        ]
    else:
        recommendations = [
            "No Shadow AI indicators were detected in the analysed artifacts.",
        ]

    print("\nRecommendations:")
    for rec in recommendations:
        print(f"- {rec}")

    # Save report
    report_lines = []
    report_lines.append("Shadow AI Detection Report")
    report_lines.append("==========================")
    report_lines.append(f"Risk Level: {risk_level}")
    report_lines.append(f"Risk Score: {risk_score}")
    report_lines.append("")

    report_lines.append("Top Indicators:")
    if indicator_counts:
        for indicator, count in indicator_counts.most_common():
            report_lines.append(f"- {indicator}: {count}")
    else:
        report_lines.append("- None")

    report_lines.append("")
    report_lines.append("Top Source IPs:")
    if src_ip_counts:
        for ip, count in src_ip_counts.most_common(3):
            report_lines.append(f"- {ip}: {count} events")
    else:
        report_lines.append("- No source IP evidence captured")

    report_lines.append("")
    report_lines.append("Evidence:")
    if unique_evidence:
        for item in unique_evidence[:8]:
            report_lines.append(f"- {item}")
    else:
        report_lines.append("- None")

    report_lines.append("")
    report_lines.append("Recommendations:")
    for rec in recommendations:
        report_lines.append(f"- {rec}")

    with open("shadow_ai_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print("\nSaved report to shadow_ai_report.txt")


def main():
    while True:
        print("\n" + "=" * 60)
        print(" Asset Discovery and API Risk Testing Framework ")
        print("=" * 60)
        print("1. Asset discovery (host scan)")
        print("2. Service discovery")
        print("3. Web/API risk scan")
        print("4. Analyse IDS alerts")
        print("5. Generate IDS graphs")
        print("6. Generate security report")
        print("7. Compare experiment runs")
        print("8. Run full security assessment")
        print("9. Shadow AI detection")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            target = input("Enter subnet (example 192.168.2.0/24): ").strip()
            run_command(f"nmap -sn {target} -oN asset_discovery_hosts.txt")
            run_command("grep 'Nmap scan report for' asset_discovery_hosts.txt > asset_inventory.txt")

        elif choice == "2":
            target = input("Enter target IP (example 192.168.2.3): ").strip()
            run_command(f"nmap -sV {target} -oN asset_services.txt")

        elif choice == "3":
            target = input("Enter target URL (example http://192.168.2.3): ").strip()
            run_command(f"nikto -h {target} -o api_web_scan.txt")

        elif choice == "4":
            run_command("python3 analyze_alerts.py")

        elif choice == "5":
            run_command("python3 visualize_alerts.py")

        elif choice == "6":
            run_command("python3 generate_report.py")
            top_ip = extract_top_ip()
            if top_ip:
                print(f"\nAuto-detected top source IP: {top_ip}")
                enrich_ip(top_ip)
            else:
                print("\nCould not auto-detect top source IP from report.")

        elif choice == "7":
            run_command("python3 compare_runs.py")

        elif choice == "8":
            print("\nRunning full security assessment...\n")

            subnet = input("Enter subnet for asset discovery (example 192.168.2.0/24): ").strip()
            target = input("Enter target host for service/API scans (example 192.168.2.3): ").strip()

            run_command(f"nmap -sn {subnet} -oN asset_discovery_hosts.txt")
            run_command("grep 'Nmap scan report for' asset_discovery_hosts.txt > asset_inventory.txt")
            run_command(f"nmap -sV {target} -oN asset_services.txt")
            run_command(f"nikto -h http://{target} -o api_web_scan.txt")
            run_command("python3 analyze_alerts.py")
            run_command("python3 visualize_alerts.py")
            run_command("python3 generate_report.py")

            top_ip = extract_top_ip()
            if top_ip:
                print(f"\nAuto-detected top source IP: {top_ip}")
                enrich_ip(top_ip)
            else:
                print("\nCould not auto-detect top source IP from report.")

            detect_shadow_ai()

        elif choice == "9":
            detect_shadow_ai()

        elif choice == "0":
            print("Exiting framework.")
            break

        else:
            print("Invalid option. Please choose again.")


if __name__ == "__main__":
    main()
