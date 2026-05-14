import json
import os
import textwrap
from collections import Counter

import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
from matplotlib.ticker import ScalarFormatter


plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.titlesize": 16,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
})


COLORS = {
    "background": "#F5F7FA",
    "panel": "#FFFFFF",
    "primary": "#1F2937",
    "secondary": "#6B7280",
    "blue": "#4C78A8",
    "orange": "#DD8452",
    "green": "#55A868",
    "red": "#C44E52",
    "grid": "#DADDE1",
    "summary_bg": "#F8FAFC",
    "summary_border": "#D1D5DB",
    "insight_bg": "#F9FAFB",
}


def load_alerts(eve_file):
    alerts = []
    with open(eve_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alerts.append(data)
            except Exception:
                continue
    return alerts


def extract_features(alerts):
    signatures, categories, src_ips, severities = [], [], [], []

    for alert in alerts:
        a = alert.get("alert", {})
        signatures.append(a.get("signature", "Unknown"))
        categories.append(a.get("category", "Unknown"))
        src_ips.append(alert.get("src_ip", "Unknown"))
        severities.append(str(a.get("severity", "Unknown")))

    return signatures, categories, src_ips, severities


def safe_top(counter):
    return counter.most_common(1)[0] if counter else ("N/A", 0)


def truncate_labels(labels, max_len=24):
    out = []
    for label in labels:
        label = str(label)
        if len(label) > max_len:
            out.append(label[:max_len] + "...")
        else:
            out.append(label)
    return out


def add_card_border(ax):
    for spine in ax.spines.values():
        spine.set_edgecolor(COLORS["summary_border"])
        spine.set_linewidth(1.1)


def style_ax(ax, grid_axis="x"):
    ax.set_facecolor(COLORS["panel"])
    ax.grid(axis=grid_axis, linestyle="--", linewidth=0.8, alpha=0.35, color=COLORS["grid"])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(COLORS["summary_border"])
    ax.spines["bottom"].set_color(COLORS["summary_border"])
    add_card_border(ax)


def build_insight(sig_counter, src_counter, sev_counter):
    top_alert, alert_count = safe_top(sig_counter)
    top_ip, ip_count = safe_top(src_counter)
    top_sev, sev_count = safe_top(sev_counter)

    text = (
        f"The alert dataset is dominated by '{top_alert}', which appears {alert_count} times. "
        f"The most active source IP is {top_ip}, responsible for {ip_count} alerts, suggesting repeated "
        f"or automated activity. Severity level {top_sev} is the most common ({sev_count} alerts), "
        f"indicating that the IDS is mainly detecting persistent lower-priority behaviour."
    )
    return textwrap.fill(text, width=42)


def plot_horizontal_bar(ax, labels, values, title, color, log_scale=False):
    labels = truncate_labels(labels, max_len=24)
    bars = ax.barh(range(len(labels)), values, color=color)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()

    if log_scale and values and max(values) > 0:
        ax.set_xscale("log")
        ax.xaxis.set_major_formatter(ScalarFormatter())

    ax.set_title(title, fontsize=15, fontweight="bold", color=COLORS["primary"], pad=10)
    ax.set_xlabel("Alert Count", color=COLORS["primary"])
    style_ax(ax, grid_axis="x")

    max_val = max(values) if values else 1
    for i, v in enumerate(values):
        x = v * 1.06 if log_scale and v > 0 else v + max_val * 0.02
        ax.text(x, i, str(v), va="center", fontsize=10, color=COLORS["secondary"])


def plot_vertical_bar(ax, labels, values, title, color):
    labels = truncate_labels(labels, max_len=14)
    bars = ax.bar(range(len(labels)), values, color=color)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")

    ax.set_title(title, fontsize=15, fontweight="bold", color=COLORS["primary"], pad=10)
    ax.set_ylabel("Alert Count", color=COLORS["primary"])
    style_ax(ax, grid_axis="y")

    max_val = max(values) if values else 1
    for i, v in enumerate(values):
        ax.text(i, v + max_val * 0.02, str(v), ha="center", fontsize=10, color=COLORS["secondary"])


def plot_summary_panel(ax, total_alerts, latest_run, sig_counter, src_counter, sev_counter):
    ax.axis("off")
    ax.set_facecolor(COLORS["panel"])
    add_card_border(ax)

    top_alert = safe_top(sig_counter)
    top_ip = safe_top(src_counter)
    top_severity = safe_top(sev_counter)
    insight = build_insight(sig_counter, src_counter, sev_counter)

    ax.text(
        0.05, 0.97, "Executive Summary",
        fontsize=18, fontweight="bold", color=COLORS["primary"], va="top"
    )

    kpi_text = (
        f"TOTAL ALERTS\n{total_alerts}\n\n"
        f"TOP ALERT\n{str(top_alert[0])[:28]}...\n({top_alert[1]} occurrences)\n\n"
        f"TOP SOURCE IP\n{top_ip[0]} ({top_ip[1]})\n\n"
        f"COMMON SEVERITY\n{top_severity[0]} ({top_severity[1]})\n\n"
        f"LATEST RUN\n{os.path.basename(latest_run)}"
    )

    ax.text(
        0.05, 0.86, kpi_text,
        fontsize=11.5,
        color=COLORS["primary"],
        va="top",
        ha="left",
        linespacing=1.45,
        bbox=dict(
            boxstyle="round,pad=0.75",
            facecolor=COLORS["summary_bg"],
            edgecolor=COLORS["summary_border"]
        )
    )

    ax.text(
        0.05, 0.37, "Analytical Insight",
        fontsize=14, fontweight="bold", color=COLORS["primary"], va="top"
    )

    ax.text(
        0.05, 0.32, insight,
        fontsize=11,
        color=COLORS["secondary"],
        va="top",
        ha="left",
        linespacing=1.35,
        bbox=dict(
            boxstyle="round,pad=0.75",
            facecolor=COLORS["insight_bg"],
            edgecolor=COLORS["summary_border"]
        )
    )


def main():
    base_path = "/home/ubuntu/ids_analysis/run_baseline"
    eve_file = os.path.join(base_path, "eve.json")

    alerts = load_alerts(eve_file)
    print(f"Loaded {len(alerts)} alerts")

    sigs, cats, ips, sevs = extract_features(alerts)

    sig_counter = Counter(sigs)
    cat_counter = Counter(cats)
    ip_counter = Counter(ips)
    sev_counter = Counter(sevs)

    top_sigs = sig_counter.most_common(6)
    top_cats = cat_counter.most_common(6)
    top_ips = ip_counter.most_common(6)
    sev_dist = sev_counter.most_common()

    fig = plt.figure(figsize=(19, 10.5), facecolor=COLORS["background"])
    gs = GridSpec(
        3, 3,
        figure=fig,
        width_ratios=[1.1, 1.1, 1.05],
        height_ratios=[0.22, 1, 1]
    )

    fig.suptitle(
        "IDS Security Analysis Dashboard",
        fontsize=30,
        fontweight="bold",
        color=COLORS["primary"],
        x=0.34,
        y=0.965
    )

    fig.text(
        0.06, 0.92,
        "Suricata Alert Analysis",
        fontsize=13,
        color=COLORS["secondary"]
    )

    ax1 = fig.add_subplot(gs[1, 0])
    plot_horizontal_bar(
        ax1,
        [x[0] for x in top_sigs],
        [x[1] for x in top_sigs],
        "Top Alert Signatures",
        COLORS["blue"],
        log_scale=True
    )

    ax2 = fig.add_subplot(gs[1, 1])
    plot_horizontal_bar(
        ax2,
        [x[0] for x in top_cats],
        [x[1] for x in top_cats],
        "Top Alert Categories",
        COLORS["orange"],
        log_scale=True
    )

    ax3 = fig.add_subplot(gs[2, 0])
    plot_vertical_bar(
        ax3,
        [x[0] for x in top_ips],
        [x[1] for x in top_ips],
        "Top Source IPs",
        COLORS["green"]
    )

    ax4 = fig.add_subplot(gs[2, 1])
    plot_vertical_bar(
        ax4,
        [str(x[0]) for x in sev_dist],
        [x[1] for x in sev_dist],
        "Severity Distribution",
        COLORS["red"]
    )

    ax5 = fig.add_subplot(gs[1:, 2])
    plot_summary_panel(
        ax5,
        len(alerts),
        base_path,
        sig_counter,
        ip_counter,
        sev_counter
    )

    fig.subplots_adjust(
        left=0.08,
        right=0.965,
        top=0.89,
        bottom=0.11,
        wspace=0.34,
        hspace=0.48
    )

    output_path = os.path.join(base_path, "dashboard_final.png")
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"[OK] Dashboard saved to: {output_path}")
    plt.show()


if __name__ == "__main__":
    main()
