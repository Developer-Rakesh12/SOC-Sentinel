
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "dst_port",
    "protocol", "bytes", "event_type", "action"
]


def analyze_logs(df):
    """Analyze sample network logs and generate security alerts."""

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    logs = df.copy()
    logs["bytes"] = pd.to_numeric(logs["bytes"], errors="coerce").fillna(0)
    logs["dst_port"] = pd.to_numeric(
        logs["dst_port"], errors="coerce"
    )

    alerts = []

    # Rule 1: Repeated failed login attempts
    failed = logs[logs["event_type"].str.lower() == "failed_login"]

    for ip, group in failed.groupby("src_ip"):
        if len(group) >= 5:
            alerts.append({
                "severity": "Critical",
                "alert_type": "Repeated Failed Login",
                "source_ip": ip,
                "count": len(group),
                "description": "Multiple failed login events detected."
            })

    # Rule 2: Repeated firewall blocks
    blocked = logs[
        logs["action"].astype(str).str.lower().isin(["blocked", "deny"])
    ]

    for ip, group in blocked.groupby("src_ip"):
        if len(group) >= 2:
            alerts.append({
                "severity": "High",
                "alert_type": "Repeated Firewall Blocks",
                "source_ip": ip,
                "count": len(group),
                "description": "Repeated blocked connections detected."
            })

    # Rule 3: Large data transfer
    large = logs[logs["bytes"] >= 5_000_000]

    for _, row in large.iterrows():
        alerts.append({
            "severity": "High",
            "alert_type": "Large Data Transfer",
            "source_ip": row["src_ip"],
            "count": 1,
            "description": f"Large transfer of {int(row['bytes'])} bytes detected."
        })

    # Rule 4: Unusual destination ports
    unusual_ports = [23, 4444, 3389]
    unusual = logs[logs["dst_port"].isin(unusual_ports)]

    for _, row in unusual.iterrows():
        alerts.append({
            "severity": "Medium",
            "alert_type": "Unusual Destination Port",
            "source_ip": row["src_ip"],
            "count": 1,
            "description": f"Connection to destination port {int(row['dst_port'])}."
        })

    return pd.DataFrame(
        alerts,
        columns=[
            "severity", "alert_type", "source_ip",
            "count", "description"
        ]
    )
