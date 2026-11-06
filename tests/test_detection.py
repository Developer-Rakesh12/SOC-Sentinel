
import pandas as pd
import pytest

from detection.threat_detector import analyze_logs


def test_failed_login_detection():
    df = pd.DataFrame({
        "timestamp": ["2026-11-06"] * 5,
        "src_ip": ["192.168.1.50"] * 5,
        "dst_ip": ["192.168.1.20"] * 5,
        "dst_port": [22] * 5,
        "protocol": ["TCP"] * 5,
        "bytes": [500] * 5,
        "event_type": ["failed_login"] * 5,
        "action": ["allowed"] * 5
    })

    alerts = analyze_logs(df)

    assert len(alerts) == 1
    assert alerts.iloc[0]["severity"] == "Critical"


def test_empty_logs():
    df = pd.DataFrame(columns=[
        "timestamp", "src_ip", "dst_ip", "dst_port",
        "protocol", "bytes", "event_type", "action"
    ])

    alerts = analyze_logs(df)

    assert alerts.empty


def test_missing_columns():
    df = pd.DataFrame({"src_ip": ["192.168.1.10"]})

    with pytest.raises(ValueError):
        analyze_logs(df)

