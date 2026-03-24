import pandas as pd

SUSPICIOUS_COMMANDS = [
    "wget",
    "curl",
    "chmod",
    "busybox",
    "sh",
    "bash",
    "python",
    "perl",
    "nc",
    "ncat",
    "telnet",
    "ftp",
    "tftp",
    "cat /proc",
    "uname",
    "whoami",
    "ps",
    "sudo"
]

def detect_suspicious_commands(df, limit=20):
    command_events = df[df["eventid"] == "cowrie.command.input"]

    suspicious_rows = []

    for cmd in command_events["input"].dropna():
        cmd_lower = cmd.lower()
        for keyword in SUSPICIOUS_COMMANDS:
            if keyword in cmd_lower:
                suspicious_rows.append(cmd)
                break

    return pd.Series(suspicious_rows).value_counts().head(limit)

def detect_bruteforce_ips(df, threshold=20):
    failed = df[df["eventid"] == "cowrie.login.failed"]
    counts = failed["src_ip"].value_counts()

    return counts[counts >= threshold]

def detect_long_sessions(df, threshold=30):
    closed_sessions = df[df["eventid"] == "cowrie.session.closed"].copy()
    closed_sessions["duration"] = pd.to_numeric(closed_sessions["duration"], errors="coerce"
    )

    suspicious = closed_sessions[
    closed_sessions["duration"] >= threshold

    ]

    return suspicious[["session", "src_ip", "duration"]]\
        .sort_values(by="duration", ascending=False)