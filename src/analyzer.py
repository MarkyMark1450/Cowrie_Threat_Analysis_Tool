import pandas as pd
from pathlib import Path
from parser import load_cowrie_logs, events_to_dataframe, get_unique_event_types
from visualizer import plot_bar_series
from reporter import build_report, save_text_report

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

def get_suspicious_commands(df, limit=20):
    command_events = df[df["eventid"] == "cowrie.command.input"]

    suspicious_rows = []

    for cmd in command_events["input"].dropna():
        cmd_lower = cmd.lower()
        for keyword in SUSPICIOUS_COMMANDS:
            if keyword in cmd_lower:
                suspicious_rows.append(cmd)
                break

    return pd.Series(suspicious_rows).value_counts().head(limit)

def get_top_source_ips(df, limit=10):
    counts = df["src_ip"].value_counts()
    return counts.head(limit)

def get_top_usernames(df, limit=10):
    counts = df["username"].value_counts()
    return counts.head(limit)

def get_top_passwords(df, limit=10):
    counts = df["password"].value_counts()
    return counts.head(limit)

def get_event_type_counts(df):
    return df["eventid"].value_counts()

def get_login_counts(df):
    login_events = df[df["eventid"].isin([
        "cowrie.login.success",
        "cowrie.login.failed"
    ])]

    return login_events["eventid"].value_counts()

def get_successful_login_ips(df, limit=10):
    successful_logins = df[df["eventid"] == "cowrie.login.success"]
    return successful_logins["src_ip"].value_counts().head(limit)

def get_successful_login_usernames(df, limit=10):
    successful_logins = df[df["eventid"] == "cowrie.login.success"]
    return successful_logins["username"].value_counts().head(limit)

def get_successful_login_passwords(df, limit=10):
    successful_logins = df[df["eventid"] == "cowrie.login.success"]
    return successful_logins["password"].value_counts().head(limit)

def add_datetime_column(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

def get_activity_by_hour(df):
    hours = df["timestamp"].dt.hour
    return hours.value_counts().sort_index()

def get_input_commands(df, limit=20):
    command_events = df[df["eventid"] == "cowrie.command.input"]
    return command_events["input"].value_counts().head(limit)

def get_sessions_per_ip(df, limit=10):
    session_events = df[df["eventid"] == "cowrie.session.connect"]
    return session_events["src_ip"].value_counts().head(limit)

def get_longest_sessions(df, limit=10):
    closed_sessions = df[df["eventid"] == "cowrie.session.closed"].copy()
    closed_sessions["duration"] = pd.to_numeric(closed_sessions["duration"], errors="coerce")

    longest_sessions = closed_sessions.sort_values(by="duration", ascending=False)

    return longest_sessions[["session", "src_ip", "duration"]].head(limit)

def get_average_session_duration(df):
    closed_sessions = df[df["eventid"] == "cowrie.session.closed"].copy()
    closed_sessions["duration"] = pd.to_numeric(closed_sessions["duration"], errors="coerce")

    return closed_sessions["duration"].mean()

def detect_bruteforce_ips(df, threshold=20):
    failed_logins = df[df["eventid"] == "cowrie.login.failed"]

    counts = failed_logins["src_ip"].value_counts()

    suspicious = counts[counts >= threshold]

    return suspicious

def detect_long_sessions(df, threshold=30):
    closed_sessions = df[df["eventid"] == "cowrie.session.closed"].copy()
    closed_sessions["duration"] = pd.to_numeric(closed_sessions["duration"], errors="coerce")

    suspicious_sessions = closed_sessions[closed_sessions["duration"] >= threshold]

    return suspicious_sessions[["session", "src_ip", "duration"]].sort_values(
        by="duration",
        ascending=False
    )

#  if __name__ == "__main__":
    file_path = Path(__file__).resolve().parent.parent / "data" / "cowrie_week_merged.json"

    events, invalid_lines = load_cowrie_logs(file_path)

    event_types = get_unique_event_types(events)

    df = events_to_dataframe(events)

    df = add_datetime_column(df)

    output_dir = Path(__file__).resolve().parent.parent / "output" / "graphs"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\nTop Source IPs:")
    print(get_top_source_ips(df))

    print("\nTop Usernames:")
    print(get_top_usernames(df))

    print("\nTop Passwords:")
    print(get_top_passwords(df))

    print("\nEvent Type Counts:")
    print(get_event_type_counts(df))

    print("\nLogin Results:")
    print(get_login_counts(df))

    print("\nTop IPs with Successful Logins:")
    print(get_successful_login_ips(df))

    print("\nTop Usernames with Successful Logins:")
    print(get_successful_login_usernames(df))

    print("\nTop Passwords with Successful Logins:")
    print(get_successful_login_passwords(df))

    print("\nActivity by Hour:")
    print(get_activity_by_hour(df))

    print("\nTop Command Inputs:")
    print(get_input_commands(df))

    print("\nSuspicious Commands:")
    print(get_suspicious_commands(df))

    print("\nSessions per IP:")
    print(get_sessions_per_ip(df))

    print("\nLongest Sessions:")
    print(get_longest_sessions(df))

    print("\nAverage Session Duration:")
    print(get_average_session_duration(df))

    print("\nBruteforce IPs:")
    print(detect_bruteforce_ips(df))

    plot_bar_series(
        get_top_source_ips(df),
        title="Top Source IPs",
        xlabel="Source IPs",
        ylabel="Count",
        output_path=output_dir / "Top_Source_IPs.png"
    )

    plot_bar_series(
        get_login_counts(df),
        title="Login Results",
        xlabel="Event",
        ylabel="Count",
        output_path = output_dir / "Login_Results.png"
    )

    plot_bar_series(
        get_activity_by_hour(df),
        title="Activity by Hour",
        xlabel="Hour",
        ylabel="Events",
        output_path = output_dir / "Activity_by_Hour.png"
    )

    report_text = build_report(
        total_events=len(events),
        invalid_lines=invalid_lines,
        event_types=get_event_type_counts(df),
        top_source_ips=get_top_source_ips(df),
        top_usernames=get_top_usernames(df),
        top_passwords=get_top_passwords(df),
        login_counts=get_login_counts(df),
        successful_login_ips=get_successful_login_ips(df),
        activity_by_hour=get_activity_by_hour(df),
        top_command_inputs=get_input_commands(df),
        suspicious_commands=get_suspicious_commands(df),
        sessions_per_ip=get_sessions_per_ip(df),
        longest_sessions=get_longest_sessions(df),
        average_session_duration=get_average_session_duration(df)
    )

    report_path = Path(__file__).resolve().parent.parent / "output" / "reports" / "cowrie_threat_report.txt"
    save_text_report(report_text, report_path)

    print(f"\nReport saved to: {report_path}")

