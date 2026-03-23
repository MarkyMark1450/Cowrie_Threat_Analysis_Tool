from pathlib import Path

def save_text_report(report_text, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

def build_report(
    total_events,
    invalid_lines,
    event_types,
    top_source_ips,
    top_usernames,
    top_passwords,
    login_counts,
    successful_login_ips,
    activity_by_hour,
    top_command_inputs,
    suspicious_commands,
    sessions_per_ip,
    longest_sessions,
    average_session_duration,
    bruteforce_ips,
    long_sessions,
):
    report = []
    report.append("Cowrie Threat Analysis Report")
    report.append("=" * 40)
    report.append("")
    report.append(f"Total Valid Events: {total_events}")
    report.append(f"Invalid Lines Skipped: {invalid_lines}")
    report.append(f"Unique Event Types: {len(event_types)}")
    report.append("")
    report.append("Top Source IPs:")
    report.append(str(top_source_ips))
    report.append("")
    report.append("Top Usernames:")
    report.append(str(top_usernames))
    report.append("")
    report.append("Top Passwords:")
    report.append(str(top_passwords))
    report.append("")
    report.append("Login Results:")
    report.append(str(login_counts))
    report.append("")
    report.append("Top Successful Login IPs:")
    report.append(str(successful_login_ips))
    report.append("")
    report.append("Activity by Hour:")
    report.append(str(activity_by_hour))
    report.append("")
    report.append("Top Command Inputs:")
    report.append(str(top_command_inputs))
    report.append("")
    report.append("Suspicious Commands:")
    report.append(str(suspicious_commands))
    report.append("")
    report.append("Sessions per IP:")
    report.append(str(sessions_per_ip))
    report.append("")
    report.append("Longest Sessions:")
    report.append(str(longest_sessions))
    report.append("")
    report.append("Average Session Duration:")
    report.append(str(average_session_duration))
    report.append("")
    report.append("Bruteforce IPs:")
    report.append(str(bruteforce_ips))
    report.append("")
    report.append("Long Sessions:")
    report.append(str(long_sessions))
    report.append("")

    return "\n".join(report)