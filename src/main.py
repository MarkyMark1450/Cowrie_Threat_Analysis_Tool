import argparse
from pathlib import Path

from parser import (
    load_cowrie_logs,
    events_to_dataframe,
    #  get_unique_event_types
)

from analyzer import (
    get_top_source_ips,
    get_top_usernames,
    get_top_passwords,
    get_event_type_counts,
    get_login_counts,
    get_successful_login_ips,
    get_successful_login_usernames,
    get_successful_login_passwords,
    add_datetime_column,
    get_activity_by_hour,
    get_input_commands,
    get_suspicious_commands,
    get_sessions_per_ip,
    get_longest_sessions,
    get_average_session_duration,
    detect_bruteforce_ips,
    detect_long_sessions
)

from visualizer import plot_bar_series

from reporter import (
    build_report,
    save_text_report
)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Cowrie threat analysis tool"
    )

    parser.add_argument(
        "--file",
        type=str,
        default="data/cowrie_week_merged.json",
        help="Path to the cowrie log file"
    )

    parser.add_argument(
        "--graphs",
        action="store_true",
        help="Generate graphs"
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate text report"
    )

    parser.add_argument(
        "--bruteforce-threshold",
        type=int,
        default=20,
        help="Minimum failed login attempts to flag an IP as brute force"
    )

    parser.add_argument(
        "--long-session-threshold",
        type=float,
        default=30,
        help="Minimum session duration in seconds to flag a session as long"
    )

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    file_path = Path(args.file)

    events, invalid_lines = load_cowrie_logs(file_path)
    #  event_types = get_unique_event_types(events)

    df = events_to_dataframe(events)
    df = add_datetime_column(df)

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

    bruteforce_ips = detect_bruteforce_ips(
        df,
        threshold=args.bruteforce_threshold
    )

    print("\nBruteforce IPs:")
    print(bruteforce_ips)

    long_sessions = detect_long_sessions(
        df,
        threshold=args.long_session_threshold
    )

    print("\nLong Sessions:")
    print(long_sessions)


    if args.graphs:
        output_dir = Path(__file__).resolve().parent.parent / "output" / "graphs"
        output_dir.mkdir(parents=True, exist_ok=True)

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
            output_path=output_dir / "Login_Results.png"
        )

        plot_bar_series(
            get_activity_by_hour(df),
            title="Activity by Hour",
            xlabel="Hour",
            ylabel="Events",
            output_path=output_dir / "Activity_by_Hour.png"
        )

        print(f"\nGraphs saved to: {output_dir}")

    if args.report:
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
            average_session_duration=get_average_session_duration(df),
            bruteforce_ips=bruteforce_ips,
            long_sessions=long_sessions
        )

        report_path = Path(__file__).resolve().parent.parent / "output" / "reports" / "cowrie_threat_report.txt"
        save_text_report(report_text, report_path)

        print(f"\nReport saved to: {report_path}")