import json
from pathlib import Path
import pandas as pd

def events_to_dataframe(events):
    rows = []

    for event in events:
        rows.append({
            "timestamp": event.get("timestamp"),
            "eventid": event.get("eventid"),
            "src_ip": event.get("src_ip"),
            "session": event.get("session"),
            "username": event.get("username"),
            "password": event.get("password"),
            "message": event.get("message"),
            "input": event.get("input"),
            "duration": event.get("duration"),
            "version": event.get("version")
        })

    return pd.DataFrame(rows)

def load_cowrie_logs(file_path):
    events = []
    invalid_lines = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                invalid_lines += 1
                print(f"Skipping invalid JSON on line {line_number}")

    return events, invalid_lines

def get_unique_event_types(events):
    event_types = set()  # Stores only unique event types

    for event in events:
        event_id = event.get("eventid")

        if event_id:
            event_types.add(event_id)

    return sorted(event_types)

def print_sample_events(events, sample_size=5):  # Prints the indicated amount of sample events
    print("\nSample events:")
    for event in events[:sample_size]:
        print({
            "timestamp": event.get("timestamp"),
            "eventid": event.get("eventid"),
            "src_ip": event.get("src_ip"),
            "session": event.get("session"),
            "username": event.get("username"),
            "password": event.get("password"),
            "message": event.get("message")
        })

#  Debug main block (disabled)
#  For parser testing if needed later

#  if __name__ == "__main__":
#    file_path = Path(__file__).resolve().parent.parent / "data" / "cowrie_week_merged.json"  # Loads log data from file path

#    events, invalid_lines = load_cowrie_logs(file_path)

#    print(f"Total valid events: {len(events)}")
#    print(f"Invalid lines skipped: {invalid_lines}")

#    event_types = get_unique_event_types(events)

#    print("\nUnique event types found:")

#    for event_type in event_types:
#        print(event_type)

#    print_sample_events(events)

#    df = events_to_dataframe(events)
#    print(df.head())
#    print(df.columns)"""