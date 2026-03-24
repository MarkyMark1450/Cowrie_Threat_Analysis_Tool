import time
import json

def tail_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        f.seek(0, 2) #  Goes to end of file

        while True:
            line = f.readline()

            if not line:
                time.sleep(1)
                continue

            try:
                event = json.loads(line.strip())
                print_event(event)
            except json.JSONDecodeError:
                continue

def print_event(event):
    print({
        "timestamp": event.get("timestamp"),
        "eventid": event.get("eventid"),
        "src_ip": event.get("src_ip"),
        "input": event.get("input")
    })

if __name__ == "__main__":
    file_path = "data/cowrie.log"
    tail_file(file_path)