import os
import re
import pandas as pd

def parse_log_file(log_file_path):
    log_entries = []

    try:
        with open(log_file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # print(f"Processing line: {line.strip()}")
                match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - (.+)$', line.strip())
                if match:
                    timestamp, log_level, message = match.groups()
                    log_entries.append({
                        'timestamp': timestamp,
                        'log_level': log_level,
                        'message': message
                    })
    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")
    except Exception as e:
        print(f"Error reading file '{log_file_path}': {e}")

    return pd.DataFrame(log_entries)

# Test
if __name__ == "__main__":
    log_folder_path = 'logs'
    if not os.path.exists(log_folder_path):
        print(f"Log folder '{log_folder_path}' does not exist.")
    else:
        for file in os.listdir(log_folder_path):
            if file.endswith('.log'):  # Process only .log files
                file_path = os.path.join(log_folder_path, file)
                if os.stat(file_path).st_size == 0:  # Skip empty files
                    print(f"Skipping empty file: {file_path}")
                    continue
                print(f"Processing file: {file_path}")
                log_df = parse_log_file(file_path)
                print(log_df.head() if not log_df.empty else "No logs found.")
