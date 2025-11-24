import os
import argparse
from datetime import datetime, timedelta

from src.FIM.FIM import MonitorChanges
from src.Authentication.Authentication import Authentication
from src.utils.anomaly_detection import parse_log_file, load_vectorizer_model
from src.api.database.connection import FimSessionLocal


class CLI:
    def __init__(self):
        self.monitor_changes = MonitorChanges()
        self.authentication = Authentication()
        self.exclude_files = []
        self.authenticated = False
        self.auth_expiry = None
        self.auth_user = ""

    def _require_auth(self):
        if self.auth_expiry and datetime.now() < self.auth_expiry:
            return
        self.auth_user = self.authentication.authorised_credentials()
        self.auth_expiry = datetime.now() + timedelta(minutes=15)  # 15min session

    def main(self):
        parser = argparse.ArgumentParser(description="File Integrity Monitor CLI Tool")
        parser.add_argument("-m", "--monitor", action="store_true", help="Start monitoring multiple directory")
        parser.add_argument("-v", "--view-baseline", action="store_true", help="View the current baseline data")
        parser.add_argument("-r", "--reset-baseline", action="store_true", help="Reset the baseline data")
        parser.add_argument("-l", "--view-logs", action="store_true", help="View the log file")
        parser.add_argument("-a", "--analyze-logs", action="store_true", help="Analyze the log file for anomalies")
        parser.add_argument("-e", "--exclude", type=str, help="Exclude selected file and folder")
        parser.add_argument("-d", "--dir", nargs="+", type=str, help="Add directories to monitor.")

        args = parser.parse_args()
        monitored_dirs = []
        if args.dir is not None:
            monitored_dirs = [os.path.abspath(dir) for dir in args.dir]

        db_session = FimSessionLocal() if any([args.monitor, args.reset_baseline, args.view_baseline]) else None

        if any([args.monitor, args.reset_baseline, args.analyze_logs]):
            self._require_auth()
            self.authenticated = True

        try:
            if args.analyze_logs:
                log_folder_path = 'logs'
                for file in os.listdir(log_folder_path):
                    file_path = os.path.join(log_folder_path, file)
                    log_df = parse_log_file(file_path)
                    if log_df.empty:
                        print("No log data found.")
                    else:
                        vectorizer, model = load_vectorizer_model()
                        if vectorizer is None or model is None:
                            print("Model not trained. Run anomaly_detection.py first.")
                            return

                        X = vectorizer.transform(log_df['message'])
                        log_df['anomaly'] = model.predict(X)
                        log_df['anomaly'] = log_df['anomaly'].apply(lambda x: 'anomaly' if x == -1 else 'normal')
                        log_df.to_csv('log_anomalies.csv', index=False)
                        print("Anomalies saved to log_anomalies.csv")
                        print(log_df.head())

            if args.view_baseline:
                self.monitor_changes.view_baseline()

            if args.reset_baseline:
                if args.dir is None:
                    print("Please specify directories.")
                    parser.print_help()
                else:
                    self.monitor_changes.reset_baseline(self.auth_user or "None", monitored_dirs)

            if not any(vars(args).values()):
                parser.print_help()
                return

            if args.view_logs:
                self.monitor_changes.view_logs()

            if args.exclude:
                self.exclude_files.append(args.exclude)

            if args.monitor:
                if args.dir is None:
                    print("Please specify directories.")
                    parser.print_help()
                else:
                    valid_dirs = []
                    for directory in monitored_dirs:
                        if not os.path.exists(directory):
                            print(f"Creating directory: {directory}")
                            os.makedirs(directory, exist_ok=True)
                        valid_dirs.append(os.path.abspath(directory))

                    print("Starting the Integrity Monitor. Use Ctrl+C to exit")
                    try:
                        self.monitor_changes.monitor_changes(self.auth_user, valid_dirs, self.exclude_files, db_session)
                    except KeyboardInterrupt:
                        print("\nMonitoring stopped. Cleaning up...")
                        raise SystemExit
                    
        finally:
            if db_session:
                db_session.close()


if __name__ == "__main__":
    cli = CLI()
    cli.main()
