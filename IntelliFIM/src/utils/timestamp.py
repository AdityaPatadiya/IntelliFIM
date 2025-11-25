from datetime import datetime
import pytz

def timezone():
    timezone = pytz.timezone("Asia/Kolkata")
    timestamp = datetime.now(timezone).strftime(r"%Y-%m-%d %H:%M:%S")
    return timestamp, timezone
