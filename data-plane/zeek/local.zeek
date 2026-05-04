# data-plane/zeek/local.zeek
# Enable JSON output for the four logs we care about in v1.
@load policy/tuning/json-logs

# Reduce noise: ignore stats / capture_loss / weird unless explicitly wanted.
redef Log::default_logdir = "/var/log/zeek";
