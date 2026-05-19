package intellifim.policy

# Default: benign event
default decision := {"score_delta": 0, "reason": "benign event"}

# Strong anomaly (score >= 0.7 wins regardless of is_anomaly flag)
decision := {"score_delta": 25, "reason": "strong anomaly (score >= 0.7)"} if {
    input.event.anomaly_score >= 0.7
}

# Moderate anomaly (is_anomaly true AND in [0.5, 0.7))
decision := {"score_delta": 10, "reason": "moderate anomaly"} if {
    input.event.is_anomaly == true
    input.event.anomaly_score >= 0.5
    input.event.anomaly_score < 0.7
}

# Weak anomaly (score in [0.3, 0.5), regardless of is_anomaly flag)
decision := {"score_delta": 5, "reason": "weak anomaly (score 0.3-0.5)"} if {
    input.event.anomaly_score >= 0.3
    input.event.anomaly_score < 0.5
}
