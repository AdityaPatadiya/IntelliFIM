package intellifim.policy

test_benign_event_returns_zero if {
    d := decision with input as {"event": {"anomaly_score": 0.1, "is_anomaly": false}}
    d == {"score_delta": 0, "reason": "benign event"}
}

test_weak_anomaly_returns_five if {
    d := decision with input as {"event": {"anomaly_score": 0.4, "is_anomaly": false}}
    d.score_delta == 5
    d.reason == "weak anomaly (score 0.3-0.5)"
}

test_moderate_anomaly_returns_ten if {
    d := decision with input as {"event": {"anomaly_score": 0.6, "is_anomaly": true}}
    d.score_delta == 10
    d.reason == "moderate anomaly"
}

test_strong_anomaly_returns_twenty_five if {
    d := decision with input as {"event": {"anomaly_score": 0.85, "is_anomaly": true}}
    d.score_delta == 25
    d.reason == "strong anomaly (score >= 0.7)"
}

test_high_score_with_is_anomaly_false_still_strong if {
    # score >= 0.7 wins regardless of is_anomaly flag
    d := decision with input as {"event": {"anomaly_score": 0.9, "is_anomaly": false}}
    d.score_delta == 25
}
