import numpy as np

from anomaly.features import extract
from anomaly.train import MODEL_VERSION, train


def _synthetic_events(make_event, n: int = 30):
    """Spread across event_types and sources to give IF some variety."""
    events = []
    for i in range(n):
        if i % 3 == 0:
            events.append(make_event(event_type="file.modified", source="wazuh.fim"))
        elif i % 3 == 1:
            events.append(make_event(
                event_type="network.flow", source="zeek.conn",
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=49152 + i, dst_port=443,
                protocol="tcp",
            ))
        else:
            events.append(make_event(
                event_type="network.http_request", source="zeek.http",
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=50000 + i, dst_port=80,
                protocol="tcp",
            ))
    return events


def test_train_returns_bundle_with_expected_keys(make_event):
    events = _synthetic_events(make_event, n=30)
    bundle = train(events)
    assert set(bundle.keys()) == {"model", "feature_names", "model_version"}
    assert bundle["model_version"] == MODEL_VERSION
    assert bundle["model_version"] == "isolation-forest-v1"


def test_train_pickle_feature_names_sorted(make_event):
    events = _synthetic_events(make_event, n=30)
    bundle = train(events)
    assert bundle["feature_names"] == sorted(bundle["feature_names"])
    # And the names match the extractor's output keys
    assert set(bundle["feature_names"]) == set(extract(events[0]).keys())


def test_train_is_deterministic(make_event):
    """random_state=42 makes the model deterministic — same inputs, same predictions."""
    events = _synthetic_events(make_event, n=30)
    bundle1 = train(events)
    bundle2 = train(events)
    # Build a small batch of feature vectors and compare decision_function outputs
    sample_features = [extract(e) for e in events[:5]]
    names = bundle1["feature_names"]
    X = np.array([[f[k] for k in names] for f in sample_features])
    d1 = bundle1["model"].decision_function(X)
    d2 = bundle2["model"].decision_function(X)
    assert np.allclose(d1, d2)
