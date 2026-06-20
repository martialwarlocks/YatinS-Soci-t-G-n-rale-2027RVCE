from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_NAMES = [
    "login_frequency",
    "privilege_changes",
    "platform_count",
    "token_count",
    "failed_auth",
    "hour_variance",
    "geo_diversity",
    "dormancy_days",
]


def extract_features(
    identity: dict,
    audit_logs: list[dict],
    api_tokens: list[dict],
) -> dict[str, float]:
    usernames = {a.get("username") for a in identity.get("platform_accounts", {}).values()}
    user_logs = [a for a in audit_logs if a["user"] in usernames]

    login_count = sum(1 for a in user_logs if a["event_type"] == "login")
    priv_changes = sum(
        1 for a in user_logs if a["event_type"] in ("privilege_change", "role_escalation")
    )
    platform_count = len(identity.get("platform_accounts", {}))
    token_count = sum(1 for t in api_tokens if t["owner"] in usernames)
    failed_auth = sum(1 for a in user_logs if a["event_type"] == "failed_authentication")

    hour_variance = 0.0
    if user_logs:
        hours = [a["timestamp"].hour for a in user_logs]
        hour_variance = float(np.std(hours)) if len(hours) > 1 else 0.0

    geo_diversity = len({a.get("geo_location") for a in user_logs})

    dormant = 0
    for account in identity.get("platform_accounts", {}).values():
        ll = account.get("last_login")
        if ll:
            if isinstance(ll, datetime):
                days = (datetime.utcnow() - ll).days
            else:
                days = (datetime.utcnow() - datetime.fromisoformat(ll)).days
            dormant = max(dormant, days)

    return {
        "login_frequency": float(login_count),
        "privilege_changes": float(priv_changes),
        "platform_count": float(platform_count),
        "token_count": float(token_count),
        "failed_auth": float(failed_auth),
        "hour_variance": hour_variance,
        "geo_diversity": float(geo_diversity),
        "dormancy_days": float(dormant),
    }


def train_anomaly_detector(
    unified_identities: list[dict],
    audit_logs: list[dict],
    api_tokens: list[dict],
) -> tuple[IsolationForest, StandardScaler, list[str]]:
    features = []
    identity_ids = []

    for identity in unified_identities:
        f = extract_features(identity, audit_logs, api_tokens)
        features.append([f[name] for name in FEATURE_NAMES])
        identity_ids.append(identity["unified_id"])

    X = np.array(features)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.08, random_state=42, n_estimators=100)
    model.fit(X_scaled)

    return model, scaler, identity_ids


def detect_anomalies(
    model: IsolationForest,
    scaler: StandardScaler,
    identity_ids: list[str],
    unified_identities: list[dict],
    audit_logs: list[dict],
    api_tokens: list[dict],
) -> dict[str, dict[str, Any]]:
    features_list = []
    for identity in unified_identities:
        features_list.append(extract_features(identity, audit_logs, api_tokens))

    X = np.array([[f[name] for name in FEATURE_NAMES] for f in features_list])
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)

    results = {}
    for i, uid in enumerate(identity_ids):
        anomaly_score = round(float(-scores[i]) * 50 + 50, 1)
        anomaly_score = min(max(anomaly_score, 0), 100)
        results[uid] = {
            "is_anomaly": bool(predictions[i] == -1),
            "anomaly_score": anomaly_score,
            "features": {k: float(v) for k, v in features_list[i].items()},
        }

    return results


def explain_anomaly(features: dict[str, float], is_anomaly: bool) -> dict[str, Any]:
    """Explain why ML flagged this identity — based on feature deviation from norms."""
    reasons = []
    thresholds = {
        "privilege_changes": (2, "Unusual volume of privilege changes detected"),
        "failed_auth": (3, "Elevated failed authentication attempts"),
        "geo_diversity": (4, "Access from unusually diverse geographic regions"),
        "dormancy_days": (120, "Extreme dormancy combined with active credentials"),
        "token_count": (3, "High number of API tokens for single identity"),
        "hour_variance": (6, "Irregular login timing pattern (possible automation or compromise)"),
        "platform_count": (5, "Excessive cross-platform access breadth"),
        "login_frequency": (0.5, "Abnormally low login frequency with active privileges"),
    }

    for key, (threshold, message) in thresholds.items():
        val = features.get(key, 0)
        if key == "login_frequency" and val < threshold and features.get("dormancy_days", 0) > 60:
            reasons.append(message)
        elif key != "login_frequency" and val >= threshold:
            reasons.append(f"{message} ({key.replace('_', ' ')}: {val:.0f})")

    return {
        "is_anomaly": is_anomaly,
        "reasons": reasons[:5] if reasons else (["Behavioral profile deviates from peer baseline"] if is_anomaly else []),
        "features": features,
        "model": "Isolation Forest (contamination=0.08, 8 behavioral features)",
    }
