import joblib
import shap
import numpy as np

MODEL_PATH = "models/threat_model.joblib"
META_PATH = "models/model_meta.joblib"

FEATURE_LABELS = {
    "src_bytes": "Source traffic volume",
    "dst_bytes": "Destination traffic volume",
    "duration": "Connection duration",
    "failed_logins": "Failed login attempts",
    "num_compromised": "Compromise indicators"
}


def load_model():
    return joblib.load(MODEL_PATH)


def load_meta():
    return joblib.load(META_PATH)


def get_recommended_action(severity):
    actions = {
        "Low": "Monitor the activity, retain logs, and continue observation.",
        "Medium": "Investigate related logs, validate the event source, and review affected systems.",
        "High": "Escalate immediately, begin incident response, and contain affected assets if required."
    }
    return actions.get(severity, "Review the alert manually.")


def get_severity_class(severity):
    classes = {
        "Low": "low",
        "Medium": "medium",
        "High": "high"
    }
    return classes.get(severity, "low")


def get_false_positive_flag(confidence, severity):
    if not confidence:
        return False

    top_conf = confidence.get(severity, 0.0)

    if severity == "Medium" and top_conf < 65:
        return True
    if severity == "High" and top_conf < 75:
        return True

    return False


def get_shap_explanation(model, feature_names, row, prediction):
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(np.array(row))

        if isinstance(shap_values, list):
            class_names = list(model.classes_)
            class_index = class_names.index(prediction)
            class_shap_values = shap_values[class_index][0]
        else:
            class_names = list(model.classes_)
            class_index = class_names.index(prediction)
            class_shap_values = shap_values[0, :, class_index]

        feature_impacts = []
        for i, feature_name in enumerate(feature_names):
            feature_impacts.append({
                "feature": feature_name,
                "label": FEATURE_LABELS.get(feature_name, feature_name),
                "value": row[0][i],
                "impact": float(class_shap_values[i])
            })

        feature_impacts.sort(key=lambda x: abs(x["impact"]), reverse=True)
        return feature_impacts[:3]

    except Exception as e:
        return [{
            "feature": "xai_error",
            "label": "XAI Error",
            "value": "",
            "impact": 0.0,
            "message": str(e)
        }]


def build_ai_explanation(severity, top_factors):
    if top_factors and top_factors[0].get("feature") == "xai_error":
        return "The model produced a classification, but the explainability layer could not fully interpret this result."

    if not top_factors:
        return "The system classified this alert based on the available network behaviour indicators."

    sentences = []

    factor_names = [factor["label"] for factor in top_factors[:3]]
    joined = ", ".join(factor_names[:-1]) + f" and {factor_names[-1]}" if len(factor_names) > 1 else factor_names[0]

    sentences.append(
        f"The alert was classified as {severity.upper()} severity because {joined} contributed most strongly to the decision."
    )

    if any(f["feature"] == "failed_logins" for f in top_factors):
        sentences.append("This behaviour may be consistent with authentication abuse or brute-force activity.")

    if any(f["feature"] == "num_compromised" for f in top_factors):
        sentences.append("The compromise-related indicators increased suspicion that the activity may be malicious.")

    if any(f["feature"] in ["src_bytes", "dst_bytes", "duration"] for f in top_factors):
        sentences.append("The traffic volume and session behaviour appear abnormal compared to a low-risk baseline.")

    return " ".join(sentences)


def build_triage_report(alert, severity, confidence, ai_explanation, recommended_action, false_positive_risk):
    fp_line = (
        "This alert may require additional validation because the confidence pattern suggests a possible false positive."
        if false_positive_risk
        else "The confidence pattern does not strongly indicate a false positive."
    )

    return f"""Triage Summary
Alert {alert['id']} was analysed by the AI-assisted threat triage engine and classified as {severity.upper()} severity.

Alert Context
- Event Type: {alert['event_type']}
- Source IP: {alert['src_ip']}
- Destination IP: {alert['dst_ip']}
- Protocol: {alert['protocol']}
- Timestamp: {alert['timestamp']}

AI Explanation
{ai_explanation}

Confidence
{", ".join([f"{label}: {value}%" for label, value in confidence.items()])}

False Positive Assessment
{fp_line}

Recommended Analyst Action
{recommended_action}

Initial Conclusion
This triage output should support analyst decision-making rather than replace human verification. Further validation should be performed using endpoint logs, authentication records, and threat-intelligence checks where available.
"""


def predict_threat_from_features(features):
    model = load_model()
    meta = load_meta()
    feature_names = meta["feature_names"]

    row = [[
        float(features["src_bytes"]),
        float(features["dst_bytes"]),
        float(features["duration"]),
        float(features["failed_logins"]),
        float(features["num_compromised"])
    ]]

    prediction = model.predict(row)[0]

    confidence = {}
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(row)[0]
        classes = model.classes_
        confidence = {
            classes[i]: round(float(probabilities[i]) * 100, 2)
            for i in range(len(classes))
        }

    top_factors = get_shap_explanation(model, feature_names, row, prediction)
    ai_explanation = build_ai_explanation(prediction, top_factors)
    false_positive_risk = get_false_positive_flag(confidence, prediction)

    score_map = {
        "Low": 1,
        "Medium": 3,
        "High": 5
    }

    return {
        "severity": prediction,
        "severity_class": get_severity_class(prediction),
        "score": score_map.get(prediction, 0),
        "confidence": confidence,
        "recommended_action": get_recommended_action(prediction),
        "top_factors": top_factors,
        "ai_explanation": ai_explanation,
        "false_positive_risk": false_positive_risk
    }