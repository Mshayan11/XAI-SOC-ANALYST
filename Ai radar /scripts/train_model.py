import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

DATA_PATH = "data/sample_logs.csv"
MODEL_PATH = "models/threat_model.joblib"
META_PATH = "models/model_meta.joblib"

FEATURE_COLUMNS = [
    "src_bytes",
    "dst_bytes",
    "duration",
    "failed_logins",
    "num_compromised"
]

TARGET_COLUMN = "severity"


def main():
    df = pd.read_csv(DATA_PATH)

    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nClassification Report:\n")
    print(classification_report(y_test, predictions))

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(
        {
            "feature_names": FEATURE_COLUMNS,
            "class_names": list(model.classes_)
        },
        META_PATH
    )

    print(f"Model saved to {MODEL_PATH}")
    print(f"Metadata saved to {META_PATH}")


if __name__ == "__main__":
    main()