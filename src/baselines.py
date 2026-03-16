# baselines.py
# Train traditional baselines and compare them with the MLP model.

from pathlib import Path
import json

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORTS_DIR = PROJECT_ROOT / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    # Load processed arrays.
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy")
    return X_train, y_train, X_test, y_test


def evaluate_model(name, model, X_train, y_train, X_test, y_test):
    # Fit and evaluate one model.
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    result = {
        "model": name,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }
    return result


def save_table(results):
    # Save a simple comparison table.
    lines = []
    header = (
        f"{'Model':<24}"
        f"{'Accuracy':>12}"
        f"{'Precision':>12}"
        f"{'Recall':>12}"
        f"{'F1':>12}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for item in results:
        line = (
            f"{item['model']:<24}"
            f"{item['accuracy']:>12.4f}"
            f"{item['precision']:>12.4f}"
            f"{item['recall']:>12.4f}"
            f"{item['f1']:>12.4f}"
        )
        lines.append(line)

    (REPORTS_DIR / "baseline_comparison.txt").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def main():
    X_train, y_train, X_test, y_test = load_data()

    results = []

    lr = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )
    results.append(
        evaluate_model("LogisticRegression", lr, X_train, y_train, X_test, y_test)
    )

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    results.append(
        evaluate_model("RandomForest", rf, X_train, y_train, X_test, y_test)
    )

    # Add your current MLP result manually for comparison.
    mlp_result = {
        "model": "MLP_Final",
        "accuracy": 0.8789170674828742,
        "precision": 0.8453755249536088,
        "recall": 0.9547119032912733,
        "f1": 0.8967231966185627,
    }
    results.append(mlp_result)

    with open(REPORTS_DIR / "baseline_metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    save_table(results)

    print("Baseline comparison saved to:")
    print(REPORTS_DIR / "baseline_metrics.json")
    print(REPORTS_DIR / "baseline_comparison.txt")
    print("\nResults:")
    for item in results:
        print(item)


if __name__ == "__main__":
    main()