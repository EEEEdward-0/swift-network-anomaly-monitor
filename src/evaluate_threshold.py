# evaluate_threshold.py
# Evaluate threshold settings and plot ROC/PR curves.

from pathlib import Path
import json

import numpy as np
import matplotlib.pyplot as plt
import torch
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
)

from experiments.train_mlp import MLP


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    # Load processed arrays.
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy")
    return X_train, y_train, X_test, y_test


def get_probabilities(model, data_loader, device):
    # Get attack probabilities from the model.
    model.eval()
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for X_batch, y_batch in data_loader:
            X_batch = X_batch.to(device)
            outputs = model(X_batch)
            probs = torch.softmax(outputs, dim=1)[:, 1]

            all_probs.extend(probs.cpu().numpy())
            all_labels.extend(y_batch.numpy())

    return np.array(all_probs), np.array(all_labels)


def evaluate_at_threshold(y_true, y_prob, threshold):
    # Evaluate metrics at a given threshold.
    y_pred = (y_prob >= threshold).astype(int)

    acc = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "threshold": float(threshold),
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": float(fpr),
        "confusion_matrix": cm.tolist(),
    }


def plot_roc_pr(y_true, y_prob):
    # Save ROC and PR curves.
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)

    precision, recall, _ = precision_recall_curve(y_true, y_prob)

    plt.figure(figsize=(10, 4))

    plt.subplot(1, 2, 1)
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()

    plt.subplot(1, 2, 2)
    plt.plot(recall, precision)
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve")

    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "roc_pr_curves.png", dpi=200)
    plt.close()


def save_threshold_table(results_dict):
    # Save a simple threshold comparison table as text.
    lines = []
    header = (
        f"{'Setting':<22}"
        f"{'Threshold':>10}"
        f"{'Accuracy':>12}"
        f"{'Precision':>12}"
        f"{'Recall':>12}"
        f"{'F1':>12}"
        f"{'FPR':>12}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for name, result in results_dict.items():
        line = (
            f"{name:<22}"
            f"{result['threshold']:>10.2f}"
            f"{result['accuracy']:>12.4f}"
            f"{result['precision']:>12.4f}"
            f"{result['recall']:>12.4f}"
            f"{result['f1']:>12.4f}"
            f"{result['false_positive_rate']:>12.4f}"
        )
        lines.append(line)

    output_path = REPORTS_DIR / "threshold_comparison.txt"
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print("Device:", device)

    X_train_full, y_train_full, X_test, y_test = load_data()

    # Rebuild the same validation split used in training.
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=0.20,
        random_state=42,
        stratify=y_train_full,
    )

    val_loader = DataLoader(
        TensorDataset(
            torch.tensor(X_val, dtype=torch.float32),
            torch.tensor(y_val, dtype=torch.long),
        ),
        batch_size=512,
        shuffle=False,
    )

    test_loader = DataLoader(
        TensorDataset(
            torch.tensor(X_test, dtype=torch.float32),
            torch.tensor(y_test, dtype=torch.long),
        ),
        batch_size=512,
        shuffle=False,
    )

    model = MLP(input_dim=X_train.shape[1]).to(device)
    model.load_state_dict(torch.load(MODELS_DIR / "best_mlp_ids.pt", map_location=device))

    val_probs, val_labels = get_probabilities(model, val_loader, device)
    test_probs, test_labels = get_probabilities(model, test_loader, device)

    # Search the best threshold on the validation set.
    thresholds = np.arange(0.30, 0.81, 0.02)
    validation_results = []
    best_result = None

    for threshold in thresholds:
        result = evaluate_at_threshold(val_labels, val_probs, threshold)
        validation_results.append(result)

        if best_result is None or result["f1"] > best_result["f1"]:
            best_result = result

    # Evaluate selected thresholds on the test set.
    default_threshold = 0.50
    high_recall_threshold = 0.36
    best_threshold = best_result["threshold"]

    test_default = evaluate_at_threshold(test_labels, test_probs, default_threshold)
    test_best = evaluate_at_threshold(test_labels, test_probs, best_threshold)
    test_high_recall = evaluate_at_threshold(test_labels, test_probs, high_recall_threshold)

    print("Best threshold on validation set:")
    print(best_result)

    print("\nTest result at default threshold 0.50:")
    print(test_default)

    print("\nTest result at best validation threshold:")
    print(test_best)

    print("\nTest result at high-recall threshold 0.36:")
    print(test_high_recall)

    summary = {
        "best_validation_threshold": best_result,
        "test_default_threshold_0.50": test_default,
        "test_best_validation_threshold": test_best,
        "test_high_recall_threshold_0.36": test_high_recall,
        "validation_results": validation_results,
    }

    with open(REPORTS_DIR / "threshold_search.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    comparison_results = {
        "Default_0.50": test_default,
        "Best_on_Val": test_best,
        "High_Recall_0.36": test_high_recall,
    }
    save_threshold_table(comparison_results)

    plot_roc_pr(test_labels, test_probs)

    print(f"\nSaved ROC/PR curves to: {REPORTS_DIR / 'roc_pr_curves.png'}")
    print(f"Saved threshold search to: {REPORTS_DIR / 'threshold_search.json'}")
    print(f"Saved threshold comparison to: {REPORTS_DIR / 'threshold_comparison.txt'}")


if __name__ == "__main__":
    main()