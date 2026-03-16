# train_mlp_ane_v2.py
# Train a deeper residual MLP variant for ANE-friendly experiments.

from pathlib import Path
import json
import copy

import numpy as np
import matplotlib.pyplot as plt
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    classification_report,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    # Load processed arrays.
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy")
    return X_train, y_train, X_test, y_test


def build_dataloaders(X_train, y_train, X_val, y_val, X_test, y_test, batch_size=256):
    # Convert arrays to tensors.
    train_dataset = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.long),
    )
    val_dataset = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.long),
    )
    test_dataset = TensorDataset(
        torch.tensor(X_test, dtype=torch.float32),
        torch.tensor(y_test, dtype=torch.long),
    )

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    return train_loader, val_loader, test_loader


class ResidualBlock(nn.Module):
    def __init__(self, dim: int, dropout: float):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
        )
        self.activation = nn.ReLU()

    def forward(self, x):
        return self.activation(x + self.block(x))


class MLPANEFriendlyV2(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()

        self.input_layer = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.ReLU(),
        )

        self.res_block_1 = ResidualBlock(512, dropout=0.20)
        self.res_block_2 = ResidualBlock(512, dropout=0.20)

        self.down_1 = nn.Sequential(
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.15),
        )

        self.res_block_3 = ResidualBlock(256, dropout=0.15)

        self.down_2 = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.10),
        )

        self.output_layer = nn.Linear(128, 2)

    def forward(self, x):
        x = self.input_layer(x)
        x = self.res_block_1(x)
        x = self.res_block_2(x)
        x = self.down_1(x)
        x = self.res_block_3(x)
        x = self.down_2(x)
        x = self.output_layer(x)
        return x


def get_class_weights(y_train):
    # Build class weights for imbalanced data.
    classes, counts = np.unique(y_train, return_counts=True)
    total = counts.sum()
    weights = total / (len(classes) * counts)
    class_weights = np.zeros(len(classes), dtype=np.float32)

    for cls, w in zip(classes, weights):
        class_weights[int(cls)] = w

    return torch.tensor(class_weights, dtype=torch.float32)


def evaluate_model(model, data_loader, device, criterion=None):
    # Evaluate loss and classification metrics.
    model.eval()

    all_labels = []
    all_preds = []
    total_loss = 0.0
    total_samples = 0

    with torch.no_grad():
        for X_batch, y_batch in data_loader:
            X_batch = X_batch.to(device)
            y_batch = y_batch.to(device)

            outputs = model(X_batch)

            if criterion is not None:
                loss = criterion(outputs, y_batch)
                total_loss += loss.item() * X_batch.size(0)
                total_samples += X_batch.size(0)

            preds = torch.argmax(outputs, dim=1)

            all_labels.extend(y_batch.cpu().numpy())
            all_preds.extend(preds.cpu().numpy())

    avg_loss = total_loss / total_samples if total_samples > 0 else None
    acc = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, zero_division=0)
    precision = precision_score(all_labels, all_preds, zero_division=0)
    recall = recall_score(all_labels, all_preds, zero_division=0)

    return {
        "loss": avg_loss,
        "accuracy": acc,
        "f1": f1,
        "precision": precision,
        "recall": recall,
        "labels": np.array(all_labels),
        "preds": np.array(all_preds),
    }


def plot_training_curves(history):
    # Save training curves.
    epochs = range(1, len(history["train_loss"]) + 1)

    plt.figure(figsize=(10, 4))

    plt.subplot(1, 2, 1)
    plt.plot(epochs, history["train_loss"], label="Train Loss")
    plt.plot(epochs, history["val_loss"], label="Val Loss")
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.title("ANE V2 Loss Curves")
    plt.legend()

    plt.subplot(1, 2, 2)
    plt.plot(epochs, history["val_f1"], label="Val F1")
    plt.plot(epochs, history["val_acc"], label="Val Accuracy")
    plt.xlabel("Epoch")
    plt.ylabel("Score")
    plt.title("ANE V2 Validation Metrics")
    plt.legend()

    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "training_curves_ane_v2.png", dpi=200)
    plt.close()


def plot_confusion_matrix(cm):
    # Save confusion matrix figure.
    plt.figure(figsize=(5, 4))
    plt.imshow(cm, interpolation="nearest")
    plt.title("ANE V2 Confusion Matrix")
    plt.colorbar()

    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Normal", "Attack"])
    plt.yticks(tick_marks, ["Normal", "Attack"])

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(
                j,
                i,
                format(cm[i, j], "d"),
                ha="center",
                va="center",
                color="white" if cm[i, j] > thresh else "black",
            )

    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "confusion_matrix_ane_v2.png", dpi=200)
    plt.close()


def main():
    np.random.seed(42)
    torch.manual_seed(42)

    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print("Device:", device)

    X_train_full, y_train_full, X_test, y_test = load_data()

    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=0.20,
        random_state=42,
        stratify=y_train_full,
    )

    print("Train shape:", X_train.shape)
    print("Val shape:", X_val.shape)
    print("Test shape:", X_test.shape)

    train_loader, val_loader, test_loader = build_dataloaders(
        X_train, y_train, X_val, y_val, X_test, y_test, batch_size=256
    )

    input_dim = X_train.shape[1]
    model = MLPANEFriendlyV2(input_dim=input_dim).to(device)

    class_weights = get_class_weights(y_train).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    optimizer = torch.optim.AdamW(model.parameters(), lr=7e-4, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode="max",
        factor=0.5,
        patience=4,
    )

    max_epochs = 60
    early_stop_patience = 10
    best_val_f1 = -1.0
    best_epoch = 0
    best_state = None
    wait = 0

    history = {
        "train_loss": [],
        "val_loss": [],
        "val_acc": [],
        "val_f1": [],
    }

    for epoch in range(1, max_epochs + 1):
        model.train()
        running_loss = 0.0
        total_samples = 0

        for X_batch, y_batch in train_loader:
            X_batch = X_batch.to(device)
            y_batch = y_batch.to(device)

            optimizer.zero_grad()
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()

            running_loss += loss.item() * X_batch.size(0)
            total_samples += X_batch.size(0)

        train_loss = running_loss / total_samples

        val_metrics = evaluate_model(model, val_loader, device, criterion=criterion)
        val_loss = val_metrics["loss"]
        val_acc = val_metrics["accuracy"]
        val_f1 = val_metrics["f1"]

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        history["val_f1"].append(val_f1)

        scheduler.step(val_f1)

        current_lr = optimizer.param_groups[0]["lr"]
        print(
            f"Epoch {epoch:03d}/{max_epochs} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f} | "
            f"Val Acc: {val_acc:.4f} | "
            f"Val F1: {val_f1:.4f} | "
            f"LR: {current_lr:.6f}"
        )

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            wait = 0
        else:
            wait += 1

        if wait >= early_stop_patience:
            print(f"Early stopping triggered at epoch {epoch}.")
            break

    model.load_state_dict(best_state)
    torch.save(model.state_dict(), MODELS_DIR / "best_mlp_ane_v2.pt")

    with open(REPORTS_DIR / "training_history_ane_v2.json", "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

    plot_training_curves(history)

    print(f"Best epoch: {best_epoch}")
    print(f"Best validation F1: {best_val_f1:.4f}")
    print(f"Best ANE V2 model saved to: {MODELS_DIR / 'best_mlp_ane_v2.pt'}")

    test_metrics = evaluate_model(model, test_loader, device, criterion=criterion)

    print("\nFinal Test Metrics")
    print(f"Test Loss: {test_metrics['loss']:.4f}")
    print(f"Test Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"Test F1: {test_metrics['f1']:.4f}")
    print(f"Test Precision: {test_metrics['precision']:.4f}")
    print(f"Test Recall: {test_metrics['recall']:.4f}")

    cm = confusion_matrix(test_metrics["labels"], test_metrics["preds"])
    plot_confusion_matrix(cm)

    report_text = classification_report(
        test_metrics["labels"],
        test_metrics["preds"],
        target_names=["Normal", "Attack"],
        digits=4,
        zero_division=0,
    )

    with open(REPORTS_DIR / "classification_report_ane_v2.txt", "w", encoding="utf-8") as f:
        f.write(report_text)

    test_summary = {
        "best_epoch": best_epoch,
        "best_val_f1": float(best_val_f1),
        "test_loss": float(test_metrics["loss"]),
        "test_accuracy": float(test_metrics["accuracy"]),
        "test_f1": float(test_metrics["f1"]),
        "test_precision": float(test_metrics["precision"]),
        "test_recall": float(test_metrics["recall"]),
    }

    with open(REPORTS_DIR / "test_metrics_ane_v2.json", "w", encoding="utf-8") as f:
        json.dump(test_summary, f, ensure_ascii=False, indent=2)

    print(f"Training curves saved to: {REPORTS_DIR / 'training_curves_ane_v2.png'}")
    print(f"Confusion matrix saved to: {REPORTS_DIR / 'confusion_matrix_ane_v2.png'}")
    print(f"Classification report saved to: {REPORTS_DIR / 'classification_report_ane_v2.txt'}")


if __name__ == "__main__":
    main()