# export_demo_cases.py
# Export multiple demo samples for the macOS app.

from pathlib import Path
import json

import numpy as np
import torch

from experiments.train_mlp import MLP


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
APP_DIR = PROJECT_ROOT / "app"

APP_DIR.mkdir(parents=True, exist_ok=True)


def softmax(logits):
    exp_values = np.exp(logits - np.max(logits))
    return exp_values / np.sum(exp_values)


def main():
    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy")

    input_dim = X_test.shape[1]

    model = MLP(input_dim=input_dim)
    model.load_state_dict(torch.load(MODELS_DIR / "best_mlp_ids.pt", map_location="cpu"))
    model.eval()

    with torch.no_grad():
        logits = model(torch.tensor(X_test, dtype=torch.float32)).numpy()

    probs = np.apply_along_axis(softmax, 1, logits)
    attack_probs = probs[:, 1]

    # 1. High-confidence normal sample
    normal_mask = y_test == 0
    normal_indices = np.where(normal_mask)[0]
    best_normal_idx = normal_indices[np.argmin(attack_probs[normal_mask])]

    # 2. Borderline sample near 0.50
    borderline_idx = int(np.argmin(np.abs(attack_probs - 0.50)))

    # 3. High-confidence attack sample
    attack_mask = y_test == 1
    attack_indices = np.where(attack_mask)[0]
    best_attack_idx = attack_indices[np.argmax(attack_probs[attack_mask])]

    demo_cases = [
        {
            "name": "normal_case",
            "index": int(best_normal_idx),
            "true_label": int(y_test[best_normal_idx]),
            "attack_probability": float(attack_probs[best_normal_idx]),
            "features": X_test[best_normal_idx].tolist(),
        },
        {
            "name": "borderline_case",
            "index": int(borderline_idx),
            "true_label": int(y_test[borderline_idx]),
            "attack_probability": float(attack_probs[borderline_idx]),
            "features": X_test[borderline_idx].tolist(),
        },
        {
            "name": "attack_case",
            "index": int(best_attack_idx),
            "true_label": int(y_test[best_attack_idx]),
            "attack_probability": float(attack_probs[best_attack_idx]),
            "features": X_test[best_attack_idx].tolist(),
        },
    ]

    output_path = APP_DIR / "demo_cases.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(demo_cases, f, ensure_ascii=False, indent=2)

    print("Demo cases saved to:")
    print(output_path)
    print()

    for case in demo_cases:
        print(case["name"])
        print(" index:", case["index"])
        print(" true_label:", case["true_label"])
        print(" attack_probability:", f"{case['attack_probability']:.4f}")
        print()


if __name__ == "__main__":
    main()