# benchmark_pytorch.py
# Measure local PyTorch inference latency.

from pathlib import Path
import time

import numpy as np
import torch

from experiments.train_mlp import MLP


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def sync_device(device):
    # Synchronize device for accurate timing.
    if device.type == "mps":
        torch.mps.synchronize()
    elif device.type == "cuda":
        torch.cuda.synchronize()


def main():
    # Select device.
    if torch.backends.mps.is_available():
        device = torch.device("mps")
    else:
        device = torch.device("cpu")

    # Load one sample shape from processed data.
    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    input_dim = X_test.shape[1]

    # Rebuild model and load trained weights.
    model = MLP(input_dim=input_dim).to(device)
    model.load_state_dict(
        torch.load(MODELS_DIR / "best_mlp_ids.pt", map_location=device)
    )
    model.eval()

    # Use one sample for single-inference latency.
    sample = torch.tensor(X_test[:1], dtype=torch.float32).to(device)

    # Warm-up runs.
    with torch.no_grad():
        for _ in range(50):
            _ = model(sample)
    sync_device(device)

    # Timed runs.
    runs = 500
    start = time.perf_counter()
    with torch.no_grad():
        for _ in range(runs):
            _ = model(sample)
    sync_device(device)
    end = time.perf_counter()

    avg_ms = (end - start) * 1000 / runs

    print("Device:", device)
    print(f"Average latency per sample: {avg_ms:.4f} ms")

    output_path = REPORTS_DIR / "pytorch_latency.txt"
    output_path.write_text(
        f"Device: {device}\nAverage latency per sample: {avg_ms:.4f} ms\n",
        encoding="utf-8",
    )

    print("Latency report saved to:")
    print(output_path)


if __name__ == "__main__":
    main()