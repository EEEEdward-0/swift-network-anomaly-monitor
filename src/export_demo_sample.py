# export_demo_sample.py
# Export one processed sample to JSON for the macOS demo app.

from pathlib import Path
import json
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
APP_DIR = PROJECT_ROOT / "app"

APP_DIR.mkdir(parents=True, exist_ok=True)


def main():
    X_test = np.load(PROCESSED_DIR / "X_test.npy")

    # Use the first test sample for the demo.
    sample = X_test[0].tolist()

    output_path = APP_DIR / "demo_sample.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sample, f, ensure_ascii=False, indent=2)

    print("Demo sample saved to:")
    print(output_path)
    print("Feature length:", len(sample))


if __name__ == "__main__":
    main()