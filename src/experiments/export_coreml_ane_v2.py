# export_coreml_ane_v2.py
# Export the residual ANE-friendly MLP variant to Core ML.

from pathlib import Path

import numpy as np
import torch
import coremltools as ct

from experiments.train_mlp_ane_v2 import MLPANEFriendlyV2


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


def main():
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    input_dim = X_train.shape[1]

    model = MLPANEFriendlyV2(input_dim=input_dim)
    model.load_state_dict(
        torch.load(MODELS_DIR / "best_mlp_ane_v2.pt", map_location="cpu")
    )
    model.eval()

    example_input = torch.rand(1, input_dim, dtype=torch.float32)
    traced_model = torch.jit.trace(model, example_input)

    mlmodel = ct.convert(
        traced_model,
        convert_to="mlprogram",
        inputs=[
            ct.TensorType(
                shape=example_input.shape,
                name="flow_features",
            )
        ],
    )

    output_path = MODELS_DIR / "IDSClassifier_ANE_v2.mlpackage"
    mlmodel.save(str(output_path))

    print("Core ML ANE V2 model saved to:")
    print(output_path)


if __name__ == "__main__":
    main()