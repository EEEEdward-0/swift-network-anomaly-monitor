# preprocess.py
# Preprocess UNSW-NB15 with numeric and categorical features.

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def load_csv(file_path: Path) -> pd.DataFrame:
    # Load CSV and replace invalid values.
    df = pd.read_csv(file_path)
    df = df.replace([np.inf, -np.inf], np.nan)
    return df


def build_features(train_df: pd.DataFrame, test_df: pd.DataFrame):
    # Define columns.
    label_col = "label"
    drop_cols = ["id", "attack_cat", label_col]
    cat_cols = ["proto", "service", "state"]

    # Keep labels.
    y_train = train_df[label_col].astype(int).to_numpy()
    y_test = test_df[label_col].astype(int).to_numpy()

    # Drop non-feature columns.
    train_x = train_df.drop(columns=drop_cols, errors="ignore").copy()
    test_x = test_df.drop(columns=drop_cols, errors="ignore").copy()

    # Split numeric and categorical parts.
    train_cat = train_x[cat_cols].copy()
    test_cat = test_x[cat_cols].copy()

    train_num = train_x.drop(columns=cat_cols, errors="ignore").copy()
    test_num = test_x.drop(columns=cat_cols, errors="ignore").copy()

    # Force numeric conversion.
    train_num = train_num.apply(pd.to_numeric, errors="coerce")
    test_num = test_num.apply(pd.to_numeric, errors="coerce")

    # Fill missing values with training medians.
    medians = train_num.median()
    train_num = train_num.fillna(medians)
    test_num = test_num.fillna(medians)

    # One-hot encode categorical features using combined columns.
    all_cat = pd.concat([train_cat, test_cat], axis=0)
    all_cat = pd.get_dummies(all_cat, columns=cat_cols, dummy_na=False)

    train_cat_encoded = all_cat.iloc[: len(train_df)].reset_index(drop=True)
    test_cat_encoded = all_cat.iloc[len(train_df):].reset_index(drop=True)

    # Scale numeric features only.
    scaler = StandardScaler()
    train_num_scaled = pd.DataFrame(
        scaler.fit_transform(train_num),
        columns=train_num.columns,
        index=train_num.index,
    )
    test_num_scaled = pd.DataFrame(
        scaler.transform(test_num),
        columns=test_num.columns,
        index=test_num.index,
    )

    # Merge numeric and categorical features.
    X_train_df = pd.concat(
        [train_num_scaled.reset_index(drop=True), train_cat_encoded.reset_index(drop=True)],
        axis=1,
    )
    X_test_df = pd.concat(
        [test_num_scaled.reset_index(drop=True), test_cat_encoded.reset_index(drop=True)],
        axis=1,
    )

    feature_names = list(X_train_df.columns)

    X_train = X_train_df.to_numpy(dtype=np.float32)
    X_test = X_test_df.to_numpy(dtype=np.float32)

    return X_train, y_train, X_test, y_test, scaler, feature_names


def main():
    train_file = RAW_DIR / "UNSW_NB15_training-set.csv"
    test_file = RAW_DIR / "UNSW_NB15_testing-set.csv"

    if not train_file.exists() or not test_file.exists():
        raise FileNotFoundError(f"Missing CSV files in: {RAW_DIR}")

    train_df = load_csv(train_file)
    test_df = load_csv(test_file)

    X_train, y_train, X_test, y_test, scaler, feature_names = build_features(train_df, test_df)

    np.save(PROCESSED_DIR / "X_train.npy", X_train)
    np.save(PROCESSED_DIR / "y_train.npy", y_train)
    np.save(PROCESSED_DIR / "X_test.npy", X_test)
    np.save(PROCESSED_DIR / "y_test.npy", y_test)

    joblib.dump(scaler, PROCESSED_DIR / "scaler.pkl")

    with open(PROCESSED_DIR / "feature_names.json", "w", encoding="utf-8") as f:
        json.dump(feature_names, f, ensure_ascii=False, indent=2)

    print("Preprocessing finished.")
    print("X_train:", X_train.shape)
    print("X_test:", X_test.shape)
    print("Feature count:", len(feature_names))


if __name__ == "__main__":
    main()