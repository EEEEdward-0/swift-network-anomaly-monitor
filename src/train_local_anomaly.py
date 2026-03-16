# train_local_anomaly.py
# Train a local anomaly detection model using extracted flow features.

from pathlib import Path
import json
import joblib

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOCAL_ANALYSIS_DIR = REPORTS_DIR / "local_analysis"
MODELS_DIR = PROJECT_ROOT / "models"

INPUT_CSV = LOCAL_ANALYSIS_DIR / "local_flows.csv"
MODEL_PATH = MODELS_DIR / "local_anomaly_iforest.pkl"
SUMMARY_PATH = LOCAL_ANALYSIS_DIR / "local_anomaly_training_summary.json"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Missing input CSV: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV)
    if df.empty:
        raise ValueError("local_flows.csv is empty.")
    return df


def build_feature_sets(df: pd.DataFrame):
    # Select features that can be stably extracted from local traffic.
    categorical_features = [
        "proto",
        "service",
        "ip_version",
    ]

    numeric_features = [
        "duration",
        "total_packets",
        "total_bytes",
        "a_to_b_packets",
        "b_to_a_packets",
        "a_to_b_bytes",
        "b_to_a_bytes",
        "a_to_b_packet_ratio",
        "b_to_a_packet_ratio",
        "packets_per_second",
        "bytes_per_second",
        "min_pkt_size",
        "max_pkt_size",
        "mean_pkt_size",
        "std_pkt_size",
        "tcp_syn_count",
        "tcp_ack_count",
        "tcp_fin_count",
        "tcp_rst_count",
        "tcp_psh_count",
        "src_is_private",
        "dst_is_private",
        "both_private",
        "src_port",
        "dst_port",
    ]

    missing_cols = [c for c in categorical_features + numeric_features if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")

    X = df[categorical_features + numeric_features].copy()
    return X, categorical_features, numeric_features


def build_pipeline(categorical_features, numeric_features):
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features,
            ),
            (
                "num",
                StandardScaler(),
                numeric_features,
            ),
        ]
    )

    model = IsolationForest(
        n_estimators=300,
        contamination=0.08,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )
    return pipeline


def main():
    df = load_data()
    X, categorical_features, numeric_features = build_feature_sets(df)
    pipeline = build_pipeline(categorical_features, numeric_features)

    pipeline.fit(X)

    # IsolationForest:
    # decision_function: higher = more normal
    # score_samples: higher = more normal
    # We invert it so higher means more anomalous.
    normality_scores = pipeline.decision_function(X)
    anomaly_scores = -normality_scores

    df_result = df.copy()
    df_result["anomaly_score"] = anomaly_scores

    # Rank anomalies for quick inspection.
    df_sorted = df_result.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
    output_csv = LOCAL_ANALYSIS_DIR / "local_flows_with_anomaly_score.csv"
    df_sorted.to_csv(output_csv, index=False)

    joblib.dump(pipeline, MODEL_PATH)

    summary = {
        "input_csv": str(INPUT_CSV),
        "model_path": str(MODEL_PATH),
        "output_csv": str(output_csv),
        "num_flows": int(len(df)),
        "categorical_features": categorical_features,
        "numeric_features": numeric_features,
        "anomaly_score_mean": float(df_result["anomaly_score"].mean()),
        "anomaly_score_std": float(df_result["anomaly_score"].std()),
        "top_10_anomaly_scores": [float(x) for x in df_sorted["anomaly_score"].head(10).tolist()],
    }

    with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Local anomaly model training finished.")
    print("Input:", INPUT_CSV)
    print("Model saved to:", MODEL_PATH)
    print("Scored flows saved to:", output_csv)
    print("Summary saved to:", SUMMARY_PATH)
    print()
    print("Top 10 suspicious flows:")
    print(
        df_sorted[
            [
                "src_ip",
                "dst_ip",
                "dst_port",
                "proto",
                "service",
                "duration",
                "total_packets",
                "total_bytes",
                "anomaly_score",
            ]
        ].head(10)
    )


if __name__ == "__main__":
    main()