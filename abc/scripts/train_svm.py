"""
Train a real SVM model for hybrid DDoS detection.

This script trains an SVM classifier on the same dataset and feature set used
by the Random Forest model, then saves it to models/svm_model.pkl.

After running this script, set HYBRID_MODE=true to enable hybrid detection.

Usage:
    python scripts/train_svm.py --data ddos_balanced/final_dataset.csv
    python scripts/train_svm.py --data ddos_balanced/final_dataset.csv --sample 50000

Note: SVM training is slow. Use --sample to limit rows (default: 50000).
      For best accuracy use 100000+ rows, but expect 20-60 minutes.
"""
import pandas as pd
import numpy as np
import joblib
import logging
import argparse
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def train_svm(csv_path: str, sample_size: int = 50000):
    """
    Train an SVM model using the same scaler and feature set as the RF model.

    Args:
        csv_path: Path to the CICFlowMeter CSV dataset
        sample_size: Number of rows to sample (SVM is slow on large datasets)
    """
    models_dir = Path("models")
    scaler_path = models_dir / "random_forest_min-max_scaling_scaler.pkl"

    if not scaler_path.exists():
        logger.error(f"Scaler not found at {scaler_path}. Train the RF model first.")
        return

    logger.info(f"Loading scaler from {scaler_path}...")
    scaler = joblib.load(scaler_path)

    # Fix #39: feature_names_in_ was added in scikit-learn 1.0.
    # Fall back to n_features_in_ on older versions to avoid AttributeError.
    if hasattr(scaler, 'feature_names_in_'):
        feature_names = list(scaler.feature_names_in_)
    else:
        n = getattr(scaler, 'n_features_in_', 77)
        logger.warning(
            f"Scaler has no feature_names_in_ (scikit-learn < 1.0). "
            f"Using positional features ({n} features)."
        )
        feature_names = [str(i) for i in range(n)]
    logger.info(f"Scaler expects {len(feature_names)} features")

    logger.info(f"Loading dataset from {csv_path} (sample={sample_size})...")
    try:
        df = pd.read_csv(csv_path, nrows=sample_size)
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        return

    logger.info(f"Loaded {len(df)} rows. Preprocessing...")

    # Clean column names
    df.columns = df.columns.str.strip()

    # Ensure all required features exist
    for f in feature_names:
        if f not in df.columns:
            df[f] = 0.0

    # Binary labels: 0=BENIGN, 1=ATTACK
    if 'Label' not in df.columns:
        logger.error("CSV must contain a 'Label' column")
        return

    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)

    # Handle inf/NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    X = df[feature_names]
    y = df['Label']

    logger.info(f"Class distribution: {dict(y.value_counts())}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale using the SAME scaler as the RF model so both models see identical input
    logger.info("Scaling features using the RF scaler...")
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train SVM
    # - kernel='rbf': good for non-linear boundaries
    # - probability=True: required for predict_proba (used by hybrid ensemble)
    # - C=10: higher regularization for better attack detection
    # - class_weight='balanced': handles class imbalance automatically
    logger.info("Training SVM classifier (this may take several minutes)...")
    logger.info("Tip: Reduce --sample if this is too slow.")
    svm = SVC(
        kernel='rbf',
        C=10.0,
        gamma='scale',
        probability=True,
        class_weight='balanced',
        random_state=42,
    )
    svm.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = svm.predict(X_test_scaled)
    logger.info("Training complete! Evaluation:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    logger.info(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")

    # Save
    svm_path = models_dir / "svm_model.pkl"
    logger.info(f"Saving SVM model to {svm_path}...")
    joblib.dump(svm, svm_path)

    logger.info("✅ Done! To enable hybrid detection:")
    logger.info("   Set environment variable: HYBRID_MODE=true")
    logger.info("   Or update config/settings.py: HYBRID_MODE default to 'True'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SVM model for hybrid DDoS detection")
    parser.add_argument(
        "--data",
        type=str,
        default="ddos_balanced/final_dataset.csv",
        help="Path to CICFlowMeter CSV dataset"
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=50000,
        help="Number of rows to sample (default: 50000, increase for better accuracy)"
    )
    args = parser.parse_args()
    train_svm(args.data, args.sample)
