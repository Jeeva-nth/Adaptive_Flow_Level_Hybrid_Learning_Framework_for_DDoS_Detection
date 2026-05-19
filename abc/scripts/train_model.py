import pandas as pd
import numpy as np
import joblib
import logging
import argparse
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, accuracy_score

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Feature column names (Standard CICFlowMeter names matching feature_extraction.py)
FEATURE_COLUMNS = [
    ' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max',
    ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    ' Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
    ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean',
    ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean',
    ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
    ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
    'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count',
    ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count',
    ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size', ' Fwd Avg Bytes/Bulk',
    ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
    ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
    'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd',
    ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max',
    ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
]

def train_model(csv_path: str, sample_size: int = 500000):
    """
    Train a Random Forest model using the provided CSV dataset.
    """
    logger.info(f"Loading dataset from {csv_path}...")
    
    # Since the file is huge (6.7GB), we read it in chunks or take a large sample
    # Here we read a sample to save memory and time while still being accurate
    try:
        # Get total row count first (optional, but good for progress)
        df_chunk = pd.read_csv(csv_path, nrows=sample_size)
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        return

    logger.info(f"Preprocessing {len(df_chunk)} rows...")
    
    # 1. Clean Feature Names (strip whitespace)
    df_chunk.columns = df_chunk.columns.str.strip()
    
    # 2. Select Features
    # We need to map our FEATURE_COLUMNS (stripped) to what's in the CSV
    clean_features = [f.strip() for f in FEATURE_COLUMNS]
    
    # Check which features exist in the CSV
    available_features = [f for f in clean_features if f in df_chunk.columns]
    missing_features = [f for f in clean_features if f not in df_chunk.columns]
    
    if missing_features:
        logger.warning(f"Missing {len(missing_features)} features in CSV: {missing_features[:5]}...")
        # Fill missing features with 0 to maintain the 77-feature input shape
        for f in missing_features:
            df_chunk[f] = 0.0
            
    # 3. Handle 'Label' column
    if 'Label' not in df_chunk.columns:
        logger.error("CSV must contain a 'Label' column!")
        return
        
    # Preserve multi-class labels (BENIGN, DoS Hulk, DoS slowloris, etc.)
    # The model_prediction.py code expects multi-class output and uses 1-P(BENIGN)
    # to compute attack probability, so we keep the original label strings.
    logger.info(f"Label distribution: {df_chunk['Label'].value_counts().to_dict()}")
    
    # 4. Handle Infinity and NaNs
    df_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_chunk.fillna(0, inplace=True)
    
    X = df_chunk[clean_features]
    y = df_chunk['Label']
    
    # 5. Split and Scale
    logger.info("Splitting data and scaling...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 6. Train Random Forest
    logger.info("Training Random Forest Classifier (this may take a few minutes)...")
    model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # 7. Evaluate
    y_pred = model.predict(X_test_scaled)
    logger.info("Training Complete! Evaluation Report:")
    print(classification_report(y_test, y_pred))
    logger.info(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    # Fix #40: use project-root-relative path so the model is always saved to
    # the correct location regardless of which directory the script is run from.
    models_dir = Path(__file__).parent.parent / "models"
    models_dir.mkdir(exist_ok=True)
    
    model_path = models_dir / "random_forest_min-max_scaling_model.pkl"
    scaler_path = models_dir / "random_forest_min-max_scaling_scaler.pkl"
    
    logger.info(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    logger.info(f"Saving scaler to {scaler_path}...")
    joblib.dump(scaler, scaler_path)
    
    logger.info("✅ SUCCESS! Your models/ folder has been updated with real intelligence.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DDoS detection model from CSV")
    parser.add_argument("--data", type=str, default="ddos_balanced/final_dataset.csv", help="Path to CSV dataset")
    parser.add_argument("--sample", type=int, default=500000, help="Number of rows to sample for training")
    
    args = parser.parse_args()
    train_model(args.data, args.sample)
