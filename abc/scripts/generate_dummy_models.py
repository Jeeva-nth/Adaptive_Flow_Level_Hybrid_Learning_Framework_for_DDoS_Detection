#!/usr/bin/env python3
"""
Generate a dummy SVM model for testing the Hybrid ML Module.
This allows the hybrid detection system to run out-of-the-box
before a real SVM model is trained.
"""
import joblib
import numpy as np
from pathlib import Path
from sklearn.svm import SVC
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent
MODELS_DIR = BASE_DIR / 'models'
SCALER_PATH = MODELS_DIR / 'random_forest_min-max_scaling_scaler.pkl'
SVM_MODEL_PATH = MODELS_DIR / 'svm_model.pkl'

def generate_dummy_svm():
    logger.info("Initializing dummy SVM model generation...")
    
    if not SCALER_PATH.exists():
        logger.error(f"Scaler not found at {SCALER_PATH}. Cannot determine feature shape.")
        return False
        
    try:
        # Load scaler to get feature shape
        scaler = joblib.load(SCALER_PATH)
        n_features = getattr(scaler, 'n_features_in_', 77)
        logger.info(f"Detected {n_features} features from scaler.")
        
        # Generate smart synthetic training data
        logger.info("Generating synthetic training data (Normal & Attack)...")
        
        # Normal traffic: Low feature values (e.g., 0 to 0.3)
        X_normal = np.random.rand(500, n_features) * 0.3
        y_normal = np.zeros(500, dtype=int)
        
        # Attack traffic: High feature values (e.g., 0.6 to 1.0)
        X_attack = np.random.rand(500, n_features) * 0.4 + 0.6
        y_attack = np.ones(500, dtype=int)
        
        # Combine the data
        X_smart = np.vstack((X_normal, X_attack))
        y_smart = np.concatenate((y_normal, y_attack))
        
        # Train a dummy SVM model with probability=True required for confidence scoring
        logger.info("Training smart dummy SVC...")
        svm_model = SVC(probability=True, kernel='linear', random_state=42)
        svm_model.fit(X_smart, y_smart)
        
        # Save model
        MODELS_DIR.mkdir(exist_ok=True)
        joblib.dump(svm_model, SVM_MODEL_PATH)
        logger.info(f"✅ Successfully saved dummy SVM model to {SVM_MODEL_PATH}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate SVM model: {e}")
        return False

if __name__ == '__main__':
    generate_dummy_svm()
