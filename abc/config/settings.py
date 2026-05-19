"""
Project configuration for DDoS detection.
"""
import os
import platform
from pathlib import Path
from typing import Union

# Project base directory
BASE_DIR = Path(__file__).parent.parent


class Config:
    """Centralized application configuration."""
    
    # General settings
    DEBUG: bool = os.getenv('DEBUG', 'False').lower() == 'true'
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # Model paths
    # Fix #34: if the env var is an absolute path, Path() / absolute_path
    # resolves correctly on POSIX but not on Windows (drive letter issue).
    # Use Path(env_val) directly when it looks absolute; otherwise join with MODELS_DIR.
    MODELS_DIR: Path = BASE_DIR / 'models'

    _model_env = os.getenv('MODEL_PATH', 'random_forest_min-max_scaling_model.pkl')
    MODEL_PATH: Path = (
        Path(_model_env) if Path(_model_env).is_absolute() else MODELS_DIR / _model_env
    )

    _scaler_env = os.getenv('SCALER_PATH', 'random_forest_min-max_scaling_scaler.pkl')
    SCALER_PATH: Path = (
        Path(_scaler_env) if Path(_scaler_env).is_absolute() else MODELS_DIR / _scaler_env
    )
    
    # Hybrid ML Configuration (Module 4)
    # Default weights: RF=60%, SVM=40% (matches walkthrough documentation)
    # NOTE: HYBRID_MODE defaults to False because the bundled svm_model.pkl is a
    # placeholder trained on random data. Set HYBRID_MODE=true only after training
    # a real SVM model with scripts/train_svm.py.
    HYBRID_MODE: bool = os.getenv('HYBRID_MODE', 'False').lower() == 'true'
    SVM_MODEL_PATH: Path = MODELS_DIR / os.getenv('SVM_MODEL_PATH', 'svm_model.pkl')
    RF_WEIGHT: float = float(os.getenv('RF_WEIGHT', '0.6'))
    SVM_WEIGHT: float = float(os.getenv('SVM_WEIGHT', '0.4'))

    @classmethod
    def _validate_weights(cls) -> None:
        """Raise if both ML weights are zero (would cause ZeroDivisionError)."""
        if cls.RF_WEIGHT + cls.SVM_WEIGHT <= 0:
            raise ValueError(
                f"RF_WEIGHT ({cls.RF_WEIGHT}) + SVM_WEIGHT ({cls.SVM_WEIGHT}) must be > 0"
            )
    
    # Adaptive Detection Configuration (Module 5)
    ADAPTIVE_MODE: bool = os.getenv('ADAPTIVE_MODE', 'True').lower() == 'true'
    BASE_THRESHOLD: float = float(os.getenv('BASE_THRESHOLD', '0.65'))
    MAX_THRESHOLD: float = float(os.getenv('MAX_THRESHOLD', '0.85'))
    ADAPTIVE_WINDOW: int = int(os.getenv('ADAPTIVE_WINDOW', '10'))  # Window size in seconds
    SPIKE_MULTIPLIER: float = float(os.getenv('SPIKE_MULTIPLIER', '3.0'))
    EMA_ALPHA: float = float(os.getenv('EMA_ALPHA', '0.3'))  # EMA smoothing factor for baseline
    
    # Logging configuration
    LOGS_DIR: Path = BASE_DIR / 'logs'
    DETECTION_LOG: Path = LOGS_DIR / 'detection.log'
    SERVER_LOG: Path = LOGS_DIR / 'server.log'
    
    # Flask server configuration
    FLASK_HOST: str = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_PORT: int = int(os.getenv('FLASK_PORT', '5050'))
    
    # Dashboard configuration
    DASHBOARD_HOST: str = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    DASHBOARD_PORT: int = int(os.getenv('DASHBOARD_PORT', '8080'))
    
    # Traffic simulation configuration
    SYN_FLOOD_ENABLED: bool = os.getenv('SYN_FLOOD_ENABLED', 'True').lower() == 'true'
    
    # Report configuration
    REPORT_WINDOW_SECONDS: int = int(os.getenv('REPORT_WINDOW_SECONDS', '300'))  # 5 min default
    
    # Detection configuration — auto-detect default loopback interface per OS
    _DEFAULT_LOOPBACK = {
        'Windows': '\\Device\\NPF_Loopback',

        'Linux': 'lo',
        'Darwin': 'lo0',
    }.get(platform.system(), 'lo0')
    NETWORK_INTERFACE: str = os.getenv('NETWORK_INTERFACE', _DEFAULT_LOOPBACK)
    BPF_FILTER: str = os.getenv('BPF_FILTER', 'tcp port 5050')
    
    # Flow tracking configuration
    FLOW_TIMEOUT: float = float(os.getenv('FLOW_TIMEOUT', '300.0'))  # 5 minutes

    # Minimum packets per flow before a prediction is made.
    # Predicting on 1–2 packet flows produces unreliable scores because most
    # statistical features (IAT std, backward packet counts, etc.) are still zero.
    MIN_PACKETS_FOR_PREDICTION: int = int(os.getenv('MIN_PACKETS_FOR_PREDICTION', '5'))

    # Redis configuration (used for cross-process event sharing between
    # the detection engine and the dashboard).
    # When Redis is unavailable the system falls back to log-file parsing.
    REDIS_HOST: str = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT: int = int(os.getenv('REDIS_PORT', '6379'))
    REDIS_DB: int = int(os.getenv('REDIS_DB', '0'))
    REDIS_PASSWORD: str = os.getenv('REDIS_PASSWORD', '')
    # Maximum number of events kept in the Redis list
    REDIS_EVENT_LIST_MAX: int = int(os.getenv('REDIS_EVENT_LIST_MAX', '500'))
    
    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure necessary directories exist."""
        cls.LOGS_DIR.mkdir(exist_ok=True)
        cls.MODELS_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def validate_paths(cls) -> bool:
        """Validate if necessary files exist."""
        if not cls.MODEL_PATH.exists():
            raise FileNotFoundError(f"Model not found: {cls.MODEL_PATH}")
        if not cls.SCALER_PATH.exists():
            raise FileNotFoundError(f"Scaler not found: {cls.SCALER_PATH}")
        return True
