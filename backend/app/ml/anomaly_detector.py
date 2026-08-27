import os
import numpy as np
import joblib
from typing import Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.core.config import get_settings

settings = get_settings()


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for behavioral analysis.

    Features (6 dimensions):
    0. network_calls_count
    1. file_access_count
    2. timing_entropy
    3. api_call_sequence_hash
    4. memory_anomaly_score
    5. cpu_spike_count
    """

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._load_model()

    def _load_model(self):
        """Load pre-trained model and scaler from disk."""
        try:
            if os.path.exists(settings.ML_MODEL_PATH) and os.path.exists(settings.ML_SCALER_PATH):
                self.model = joblib.load(settings.ML_MODEL_PATH)
                self.scaler = joblib.load(settings.ML_SCALER_PATH)
                print(f"[ML] Loaded model from {settings.ML_MODEL_PATH}")
            else:
                print("[ML] No pre-trained model found — using heuristic fallback")
                self._train_initial_model()
        except Exception as e:
            print(f"[ML] Error loading model: {e} — using heuristic fallback")
            self._train_initial_model()

    def _train_initial_model(self):
        """Train an initial model with synthetic normal data."""
        print("[ML] Training initial model with synthetic data...")
        np.random.seed(42)

        # Generate synthetic "normal" behavioral patterns
        n_samples = 1000
        normal_data = np.column_stack([
            np.random.poisson(lam=10, size=n_samples),         # network_calls
            np.random.poisson(lam=5, size=n_samples),          # file_access
            np.random.beta(a=5, b=2, size=n_samples),          # timing_entropy (skewed high = normal)
            np.random.uniform(0, 1, size=n_samples),           # api_call_hash
            np.random.exponential(scale=0.05, size=n_samples), # memory_anomaly (low = normal)
            np.random.poisson(lam=1, size=n_samples),          # cpu_spikes (low = normal)
        ])

        self.retrain(normal_data.tolist())

    def retrain(self, normal_data: list):
        """
        Retrain the model with new normal behavioral data.

        Args:
            normal_data: List of lists, each inner list is a 6-feature vector.
        """
        X = np.array(normal_data, dtype=np.float64)

        self.scaler = StandardScaler().fit(X)
        X_scaled = self.scaler.transform(X)

        self.model = IsolationForest(
            contamination=settings.ML_CONTAMINATION,  # 5% anomaly rate
            n_estimators=settings.ML_N_ESTIMATORS,      # 200 trees
            random_state=42,
            n_jobs=-1,
        ).fit(X_scaled)

        os.makedirs(os.path.dirname(settings.ML_MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, settings.ML_MODEL_PATH)
        joblib.dump(self.scaler, settings.ML_SCALER_PATH)
        print(f"[ML] Model trained and saved ({len(normal_data)} samples)")

    def predict(self, features: list) -> tuple[float, Optional[str]]:
        """
        Predict anomaly score for a feature vector.

        Args:
            features: List of 6 floats (the behavioral feature vector).

        Returns:
            (anomaly_score, attack_type) where:
            - anomaly_score: 0.0 (normal) to 1.0 (highly anomalous)
            - attack_type: Classified attack type or None
        """
        if self.model is None or self.scaler is None:
            return self._heuristic_predict(features)

        try:
            X = np.array([features], dtype=np.float64)
            X_scaled = self.scaler.transform(X)

            # decision_function: negative = anomaly, positive = normal
            raw_score = self.model.decision_function(X_scaled)[0]

            # Normalize to 0-1 (1 = very anomalous)
            anomaly_score = float(max(0.0, min(1.0, 0.5 - raw_score)))

            return anomaly_score, self._classify_attack(features, anomaly_score)

        except Exception as e:
            print(f"[ML] Prediction error: {e}")
            return self._heuristic_predict(features)

    def _classify_attack(self, features: list, anomaly_score: float) -> Optional[str]:
        """
        Classify the type of attack based on feature signatures.

        Known signatures from the spec:
        - frida_injection: memory > 0.8 AND network > 50
        - apk_repack: timing_entropy < 0.1
        - mitm_attempt: network > 100 AND cpu > 10
        - root_exploit: file_access > 30 AND memory > 0.6
        """
        if anomaly_score < 0.3:
            return None  # Not anomalous enough to classify

        network, files, entropy, api_hash, memory, cpu = features

        if memory > 0.8 and network > 50:
            return "frida_injection"

        if entropy < 0.1 and network > 5:
            return "apk_repack"

        if network > 100 and cpu > 10:
            return "mitm_attempt"

        if files > 30 and memory > 0.6:
            return "root_exploit"

        if anomaly_score > 0.6:
            return "unknown_anomaly"

        return None

    def _heuristic_predict(self, features: list) -> tuple[float, Optional[str]]:
        """Fallback prediction when the ML model is unavailable."""
        network, files, entropy, api_hash, memory, cpu = features
        score = 0.0

        if memory > 0.8 and network > 50:
            score = max(score, 0.92)
        if entropy < 0.1 and network > 5:
            score = max(score, 0.75)
        if network > 100 and cpu > 10:
            score = max(score, 0.80)
        if files > 30 and memory > 0.6:
            score = max(score, 0.70)
        if memory > 0.6:
            score = max(score, memory * 0.8)

        attack_type = self._classify_attack(features, score)
        return score, attack_type
