import numpy as np
from typing import List

from .anomaly_detector import AnomalyDetector


def generate_synthetic_data(n_normal: int = 1000, n_anomalous: int = 50) -> tuple:
    """
    Generate synthetic behavioral data for model training.

    Returns:
        (normal_data, anomalous_data) — both as lists of 6-feature vectors.
    """
    np.random.seed(42)

    # ── Normal patterns ──
    normal = np.column_stack([
        np.random.poisson(lam=10, size=n_normal),          # network_calls (moderate)
        np.random.poisson(lam=5, size=n_normal),           # file_access (low)
        np.random.beta(a=5, b=2, size=n_normal),           # timing_entropy (high = human-like)
        np.random.uniform(0, 1, size=n_normal),            # api_hash (random)
        np.random.exponential(scale=0.05, size=n_normal),  # memory (near zero)
        np.random.poisson(lam=1, size=n_normal),           # cpu_spikes (rare)
    ])

    # ── Anomalous patterns ──
    # Frida injection signature
    frida = np.column_stack([
        np.random.poisson(lam=80, size=n_anomalous // 5),
        np.random.poisson(lam=10, size=n_anomalous // 5),
        np.random.beta(a=2, b=5, size=n_anomalous // 5),
        np.random.uniform(0, 1, size=n_anomalous // 5),
        np.random.uniform(0.8, 1.0, size=n_anomalous // 5),
        np.random.poisson(lam=5, size=n_anomalous // 5),
    ])

    # APK repackage signature
    repack = np.column_stack([
        np.random.poisson(lam=15, size=n_anomalous // 5),
        np.random.poisson(lam=3, size=n_anomalous // 5),
        np.random.uniform(0, 0.1, size=n_anomalous // 5),  # Very low entropy
        np.random.uniform(0, 0.3, size=n_anomalous // 5),
        np.random.uniform(0.1, 0.3, size=n_anomalous // 5),
        np.random.poisson(lam=2, size=n_anomalous // 5),
    ])

    # MITM attempt signature
    mitm = np.column_stack([
        np.random.poisson(lam=150, size=n_anomalous // 5),  # Very high network
        np.random.poisson(lam=5, size=n_anomalous // 5),
        np.random.beta(a=3, b=3, size=n_anomalous // 5),
        np.random.uniform(0, 1, size=n_anomalous // 5),
        np.random.uniform(0.3, 0.6, size=n_anomalous // 5),
        np.random.poisson(lam=15, size=n_anomalous // 5),   # High CPU
    ])

    # Root exploit signature
    root = np.column_stack([
        np.random.poisson(lam=20, size=n_anomalous // 5),
        np.random.poisson(lam=40, size=n_anomalous // 5),   # Very high file access
        np.random.beta(a=3, b=3, size=n_anomalous // 5),
        np.random.uniform(0, 1, size=n_anomalous // 5),
        np.random.uniform(0.6, 0.9, size=n_anomalous // 5), # High memory
        np.random.poisson(lam=3, size=n_anomalous // 5),
    ])

    # Generic anomaly
    generic = np.column_stack([
        np.random.poisson(lam=60, size=n_anomalous // 5),
        np.random.poisson(lam=20, size=n_anomalous // 5),
        np.random.uniform(0, 0.3, size=n_anomalous // 5),
        np.random.uniform(0, 1, size=n_anomalous // 5),
        np.random.uniform(0.5, 0.8, size=n_anomalous // 5),
        np.random.poisson(lam=8, size=n_anomalous // 5),
    ])

    anomalous = np.vstack([frida, repack, mitm, root, generic])

    return normal.tolist(), anomalous.tolist()


def generate_and_train():
    """Generate synthetic data and train a new Isolation Forest model."""
    print("[Trainer] Generating synthetic behavioral data...")
    normal_data, anomalous_data = generate_synthetic_data()

    print(f"[Trainer] Normal samples: {len(normal_data)}")
    print(f"[Trainer] Anomalous samples: {len(anomalous_data)}")

    detector = AnomalyDetector()
    detector.retrain(normal_data)

    # Validate on anomalous data
    print("\n[Trainer] Validation on anomalous samples:")
    correct = 0
    for features in anomalous_data:
        score, attack_type = detector.predict(features)
        if score > 0.3:
            correct += 1

    accuracy = correct / len(anomalous_data) * 100
    print(f"[Trainer] Detection rate: {correct}/{len(anomalous_data)} ({accuracy:.1f}%)")

    # Validate on normal data (should have low scores)
    print("\n[Trainer] Validation on normal samples:")
    false_positives = 0
    for features in normal_data[:100]:
        score, _ = detector.predict(features)
        if score > 0.5:
            false_positives += 1

    fp_rate = false_positives / 100 * 100
    print(f"[Trainer] False positive rate: {false_positives}/100 ({fp_rate:.1f}%)")

    print("\n[Trainer] Training complete!")
    return detector


if __name__ == "__main__":
    generate_and_train()
