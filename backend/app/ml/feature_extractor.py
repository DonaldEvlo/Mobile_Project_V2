import math
import hashlib
from typing import List, Dict, Any


class FeatureExtractor:
    """
    Extracts 6-dimension behavioral features from raw event data.

    Used for preprocessing mobile event streams before ML inference.
    """

    @staticmethod
    def extract_from_events(events: List[Dict[str, Any]]) -> List[float]:
        """
        Extract feature vector from a list of raw events.

        Args:
            events: List of event dicts with 'type', 'timestamp', 'metadata'.

        Returns:
            6-element feature vector.
        """
        if not events:
            return [0.0, 0.0, 0.5, 0.0, 0.0, 0.0]

        network_count = sum(1 for e in events if e.get("type") == "networkCall")

        file_count = sum(1 for e in events if e.get("type") == "fileAccess")

        timing_entropy = FeatureExtractor._compute_timing_entropy(events)

        api_hash = FeatureExtractor._compute_api_sequence_hash(events)

        memory_score = FeatureExtractor._compute_memory_score(events)

        cpu_spikes = sum(1 for e in events if e.get("type") == "cpuSpike")

        return [
            float(network_count),
            float(file_count),
            timing_entropy,
            api_hash,
            memory_score,
            float(cpu_spikes),
        ]

    @staticmethod
    def _compute_timing_entropy(events: List[Dict]) -> float:
        """Shannon entropy of inter-event timing intervals."""
        if len(events) < 3:
            return 0.5

        timestamps = []
        for e in events:
            ts = e.get("epoch_ms") or e.get("timestamp", 0)
            if isinstance(ts, str):
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts)
                    ts = int(dt.timestamp() * 1000)
                except (ValueError, TypeError):
                    continue
            timestamps.append(int(ts))

        if len(timestamps) < 3:
            return 0.5

        timestamps.sort()
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        max_interval = max(intervals) if intervals else 1
        if max_interval == 0:
            return 0.0  # All simultaneous — suspicious

        # Bucket intervals into 10 bins
        buckets = [0] * 10
        for interval in intervals:
            bucket = min(9, int((interval / max_interval) * 9))
            buckets[bucket] += 1

        total = len(intervals)
        entropy = 0.0
        for count in buckets:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return min(1.0, entropy / 3.32)  # Normalize by log2(10)

    @staticmethod
    def _compute_api_sequence_hash(events: List[Dict]) -> float:
        """Normalized hash of API call sequence."""
        api_calls = [
            e.get("metadata", {}).get("endpoint", "unknown")
            for e in events
            if e.get("type") == "apiCall"
        ]

        if not api_calls:
            return 0.0

        sequence = "|".join(api_calls)
        hash_val = int(hashlib.md5(sequence.encode()).hexdigest(), 16)
        return (hash_val % 10000) / 10000.0

    @staticmethod
    def _compute_memory_score(events: List[Dict]) -> float:
        """Average memory anomaly score from memory events."""
        memory_events = [
            e for e in events if e.get("type") == "memoryAnomaly"
        ]

        if not memory_events:
            return 0.0

        scores = [
            float(e.get("metadata", {}).get("score", 0))
            for e in memory_events
        ]

        return min(1.0, sum(scores) / len(scores))
