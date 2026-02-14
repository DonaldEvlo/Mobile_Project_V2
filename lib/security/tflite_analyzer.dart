import 'dart:math';

import 'package:logger/logger.dart';

import 'models/behavior_event.dart';
import 'models/security_report.dart';

/// On-device anomaly detector using TFLite.
///
/// Extracts 6-dimension behavioral features from the event buffer
/// and runs inference locally (offline-first design).
///
/// NOTE: In the initial version, TFLite model loading is stubbed.
/// The actual .tflite model will be generated from the backend
/// Isolation Forest after training on real behavioral data.
class TFLiteAnalyzer {
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));
  bool _isInitialized = false;

  // TFLite interpreter — uncomment when model is ready:
  // late Interpreter _interpreter;

  /// Initialize the TFLite model from assets.
  Future<void> initialize() async {
    try {
      // When the real model is ready, load it:
      // _interpreter = await Interpreter.fromAsset('models/anomaly_detector.tflite');
      _isInitialized = true;
      _log.i('TFLite analyzer initialized (using heuristic fallback)');
    } catch (e) {
      _log.e('Failed to initialize TFLite model: $e');
      _isInitialized = false;
    }
  }

  /// Analyze a buffer of behavioral events and return an anomaly score.
  ///
  /// Returns a score between 0.0 (normal) and 1.0 (highly anomalous).
  Future<double> analyzeBuffer(List<BehaviorEvent> events) async {
    if (events.isEmpty) return 0.0;

    final features = extractFeatures(events);

    if (_isInitialized) {
      return _runInference(features);
    } else {
      // Heuristic fallback when model isn't loaded
      return _heuristicScore(features);
    }
  }

  /// Extract 6-dimension feature vector from event buffer.
  BehaviorFeatures extractFeatures(List<BehaviorEvent> events) {
    // 1. Network calls count
    final networkCalls = events
        .where((e) => e.type == BehaviorEventType.networkCall)
        .length
        .toDouble();

    // 2. File access count
    final fileAccesses = events
        .where((e) => e.type == BehaviorEventType.fileAccess)
        .length
        .toDouble();

    // 3. Timing entropy — Shannon entropy of inter-event intervals
    final timingEntropy = _calculateTimingEntropy(events);

    // 4. API call sequence hash — normalized hash of API call order
    final apiSequenceHash = _calculateApiSequenceHash(events);

    // 5. Memory anomaly score — from native metadata if available
    final memoryScore = _extractMemoryAnomalyScore(events);

    // 6. CPU spike count
    final cpuSpikes = events
        .where((e) => e.type == BehaviorEventType.cpuSpike)
        .length
        .toDouble();

    return BehaviorFeatures(
      networkCallsCount: networkCalls,
      fileAccessCount: fileAccesses,
      timingEntropy: timingEntropy,
      apiCallSequenceHash: apiSequenceHash,
      memoryAnomalyScore: memoryScore,
      cpuSpikeCount: cpuSpikes,
    );
  }

  /// Run TFLite inference on the 6-dimension feature vector.
  Future<double> _runInference(BehaviorFeatures features) async {
    try {
      final input = features.toFeatureVector();

      // When the real model is ready:
      // final output = List.filled(1, 0.0).reshape([1, 1]);
      // _interpreter.run(input.reshape([1, input.length]), output);
      // return (output[0][0] as double).clamp(0.0, 1.0);

      // Fallback to heuristic for now
      return _heuristicScore(features);
    } catch (e) {
      _log.e('TFLite inference failed: $e');
      return _heuristicScore(features);
    }
  }

  /// Heuristic anomaly scoring when TFLite isn't available.
  ///
  /// Uses calibrated thresholds based on the spec's attack signatures.
  double _heuristicScore(BehaviorFeatures f) {
    double score = 0.0;

    // Frida injection signature: memory > 0.8 AND network > 50
    if (f.memoryAnomalyScore > 0.8 && f.networkCallsCount > 50) {
      score = max(score, 0.92);
    }

    // APK repackage: timing entropy < 0.1
    if (f.timingEntropy < 0.1 && f.networkCallsCount > 5) {
      score = max(score, 0.75);
    }

    // MITM: network > 100 AND CPU spikes > 10
    if (f.networkCallsCount > 100 && f.cpuSpikeCount > 10) {
      score = max(score, 0.80);
    }

    // Root exploit: file access > 30 AND memory > 0.6
    if (f.fileAccessCount > 30 && f.memoryAnomalyScore > 0.6) {
      score = max(score, 0.70);
    }

    // General anomaly: high memory score
    if (f.memoryAnomalyScore > 0.6) {
      score = max(score, f.memoryAnomalyScore * 0.8);
    }

    // Network anomaly
    if (f.networkCallsCount > 80) {
      score = max(score, 0.50);
    }

    return score.clamp(0.0, 1.0);
  }

  /// Shannon entropy of inter-event timing intervals.
  double _calculateTimingEntropy(List<BehaviorEvent> events) {
    if (events.length < 3) return 0.5;

    final intervals = <int>[];
    for (int i = 1; i < events.length; i++) {
      intervals.add(events[i].epochMs - events[i - 1].epochMs);
    }

    // Bucket intervals into 10 bins
    final maxInterval = intervals.reduce(max);
    if (maxInterval == 0) return 0.0; // All events simultaneous — suspicious

    final buckets = List.filled(10, 0);
    for (final interval in intervals) {
      final bucket = ((interval / maxInterval) * 9).floor().clamp(0, 9);
      buckets[bucket]++;
    }

    // Shannon entropy
    final total = intervals.length.toDouble();
    double entropy = 0.0;
    for (final count in buckets) {
      if (count > 0) {
        final p = count / total;
        entropy -= p * log(p) / ln2;
      }
    }

    // Normalize to 0-1 (max entropy for 10 bins = log2(10) ≈ 3.32)
    return (entropy / 3.32).clamp(0.0, 1.0);
  }

  /// Normalized hash of API call sequence.
  double _calculateApiSequenceHash(List<BehaviorEvent> events) {
    final apiCalls = events
        .where((e) => e.type == BehaviorEventType.apiCall)
        .map((e) => e.metadata['endpoint'] ?? 'unknown')
        .toList();

    if (apiCalls.isEmpty) return 0.0;

    // Simple hash normalized to 0-1
    int hash = 0;
    for (final call in apiCalls) {
      hash = (hash * 31 + call.hashCode) & 0x7FFFFFFF;
    }
    return (hash % 10000) / 10000.0;
  }

  /// Extract memory anomaly score from native metadata.
  double _extractMemoryAnomalyScore(List<BehaviorEvent> events) {
    final memoryEvents =
        events.where((e) => e.type == BehaviorEventType.memoryAnomaly).toList();

    if (memoryEvents.isEmpty) return 0.0;

    // Average memory anomaly scores
    double total = 0.0;
    for (final event in memoryEvents) {
      total += (event.metadata['score'] as num?)?.toDouble() ?? 0.0;
    }
    return (total / memoryEvents.length).clamp(0.0, 1.0);
  }

  void dispose() {
    // _interpreter.close();
    _isInitialized = false;
  }
}
