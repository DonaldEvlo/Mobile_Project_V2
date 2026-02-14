/// Types of behavioral events tracked by the security system.
enum BehaviorEventType {
  networkCall,
  fileAccess,
  apiCall,
  cpuSpike,
  memoryAnomaly,
  userInteraction,
  screenChange,
  backgroundTask,
}

/// A timestamped behavioral event used for anomaly detection.
///
/// These events are buffered by [SecurityManager] and periodically
/// analyzed by the TFLite model to compute behavioral anomaly scores.
class BehaviorEvent {
  final BehaviorEventType type;
  final DateTime timestamp;
  final Map<String, dynamic> metadata;

  BehaviorEvent({
    required this.type,
    DateTime? timestamp,
    this.metadata = const {},
  }) : timestamp = timestamp ?? DateTime.now();

  /// Time since epoch in milliseconds — used for timing entropy calculation.
  int get epochMs => timestamp.millisecondsSinceEpoch;

  Map<String, dynamic> toJson() => {
    'type': type.name,
    'timestamp': timestamp.toIso8601String(),
    'epoch_ms': epochMs,
    'metadata': metadata,
  };

  factory BehaviorEvent.fromJson(Map<String, dynamic> json) {
    return BehaviorEvent(
      type: BehaviorEventType.values.firstWhere(
        (e) => e.name == json['type'],
        orElse: () => BehaviorEventType.userInteraction,
      ),
      timestamp: DateTime.parse(json['timestamp']),
      metadata: Map<String, dynamic>.from(json['metadata'] ?? {}),
    );
  }

  @override
  String toString() => 'BehaviorEvent(${type.name} @ $timestamp)';
}
