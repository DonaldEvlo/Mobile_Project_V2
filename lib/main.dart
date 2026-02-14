import 'package:flutter/material.dart';

import 'app_theme.dart';
import 'security/security_gate.dart';
import 'security/security_manager.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the security system (TFLite + HTTP client)
  // The SecurityGate handles the initial scan and startup blocking.
  final securityManager = SecurityManager();
  await securityManager.initialize();

  runApp(const AntiTamperingApp());
}

class AntiTamperingApp extends StatelessWidget {
  const AntiTamperingApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Anti-Tampering APK',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      home: const SecurityGate(),
    );
  }
}
