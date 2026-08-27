import 'package:flutter/material.dart';

import 'app_theme.dart';
import 'screens/splash_screen.dart';
import 'theme_provider.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final themeProvider = ThemeProvider();
  await themeProvider.initialize();

  // Security initialization runs in SecurityGate, not here: doing it before
  // runApp() crashed when the backend was unreachable or native plugins were
  // missing (emulator).
  runApp(AntiTamperingApp(themeProvider: themeProvider));
}

class AntiTamperingApp extends StatefulWidget {
  final ThemeProvider themeProvider;

  const AntiTamperingApp({super.key, required this.themeProvider});

  /// Global access to theme provider from anywhere.
  static ThemeProvider of(BuildContext context) {
    final state = context.findAncestorStateOfType<_AntiTamperingAppState>();
    return state!.widget.themeProvider;
  }

  @override
  State<AntiTamperingApp> createState() => _AntiTamperingAppState();
}

class _AntiTamperingAppState extends State<AntiTamperingApp> {
  @override
  void initState() {
    super.initState();
    widget.themeProvider.addListener(_onThemeChanged);
  }

  @override
  void dispose() {
    widget.themeProvider.removeListener(_onThemeChanged);
    super.dispose();
  }

  void _onThemeChanged() {
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GuardPay AI',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: widget.themeProvider.themeMode,
      home: const SplashScreen(),
    );
  }
}
