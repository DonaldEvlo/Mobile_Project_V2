import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../app_theme.dart';
import '../security/security_gate.dart';

/// Animated splash screen shown at app startup.
///
/// Features a shield icon with scale + glow animation,
/// app name with fade-in, and auto-navigation to SecurityGate.
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with TickerProviderStateMixin {
  late AnimationController _scaleController;
  late AnimationController _fadeController;
  late AnimationController _glowController;

  late Animation<double> _scaleAnim;
  late Animation<double> _fadeAnim;
  late Animation<double> _subtitleFadeAnim;
  late Animation<Offset> _subtitleSlideAnim;

  @override
  void initState() {
    super.initState();

    // Shield scale-up animation (0 → 1)
    _scaleController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 800),
    );
    _scaleAnim = CurvedAnimation(
      parent: _scaleController,
      curve: Curves.elasticOut,
    );

    // Text fade-in animation
    _fadeController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1000),
    );
    _fadeAnim = CurvedAnimation(
      parent: _fadeController,
      curve: Curves.easeIn,
    );
    _subtitleFadeAnim = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _fadeController,
        curve: const Interval(0.4, 1.0, curve: Curves.easeIn),
      ),
    );
    _subtitleSlideAnim = Tween<Offset>(
      begin: const Offset(0, 0.3),
      end: Offset.zero,
    ).animate(
      CurvedAnimation(
        parent: _fadeController,
        curve: const Interval(0.4, 1.0, curve: Curves.easeOut),
      ),
    );

    // Glow pulse
    _glowController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    )..repeat(reverse: true);

    _startAnimation();
  }

  Future<void> _startAnimation() async {
    await Future.delayed(const Duration(milliseconds: 200));
    _scaleController.forward();
    await Future.delayed(const Duration(milliseconds: 500));
    _fadeController.forward();
    await Future.delayed(const Duration(milliseconds: 2000));

    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      PageRouteBuilder(
        pageBuilder: (_, __, ___) => const SecurityGate(),
        transitionsBuilder: (_, animation, __, child) {
          return FadeTransition(opacity: animation, child: child);
        },
        transitionDuration: const Duration(milliseconds: 600),
      ),
    );
  }

  @override
  void dispose() {
    _scaleController.dispose();
    _fadeController.dispose();
    _glowController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDark(context);
    final bgColor = isDark ? AppTheme.bgDark : AppTheme.bgLight;
    final subColor =
        isDark ? AppTheme.textSecondary : AppTheme.textSecondaryLight;

    return Scaffold(
      backgroundColor: bgColor,
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Shield icon with glow
            AnimatedBuilder(
              animation: Listenable.merge([_scaleController, _glowController]),
              builder: (context, child) {
                return Transform.scale(
                  scale: _scaleAnim.value,
                  child: Container(
                    width: 140,
                    height: 140,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: LinearGradient(
                        colors: [
                          AppTheme.accentCyan
                              .withOpacity(0.15 + _glowController.value * 0.1),
                          AppTheme.accentPurple
                              .withOpacity(0.1 + _glowController.value * 0.08),
                        ],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                      border: Border.all(
                        color: AppTheme.accentCyan
                            .withOpacity(0.4 + _glowController.value * 0.2),
                        width: 2.5,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: AppTheme.accentCyan
                              .withOpacity(0.15 + _glowController.value * 0.15),
                          blurRadius: 40,
                          spreadRadius: 8,
                        ),
                        BoxShadow(
                          color: AppTheme.accentPurple
                              .withOpacity(0.1 + _glowController.value * 0.1),
                          blurRadius: 60,
                          spreadRadius: 12,
                        ),
                      ],
                    ),
                    child: const Icon(
                      Icons.shield,
                      color: AppTheme.accentCyan,
                      size: 60,
                    ),
                  ),
                );
              },
            ),
            const SizedBox(height: 40),

            // App name
            FadeTransition(
              opacity: _fadeAnim,
              child: ShaderMask(
                shaderCallback: (bounds) =>
                    AppTheme.primaryGradient.createShader(bounds),
                child: Text(
                  'GuardPay AI',
                  style: GoogleFonts.inter(
                    fontSize: 36,
                    fontWeight: FontWeight.w900,
                    color: Colors.white,
                    letterSpacing: 2,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),

            // Subtitle
            SlideTransition(
              position: _subtitleSlideAnim,
              child: FadeTransition(
                opacity: _subtitleFadeAnim,
                child: Text(
                  'Security Intelligence',
                  style: GoogleFonts.inter(
                    fontSize: 14,
                    fontWeight: FontWeight.w400,
                    color: subColor,
                    letterSpacing: 4,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 60),

            // Loading dots
            FadeTransition(
              opacity: _fadeAnim,
              child: SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: AppTheme.accentCyan.withOpacity(0.5),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
