import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Premium dark theme for the security dashboard.
class AppTheme {
  AppTheme._();

  // ── Color Palette ──
  static const Color bgDark = Color(0xFF0A0E1A);
  static const Color bgCard = Color(0xFF121829);
  static const Color bgCardLight = Color(0xFF1A2240);
  static const Color surface = Color(0xFF1E2545);

  static const Color accentCyan = Color(0xFF00E5FF);
  static const Color accentGreen = Color(0xFF00E676);
  static const Color accentPurple = Color(0xFF7C4DFF);
  static const Color accentAmber = Color(0xFFFFAB00);
  static const Color accentRed = Color(0xFFFF1744);

  static const Color textPrimary = Color(0xFFE8EAF6);
  static const Color textSecondary = Color(0xFF9FA8DA);
  static const Color textMuted = Color(0xFF5C6BC0);

  // ── Threat Level Colors ──
  static const Color cleanColor = Color(0xFF00E676);
  static const Color lowColor = Color(0xFF69F0AE);
  static const Color mediumColor = Color(0xFFFFAB00);
  static const Color highColor = Color(0xFFFF6D00);
  static const Color criticalColor = Color(0xFFFF1744);

  /// Get color for a threat level name.
  static Color threatColor(String level) {
    switch (level.toLowerCase()) {
      case 'clean':
        return cleanColor;
      case 'low':
        return lowColor;
      case 'medium':
        return mediumColor;
      case 'high':
        return highColor;
      case 'critical':
        return criticalColor;
      default:
        return textMuted;
    }
  }

  // ── Gradients ──
  static const LinearGradient primaryGradient = LinearGradient(
    colors: [accentCyan, accentPurple],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient dangerGradient = LinearGradient(
    colors: [accentAmber, accentRed],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  // ── Card Decoration ──
  static BoxDecoration cardDecoration({Color? borderColor}) => BoxDecoration(
        color: bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: borderColor ?? bgCardLight.withOpacity(0.5),
          width: 1,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.3),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      );

  static BoxDecoration glassDecoration({Color? tintColor}) => BoxDecoration(
        color: (tintColor ?? bgCard).withOpacity(0.15),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: (tintColor ?? accentCyan).withOpacity(0.2),
          width: 1,
        ),
      );

  // ── Theme Data ──
  static ThemeData get darkTheme => ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: bgDark,
        primaryColor: accentCyan,
        colorScheme: const ColorScheme.dark(
          primary: accentCyan,
          secondary: accentPurple,
          surface: surface,
          error: accentRed,
        ),
        textTheme: GoogleFonts.interTextTheme(
          ThemeData.dark().textTheme,
        ).apply(bodyColor: textPrimary, displayColor: textPrimary),
        appBarTheme: AppBarTheme(
          backgroundColor: bgDark,
          elevation: 0,
          centerTitle: false,
          titleTextStyle: GoogleFonts.inter(
            fontSize: 20,
            fontWeight: FontWeight.w700,
            color: textPrimary,
          ),
        ),
        iconTheme: const IconThemeData(color: accentCyan),
      );
}
