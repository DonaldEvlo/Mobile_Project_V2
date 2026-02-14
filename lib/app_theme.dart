import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Premium theme system with dark and light modes.
///
/// Use `AppTheme.of(context)` for theme-aware colors and decorations.
class AppTheme {
  AppTheme._();

  // ═══════════════════════════════════════════════
  // DARK PALETTE
  // ═══════════════════════════════════════════════
  static const Color bgDark = Color(0xFF0A0E1A);
  static const Color bgCard = Color(0xFF121829);
  static const Color bgCardLight = Color(0xFF1A2240);
  static const Color surface = Color(0xFF1E2545);

  // ═══════════════════════════════════════════════
  // LIGHT PALETTE
  // ═══════════════════════════════════════════════
  static const Color bgLight = Color(0xFFF5F6FA);
  static const Color bgCardLightMode = Color(0xFFFFFFFF);
  static const Color bgCardLightAccent = Color(0xFFEEF0F8);
  static const Color surfaceLight = Color(0xFFE8EAF2);

  // ═══════════════════════════════════════════════
  // ACCENT COLORS (shared)
  // ═══════════════════════════════════════════════
  static const Color accentCyan = Color(0xFF00E5FF);
  static const Color accentGreen = Color(0xFF00E676);
  static const Color accentPurple = Color(0xFF7C4DFF);
  static const Color accentAmber = Color(0xFFFFAB00);
  static const Color accentRed = Color(0xFFFF1744);

  // ═══════════════════════════════════════════════
  // TEXT COLORS — DARK
  // ═══════════════════════════════════════════════
  static const Color textPrimary = Color(0xFFE8EAF6);
  static const Color textSecondary = Color(0xFF9FA8DA);
  static const Color textMuted = Color(0xFF5C6BC0);

  // ═══════════════════════════════════════════════
  // TEXT COLORS — LIGHT
  // ═══════════════════════════════════════════════
  static const Color textPrimaryLight = Color(0xFF1A1D2E);
  static const Color textSecondaryLight = Color(0xFF4A5068);
  static const Color textMutedLight = Color(0xFF8890AA);

  // ═══════════════════════════════════════════════
  // THREAT LEVEL COLORS
  // ═══════════════════════════════════════════════
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

  // ═══════════════════════════════════════════════
  // GRADIENTS
  // ═══════════════════════════════════════════════
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

  // ═══════════════════════════════════════════════
  // THEME-AWARE HELPERS
  // ═══════════════════════════════════════════════

  /// Convenience to check if current theme is dark.
  static bool isDark(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark;

  /// Get background color for current mode.
  static Color backgroundColor(BuildContext context) =>
      isDark(context) ? bgDark : bgLight;

  /// Get card background for current mode.
  static Color cardColor(BuildContext context) =>
      isDark(context) ? bgCard : bgCardLightMode;

  /// Get card accent background for current mode.
  static Color cardAccentColor(BuildContext context) =>
      isDark(context) ? bgCardLight : bgCardLightAccent;

  /// Get surface color for current mode.
  static Color surfaceColor(BuildContext context) =>
      isDark(context) ? surface : surfaceLight;

  /// Primary text color.
  static Color primaryText(BuildContext context) =>
      isDark(context) ? textPrimary : textPrimaryLight;

  /// Secondary text color.
  static Color secondaryText(BuildContext context) =>
      isDark(context) ? textSecondary : textSecondaryLight;

  /// Muted text color.
  static Color mutedText(BuildContext context) =>
      isDark(context) ? textMuted : textMutedLight;

  /// Divider color.
  static Color dividerColor(BuildContext context) =>
      isDark(context) ? Colors.white10 : Colors.black12;

  // ═══════════════════════════════════════════════
  // CARD DECORATIONS
  // ═══════════════════════════════════════════════

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

  /// Theme-aware card decoration.
  static BoxDecoration cardDecorationOf(BuildContext context,
      {Color? borderColor}) {
    final dark = isDark(context);
    return BoxDecoration(
      color: dark ? bgCard : bgCardLightMode,
      borderRadius: BorderRadius.circular(16),
      border: Border.all(
        color: borderColor ??
            (dark
                ? bgCardLight.withOpacity(0.5)
                : Colors.black.withOpacity(0.06)),
        width: 1,
      ),
      boxShadow: [
        BoxShadow(
          color: dark
              ? Colors.black.withOpacity(0.3)
              : Colors.black.withOpacity(0.05),
          blurRadius: 12,
          offset: const Offset(0, 4),
        ),
      ],
    );
  }

  static BoxDecoration glassDecoration({Color? tintColor}) => BoxDecoration(
        color: (tintColor ?? bgCard).withOpacity(0.15),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: (tintColor ?? accentCyan).withOpacity(0.2),
          width: 1,
        ),
      );

  static BoxDecoration glassDecorationOf(BuildContext context,
      {Color? tintColor}) {
    final dark = isDark(context);
    final base = tintColor ?? (dark ? bgCard : bgCardLightMode);
    return BoxDecoration(
      color: base.withOpacity(dark ? 0.15 : 0.08),
      borderRadius: BorderRadius.circular(16),
      border: Border.all(
        color: (tintColor ?? accentCyan).withOpacity(dark ? 0.2 : 0.15),
        width: 1,
      ),
    );
  }

  // ═══════════════════════════════════════════════
  // THEME DATA
  // ═══════════════════════════════════════════════

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
          iconTheme: const IconThemeData(color: textSecondary),
        ),
        iconTheme: const IconThemeData(color: accentCyan),
        dividerColor: Colors.white10,
        cardColor: bgCard,
      );

  static ThemeData get lightTheme => ThemeData(
        brightness: Brightness.light,
        scaffoldBackgroundColor: bgLight,
        primaryColor: accentPurple,
        colorScheme: const ColorScheme.light(
          primary: accentPurple,
          secondary: accentCyan,
          surface: surfaceLight,
          error: accentRed,
        ),
        textTheme: GoogleFonts.interTextTheme(
          ThemeData.light().textTheme,
        ).apply(bodyColor: textPrimaryLight, displayColor: textPrimaryLight),
        appBarTheme: AppBarTheme(
          backgroundColor: bgLight,
          elevation: 0,
          centerTitle: false,
          titleTextStyle: GoogleFonts.inter(
            fontSize: 20,
            fontWeight: FontWeight.w700,
            color: textPrimaryLight,
          ),
          iconTheme: const IconThemeData(color: textSecondaryLight),
        ),
        iconTheme: const IconThemeData(color: accentPurple),
        dividerColor: Colors.black12,
        cardColor: bgCardLightMode,
      );
}
