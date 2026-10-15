package de.liforra.snustracker.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import de.liforra.snustracker.R

/**
 * The liforra.de palette used by the desktop bar, shared with the Linux client
 * (`linux-x86/src/theme.rs`) so they read as one product. Change the tokens in both
 * places or not at all.
 *
 * Dark only, like the bar: this is something you tap in a pocket, often at night.
 */
val Bg = Color(0xFF030205)
val Panel = Color(0xFF09050F)
val DividerColor = Color(0xFF2B2239)
val Frame = Color(0xFF9D5BF4)
val Accent = Color(0xFFAC77FA)
val AccentStrong = Color(0xFFC295FF)
val AccentWash = Color(0xFF211632)
val Hover = Color(0xFF120B1C)
val TextPrimary = Color(0xFFECE9F4)
val TextBody = Color(0xFFBFBCC6)
val TextMuted = Color(0xFF918D9A)
val Good = Color(0xFF7EE2A8)
val Warn = Color(0xFFFFCF6B)
val Bad = Color(0xFFFF6B8B)

/** Nicotine takes the accent, cotinine the warm contrast, so the curves stay apart. */
val Nicotine = Accent
val Cotinine = Warn

private val SpaceMono = FontFamily(
    Font(R.font.space_mono_regular, FontWeight.Normal),
    Font(R.font.space_mono_bold, FontWeight.Bold),
)

private val DarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Bg,
    primaryContainer = AccentWash,
    onPrimaryContainer = AccentStrong,
    secondary = Warn,
    background = Bg,
    onBackground = TextPrimary,
    surface = Panel,
    onSurface = TextPrimary,
    surfaceVariant = Hover,
    onSurfaceVariant = TextMuted,
    surfaceContainer = Panel,
    surfaceContainerHigh = Panel,
    surfaceContainerHighest = Hover,
    outline = DividerColor,
    outlineVariant = DividerColor,
    error = Bad,
)

private fun style(size: Int, bold: Boolean = false) = TextStyle(
    fontFamily = SpaceMono,
    fontSize = size.sp,
    fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal,
)

private val AppTypography = Typography(
    displaySmall = style(40, bold = true),
    headlineSmall = style(20, bold = true),
    titleLarge = style(20, bold = true),
    titleMedium = style(15, bold = true),
    titleSmall = style(13, bold = true),
    bodyLarge = style(15),
    bodyMedium = style(13),
    bodySmall = style(12),
    labelLarge = style(13, bold = true),
    labelMedium = style(12),
    labelSmall = style(11),
)

/** Square, as in the bar: no corner is rounded anywhere. */
private val SquareShapes = Shapes(
    extraSmall = RoundedCornerShape(0),
    small = RoundedCornerShape(0),
    medium = RoundedCornerShape(0),
    large = RoundedCornerShape(0),
    extraLarge = RoundedCornerShape(0),
)

@Composable
fun SnusTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = AppTypography,
        shapes = SquareShapes,
        content = content,
    )
}
