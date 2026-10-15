package de.liforra.snustracker.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * One palette shared with the desktop client, so the two do not read as different
 * products. Amber means "active"; everything else stays out of the way.
 */
val Amber = Color(0xFFF2994A)
val AmberDim = Color(0xFF6E4A28)
val Sky = Color(0xFF56A8D8)
val Ink = Color(0xFF14161A)
val SurfaceDark = Color(0xFF1C1F25)
val SurfaceEdge = Color(0xFF2A2E36)
val TextPrimary = Color(0xFFE6E8EC)
val TextMuted = Color(0xFF8C93A0)
val Good = Color(0xFF5CB85C)

private val DarkColors = darkColorScheme(
    primary = Amber,
    onPrimary = Ink,
    secondary = Sky,
    background = Ink,
    onBackground = TextPrimary,
    surface = SurfaceDark,
    onSurface = TextPrimary,
    surfaceVariant = SurfaceEdge,
    onSurfaceVariant = TextMuted,
    outline = SurfaceEdge,
)

/**
 * Light mode exists so the app does not look broken for anyone who forces it, but the
 * design is dark-first: this is something you tap in a pocket, often at night.
 */
private val LightColors = lightColorScheme(
    primary = Color(0xFFB4632A),
    onPrimary = Color.White,
    secondary = Color(0xFF2E6C90),
    background = Color(0xFFF7F7F8),
    onBackground = Color(0xFF1A1C20),
    surface = Color.White,
    onSurface = Color(0xFF1A1C20),
    surfaceVariant = Color(0xFFE8E9EC),
    onSurfaceVariant = Color(0xFF5A6069),
)

private val AppTypography = Typography(
    displaySmall = TextStyle(fontSize = 44.sp, fontWeight = FontWeight.SemiBold),
    headlineSmall = TextStyle(fontSize = 22.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = TextStyle(fontSize = 17.sp, fontWeight = FontWeight.SemiBold),
    bodyMedium = TextStyle(fontSize = 14.sp),
    labelSmall = TextStyle(fontSize = 11.sp, fontWeight = FontWeight.Medium),
)

@Composable
fun SnusTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = AppTypography,
        content = content,
    )
}
