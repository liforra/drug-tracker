package de.liforra.snustracker.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import de.liforra.snustracker.Curves
import de.liforra.snustracker.Snapshot

/**
 * The reading view: what the log adds up to over a day, and where that sits against
 * this person's own recent baseline.
 *
 * Separate from the home screen on purpose. Home answers "is something in, and shall I
 * put one in"; this answers "how am I doing", and the two are looked at in different
 * moods.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StatsScreen(snapshot: Snapshot, curves: Curves?, onBack: () -> Unit) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Statistik", style = MaterialTheme.typography.headlineSmall) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Zurück")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
            )
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Tile(
                    Modifier.weight(1f),
                    "Toleranz",
                    snapshot.toleranceIndex?.let { "%.0f".format(it) } ?: "—",
                    snapshot.toleranceIndex?.let { "% vom Hoch" } ?: "zu wenig Verlauf",
                    Cotinine,
                )
                Tile(
                    Modifier.weight(1f),
                    "Heute",
                    snapshot.todayCount.toString(),
                    "%.1f mg".format(snapshot.todayMg),
                    Accent,
                )
            }

            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Tile(
                    Modifier.weight(1f),
                    "Nikotin",
                    "%.1f".format(snapshot.nicotineNgMl),
                    "%+.2f/min".format(snapshot.nicotineRatePerMin),
                    Accent,
                )
                Tile(
                    Modifier.weight(1f),
                    "Cotinin",
                    "%.0f".format(snapshot.cotinineNgMl),
                    "ng/mL",
                    Cotinine,
                )
            }

            Spacer(Modifier.height(24.dp))
            Text("Letzte 24 Stunden", style = MaterialTheme.typography.titleMedium, color = TextPrimary)
            Spacer(Modifier.height(4.dp))
            Text(
                "Nikotin in Bernstein, Cotinin in Blau — eigene Skalen, weil Cotinin sich " +
                    "über Tage aufbaut und Nikotin im Stundentakt schwankt.",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
            )
            Spacer(Modifier.height(12.dp))

            if (curves == null || curves.times.size < 2) {
                Box(
                    Modifier.fillMaxWidth().height(200.dp),
                    contentAlignment = androidx.compose.ui.Alignment.Center,
                ) {
                    Text("Noch keine Daten", color = TextMuted)
                }
            } else {
                DualAxisChart(curves, Modifier.fillMaxWidth().height(220.dp))
            }

            Spacer(Modifier.height(24.dp))
            Text(
                buildString {
                    append("Gerechnet mit ")
                    append("%.0f kg".format(snapshot.bodyMassKg))
                    if (snapshot.bodyMassIsDefault) append(" (Voreinstellung)")
                    append(".")
                },
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
            )
            Spacer(Modifier.height(32.dp))
        }
    }
}

/**
 * Two curves, two scales, one time axis.
 *
 * Sharing a scale would be the obvious choice and it would make the chart useless:
 * cotinine sits an order of magnitude above nicotine, so on a common axis the nicotine
 * curve flattens into the baseline and the sawtooth that carries all the information
 * disappears.
 */
@Composable
private fun DualAxisChart(curves: Curves, modifier: Modifier) {
    val nicotinePeak = (curves.nicotine.maxOrNull() ?: 1.0).coerceAtLeast(1.0)
    val cotininePeak = (curves.cotinine.maxOrNull() ?: 1.0).coerceAtLeast(1.0)

    Canvas(
        modifier
            .clip(RectangleShape)
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, MaterialTheme.colorScheme.outline, RectangleShape)
            .padding(12.dp)
    ) {
        val count = curves.times.size
        val stepX = size.width / (count - 1).toFloat()

        fun pointsFor(values: List<Double>, peak: Double): List<Offset> =
            values.mapIndexed { i, value ->
                Offset(
                    x = i * stepX,
                    y = size.height - (value / peak).toFloat() * size.height,
                )
            }

        val nicotine = pointsFor(curves.nicotine, nicotinePeak)
        val cotinine = pointsFor(curves.cotinine, cotininePeak)

        // Filled area under nicotine: it reads as "how much is in you right now", and
        // an area says that better than a line.
        val area = Path().apply {
            moveTo(0f, size.height)
            nicotine.forEach { lineTo(it.x, it.y) }
            lineTo(size.width, size.height)
            close()
        }
        drawPath(area, Accent.copy(alpha = 0.18f))

        val nicotinePath = Path().apply {
            nicotine.forEachIndexed { i, p -> if (i == 0) moveTo(p.x, p.y) else lineTo(p.x, p.y) }
        }
        drawPath(nicotinePath, Accent, style = Stroke(width = 2.5f))

        val cotininePath = Path().apply {
            cotinine.forEachIndexed { i, p -> if (i == 0) moveTo(p.x, p.y) else lineTo(p.x, p.y) }
        }
        drawPath(cotininePath, Cotinine, style = Stroke(width = 2f))

        // Baseline, so an empty stretch is visibly zero rather than merely empty.
        drawLine(
            Color.White.copy(alpha = 0.08f),
            Offset(0f, size.height),
            Offset(size.width, size.height),
            strokeWidth = 1f,
        )
    }
}

@Composable
private fun Tile(modifier: Modifier, label: String, value: String, unit: String, accent: Color) {
    Column(
        modifier
            .clip(RectangleShape)
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, MaterialTheme.colorScheme.outline, RectangleShape)
            .padding(vertical = 14.dp, horizontal = 12.dp)
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = TextMuted)
        Spacer(Modifier.height(4.dp))
        Text(value, style = MaterialTheme.typography.headlineSmall, color = accent)
        Text(unit, style = MaterialTheme.typography.labelSmall, color = TextMuted)
    }
}
