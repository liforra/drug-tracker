package de.liforra.snustracker.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import de.liforra.snustracker.Invite
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.automirrored.filled.ShowChart
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import de.liforra.snustracker.OpenSession
import de.liforra.snustracker.Product
import de.liforra.snustracker.Snapshot
import kotlinx.coroutines.delay

/**
 * The first thing that appears on launch: what is in right now, and every variety, all
 * one tap away. Nothing is behind a menu, because a tracker that takes effort is a
 * tracker with gaps in it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    snapshot: Snapshot,
    busy: Boolean,
    message: String?,
    onStart: (Product) -> Unit,
    onEnd: (OpenSession) -> Unit,
    onPauseToggle: (OpenSession) -> Unit,
    onDiscard: (OpenSession) -> Unit,
    onAddProduct: (String, Double) -> Unit,
    onSetDuration: (Product, Double) -> Unit,
    onRetire: (Product) -> Unit,
    onSetBodyMass: (Double) -> Unit,
    onApproveDevices: () -> Unit,
    invite: Invite?,
    onInviteDevice: () -> Unit,
    onDismissInvite: () -> Unit,
    onSync: () -> Unit,
    onOpenStats: () -> Unit,
    onDismissMessage: () -> Unit,
) {
    var showAddSheet by remember { mutableStateOf(false) }
    var tuning by remember { mutableStateOf<Product?>(null) }
    var showBodySheet by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Snus Tracker", style = MaterialTheme.typography.headlineSmall) },
                actions = {
                    ConnectionDot(snapshot.online, snapshot.pending)
                    IconButton(onClick = onOpenStats) {
                        Icon(Icons.AutoMirrored.Filled.ShowChart, contentDescription = "Statistik")
                    }
                    IconButton(onClick = { showSettings = true }) {
                        Icon(Icons.Default.Settings, contentDescription = "Körperdaten")
                    }
                    IconButton(onClick = onSync, enabled = !busy) {
                        Icon(Icons.Default.Refresh, contentDescription = "Synchronisieren")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { showAddSheet = true },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Sorte")
            }
        },
        snackbarHost = {
            message?.let {
                Snackbar(
                    action = { TextButton(onClick = onDismissMessage) { Text("OK") } },
                    modifier = Modifier.padding(12.dp),
                ) { Text(it) }
            }
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(horizontal = 16.dp)
                .fillMaxSize()
        ) {
            AnimatedVisibility(
                visible = snapshot.openSession != null,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically(),
            ) {
                snapshot.openSession?.let { open ->
                    ActiveSessionCard(
                        session = open,
                        busy = busy,
                        onEnd = { onEnd(open) },
                        onPauseToggle = { onPauseToggle(open) },
                        onDiscard = { onDiscard(open) },
                    )
                    Spacer(Modifier.height(16.dp))
                }
            }

            if (snapshot.locked) {
                LockedBanner()
                Spacer(Modifier.height(16.dp))
            }

            StatsRow(snapshot)
            Spacer(Modifier.height(20.dp))

            Text(
                "Sorten",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Spacer(Modifier.height(10.dp))

            if (snapshot.products.isEmpty()) {
                EmptyProducts()
            } else {
                LazyVerticalGrid(
                    columns = GridCells.Fixed(2),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    contentPadding = PaddingValues(bottom = 96.dp),
                ) {
                    items(snapshot.products, key = { it.id }) { product ->
                        ProductTile(
                            product = product,
                            // One at a time: a second pouch while one is in is almost
                            // always a mis-tap, and correcting a stray record is more
                            // friction than the tap ever saved.
                            enabled = snapshot.openSession == null && !busy && !snapshot.locked,
                            onClick = { onStart(product) },
                            onLongClick = { tuning = product },
                        )
                    }
                }
            }
        }
    }

    if (showAddSheet) {
        AddProductSheet(
            onDismiss = { showAddSheet = false },
            onConfirm = { name, mg ->
                onAddProduct(name, mg)
                showAddSheet = false
            },
        )
    }

    tuning?.let { product ->
        NumberSheet(
            title = product.name,
            explanation = "Wie lange gibt diese Sorte Nikotin ab? Nach dieser Zeit ist " +
                "sie praktisch ausgeschöpft. Voreinstellung des Modells: 60 Minuten.",
            label = "Minuten",
            initial = product.defaultDurationSecs?.let { (it / 60).toInt().toString() } ?: "60",
            onDismiss = { tuning = null },
            onConfirm = { minutes ->
                onSetDuration(product, minutes)
                tuning = null
            },
            onRetire = {
                onRetire(product)
                tuning = null
            },
        )
    }

    if (showSettings) {
        SettingsSheet(
            bodyMassKg = snapshot.bodyMassKg,
            bodyMassIsDefault = snapshot.bodyMassIsDefault,
            onDismiss = { showSettings = false },
            onEditBodyMass = {
                showSettings = false
                showBodySheet = true
            },
            onApproveDevices = {
                showSettings = false
                onApproveDevices()
            },
            onInviteDevice = {
                showSettings = false
                onInviteDevice()
            },
        )
    }

    invite?.let { InviteDialog(it, onDismissInvite) }

    if (showBodySheet) {
        NumberSheet(
            title = "Körpergewicht",
            explanation = "Das Verteilungsvolumen wird pro Kilogramm gerechnet, jeder " +
                "Spiegel skaliert also damit. Ohne Angabe rechnet das Modell mit 75 kg.",
            label = "kg",
            initial = snapshot.bodyMassKg.toInt().toString(),
            onDismiss = { showBodySheet = false },
            onConfirm = { kg ->
                onSetBodyMass(kg)
                showBodySheet = false
            },
        )
    }
}

/**
 * The things that are set once and then forgotten about.
 *
 * Kept off the home screen deliberately: that screen answers "shall I put one in", and
 * every extra control there is one more thing to read past.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsSheet(
    bodyMassKg: Double,
    bodyMassIsDefault: Boolean,
    onDismiss: () -> Unit,
    onEditBodyMass: () -> Unit,
    onApproveDevices: () -> Unit,
    onInviteDevice: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 8.dp).padding(bottom = 32.dp)) {
            ListItem(
                headlineContent = { Text("Körpergewicht") },
                supportingContent = {
                    Text(
                        "%.0f kg%s".format(
                            bodyMassKg,
                            if (bodyMassIsDefault) " — Voreinstellung" else "",
                        )
                    )
                },
                modifier = Modifier.clickable(onClick = onEditBodyMass),
            )
            ListItem(
                headlineContent = { Text("Gerät einladen") },
                supportingContent = {
                    Text("QR-Code und Einladungscode für Laptop oder Handy. Einmalig, nur Minuten gültig.")
                },
                modifier = Modifier.clickable(onClick = onInviteDevice),
            )
            ListItem(
                headlineContent = { Text("Neues Gerät freischalten") },
                supportingContent = {
                    Text("Gibt Geräten, die sich später angemeldet haben, den Datenschlüssel.")
                },
                modifier = Modifier.clickable(onClick = onApproveDevices),
            )
        }
    }
}

/**
 * The enrolment values for a new device, as a QR code and as text.
 *
 * The code is a one-time secret, so it lives only as long as this dialog does and is never
 * stored. The text stays selectable for the laptop, where scanning a phone screen is
 * clumsier than typing three values.
 */
@Composable
private fun InviteDialog(invite: Invite, onDismiss: () -> Unit) {
    val qr = remember(invite.uri) { qrBitmap(invite.uri) }
    val minutes = remember(invite) {
        ((invite.expiresAt - System.currentTimeMillis() / 1000) / 60).coerceAtLeast(0)
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Fertig") } },
        title = { Text("Gerät einladen") },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                qr?.let {
                    Image(
                        bitmap = it.asImageBitmap(),
                        contentDescription = "QR-Code zur Geräteanmeldung",
                        filterQuality = FilterQuality.None,
                        modifier = Modifier.size(240.dp).clip(RectangleShape),
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    "Gültig für $minutes Minuten, einmalig einlösbar. Danach hier in den " +
                        "Einstellungen „Neues Gerät freischalten“ tippen, sonst bleibt das " +
                        "neue Gerät gesperrt.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
                SelectionContainer {
                    Column(Modifier.fillMaxWidth()) {
                        InviteField("Server-Adresse", invite.serverUrl)
                        InviteField("Server-Schlüssel", invite.serverKey)
                        InviteField("Einladungscode", invite.code)
                    }
                }
            }
        },
    )
}

@Composable
private fun InviteField(label: String, value: String) {
    Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
    Spacer(Modifier.height(8.dp))
}

/** Black modules on white with a quiet zone, whatever the app theme: scanners need contrast. */
private fun qrBitmap(content: String, size: Int = 512): Bitmap? = try {
    val matrix = QRCodeWriter().encode(
        content, BarcodeFormat.QR_CODE, size, size,
        mapOf<EncodeHintType, Any>(
            EncodeHintType.MARGIN to 2,
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        ),
    )
    val pixels = IntArray(size * size) { i ->
        if (matrix[i % size, i / size]) android.graphics.Color.BLACK else android.graphics.Color.WHITE
    }
    Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
} catch (e: Exception) {
    null
}

/**
 * One number, with the reason it matters. Used for the two calibration values that
 * change what every other figure in the app means.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NumberSheet(
    title: String,
    explanation: String,
    label: String,
    initial: String,
    onDismiss: () -> Unit,
    onConfirm: (Double) -> Unit,
    onRetire: (() -> Unit)? = null,
) {
    var text by remember { mutableStateOf(initial) }
    // Comma decimals: a German keyboard offers a comma, and rejecting it would be
    // rejecting what the user was handed.
    val value = text.replace(',', '.').toDoubleOrNull()

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 24.dp).padding(bottom = 32.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge, color = TextPrimary)
            Spacer(Modifier.height(8.dp))
            Text(explanation, style = MaterialTheme.typography.bodySmall, color = TextMuted)
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text(label) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(20.dp))
            Button(
                onClick = { value?.let(onConfirm) },
                enabled = value != null && value > 0,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RectangleShape,
            ) {
                Text("Speichern")
            }
            onRetire?.let { retire ->
                TextButton(
                    onClick = retire,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                ) {
                    // "Ausblenden", not "Löschen": sessions already recorded against
                    // this variety still need it to compute their curves.
                    Text("Ausblenden", color = TextMuted)
                }
            }
        }
    }
}

/**
 * The card that answers "is something in, and for how long".
 *
 * The clock ticks locally from the start timestamp rather than polling the native side:
 * elapsed time is arithmetic, and waking the core once a second to be told what we can
 * work out ourselves would cost battery for nothing.
 */
@Composable
private fun ActiveSessionCard(
    session: OpenSession,
    busy: Boolean,
    onEnd: () -> Unit,
    onPauseToggle: () -> Unit,
    onDiscard: () -> Unit,
) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(session.sessionId) {
        while (true) {
            now = System.currentTimeMillis() / 1000
            delay(1000)
        }
    }
    val elapsed = (now - session.startedAt).coerceAtLeast(0)

    // A gentle pulse so the card reads as live rather than as a static banner.
    val pulse by animateFloatAsState(
        targetValue = if (elapsed % 2 == 0L) 1f else 0.55f,
        label = "pulse",
    )

    Surface(
        shape = RectangleShape,
        color = Color.Transparent,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            Modifier
                .clip(RectangleShape)
                .background(AccentWash)
                .border(1.dp, Accent, RectangleShape)
                .padding(20.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(Accent.copy(alpha = pulse))
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    session.productName,
                    style = MaterialTheme.typography.titleMedium,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.height(12.dp))
            Text(
                formatElapsed(elapsed),
                style = MaterialTheme.typography.displaySmall,
                color = Accent,
            )
            Text(
                if (session.paused) "ruht — gibt gerade nichts ab" else "seit dem Einlegen",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
            )

            // What the pouch still has in it. Worth showing, because a spent pouch in
            // your lip does nothing at all, and there is no way to tell by feel.
            session.releaseLeftSecs?.let { left ->
                Spacer(Modifier.height(6.dp))
                Text(
                    if (left <= 0) "leer — gibt nichts mehr ab"
                    else "noch ${left / 60} min Freisetzung",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (left <= 0) TextMuted else Accent.copy(alpha = 0.8f),
                )
            }

            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(
                    onClick = onPauseToggle,
                    enabled = !busy,
                    modifier = Modifier.weight(1f).height(52.dp),
                    shape = RectangleShape,
                ) {
                    Text(
                        if (session.paused) "Wieder rein" else "Ruhen",
                        style = MaterialTheme.typography.titleMedium,
                        color = Accent,
                    )
                }
                Button(
                    onClick = onEnd,
                    enabled = !busy,
                    modifier = Modifier.weight(1f).height(52.dp),
                    shape = RectangleShape,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Accent,
                        contentColor = Bg,
                    ),
                ) {
                    Text("Beenden", style = MaterialTheme.typography.titleMedium)
                }
            }

            // Deliberately small and last: this is the undo for a mis-tap, not a second
            // way to end a session. Ending records a consumption; discarding says it
            // never happened, and the two must not be a coin flip in the UI.
            TextButton(
                onClick = onDiscard,
                enabled = !busy,
                modifier = Modifier.align(Alignment.CenterHorizontally),
            ) {
                Text("Verwerfen", style = MaterialTheme.typography.labelMedium, color = TextMuted)
            }
        }
    }
}

@Composable
private fun StatsRow(snapshot: Snapshot) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        StatTile(
            Modifier.weight(1f),
            "Nikotin",
            "%.1f".format(snapshot.nicotineNgMl),
            // The slope, not the unit: what a pouch feels like tracks the rate of
            // change, because nicotinic receptors desensitise under a steady level.
            "%+.2f/min".format(snapshot.nicotineRatePerMin),
            Accent,
        )
        StatTile(Modifier.weight(1f), "Cotinin", "%.0f".format(snapshot.cotinineNgMl), "ng/mL", Cotinine)
        StatTile(
            Modifier.weight(1f),
            "Heute",
            snapshot.todayCount.toString(),
            "%.1f mg".format(snapshot.todayMg),
            TextPrimary,
        )
    }
}

@Composable
private fun StatTile(
    modifier: Modifier,
    label: String,
    value: String,
    unit: String,
    accent: Color,
) {
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ProductTile(
    product: Product,
    enabled: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
) {
    val accent = product.accent?.let { parseHex(it) } ?: Accent
    val alpha = if (enabled) 1f else 0.4f

    Column(
        Modifier
            .fillMaxWidth()
            .height(112.dp)
            .clip(RectangleShape)
            .background(MaterialTheme.colorScheme.surface.copy(alpha = alpha))
            .border(1.dp, accent.copy(alpha = 0.35f * alpha), RectangleShape)
            // Long-press tunes how long this variety releases. Hidden on purpose: it
            // is a calibration knob, not something to reach for every day.
            .combinedClickable(
                enabled = enabled,
                onClick = onClick,
                onLongClick = onLongClick,
            )
            .padding(16.dp),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        Box(
            Modifier
                .size(width = 28.dp, height = 4.dp)
                .clip(RectangleShape)
                .background(accent.copy(alpha = alpha))
        )
        Column {
            Text(
                product.name,
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary.copy(alpha = alpha),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "%.1f mg".format(product.nominalMg),
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted.copy(alpha = alpha),
            )
        }
    }
}

/**
 * No valid lease and no server: the records cannot be read, so there is nothing honest
 * to show. Without this the screen looked merely empty, which reads as "no data" rather
 * than "locked out" -- and the Linux client already says so.
 */
@Composable
private fun LockedBanner() {
    Column(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, Bad, RectangleShape)
            .padding(16.dp)
    ) {
        Text("Gesperrt", style = MaterialTheme.typography.titleMedium, color = Bad)
        Spacer(Modifier.height(4.dp))
        Text(
            "Kein gültiges Lease und der Server ist nicht erreichbar. Sobald die " +
                "Verbindung steht, entsperrt sich die App von selbst.",
            style = MaterialTheme.typography.bodySmall,
            color = TextBody,
        )
    }
}

@Composable
private fun EmptyProducts() {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RectangleShape)
            .background(MaterialTheme.colorScheme.surface)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Noch keine Sorten", style = MaterialTheme.typography.titleMedium, color = TextPrimary)
        Spacer(Modifier.height(6.dp))
        Text(
            "Über den Knopf unten rechts anlegen. Neue Sorten erscheinen auf allen Geräten.",
            style = MaterialTheme.typography.bodyMedium,
            color = TextMuted,
        )
    }
}

@Composable
private fun ConnectionDot(online: Boolean, pending: Long) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(end = 4.dp)) {
        if (pending > 0) {
            Text(
                "$pending offen",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
                modifier = Modifier.padding(end = 6.dp),
            )
        }
        Box(
            Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(if (online) Good else TextMuted)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddProductSheet(onDismiss: () -> Unit, onConfirm: (String, Double) -> Unit) {
    var name by remember { mutableStateOf("") }
    var mg by remember { mutableStateOf("") }

    // Accept a comma: that is how the number is printed on the tin here.
    val parsedMg = mg.replace(',', '.').toDoubleOrNull()
    val valid = name.isNotBlank() && parsedMg != null && parsedMg > 0

    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = MaterialTheme.colorScheme.surface) {
        Column(Modifier.padding(horizontal = 24.dp).padding(bottom = 32.dp)) {
            Text("Sorte anlegen", style = MaterialTheme.typography.headlineSmall, color = TextPrimary)
            Spacer(Modifier.height(6.dp))
            Text(
                "Erscheint auf allen angemeldeten Geräten.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextMuted,
            )
            Spacer(Modifier.height(20.dp))

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name") },
                placeholder = { Text("CUBA PEACH") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = mg,
                onValueChange = { mg = it },
                label = { Text("Nikotin pro Pouch (mg)") },
                placeholder = { Text("10,4") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = { onConfirm(name.trim(), parsedMg ?: 0.0) },
                enabled = valid,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RectangleShape,
            ) {
                Text("Anlegen")
            }
        }
    }
}

/** "8 min", "1:05 h" -- short enough to read at a glance on a lock screen. */
private fun formatElapsed(seconds: Long): String {
    val minutes = seconds / 60
    return when {
        minutes < 1 -> "gerade eben"
        minutes < 60 -> "$minutes min"
        else -> "%d:%02d h".format(minutes / 60, minutes % 60)
    }
}

private fun parseHex(hex: String): Color? = runCatching {
    Color(android.graphics.Color.parseColor(if (hex.startsWith("#")) hex else "#$hex"))
}.getOrNull()
