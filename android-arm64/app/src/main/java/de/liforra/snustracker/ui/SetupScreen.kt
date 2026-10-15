package de.liforra.snustracker.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.platform.LocalContext
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import android.content.pm.PackageManager
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * One-time enrollment.
 *
 * The server key is entered by hand rather than fetched, and that is the point: pulling
 * it over the network would prove nothing, since anything sitting in the middle would
 * simply hand over its own. Comparing it against what the server printed is what makes
 * the tunnel worth having.
 */
@Composable
fun SetupScreen(
    busy: Boolean,
    error: String?,
    onEnroll: (serverUrl: String, serverPub: String, code: String, name: String) -> Unit,
) {
    var serverUrl by remember { mutableStateOf("https://") }
    var serverPub by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var name by remember { mutableStateOf(android.os.Build.MODEL ?: "Handy") }

    var scanError by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        // contents == null heisst abgebrochen, nicht fehlgeschlagen -- dann still bleiben.
        result.contents?.let { raw ->
            val parsed = parseEnrollmentUri(raw)
            if (parsed == null) {
                scanError = "Das ist kein Anmelde-Code dieser App."
            } else {
                serverUrl = parsed.url
                serverPub = parsed.key
                code = parsed.code
                scanError = null
            }
        }
    }

    val startScan = {
        scanLauncher.launch(
            ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Code vom anderen Gerät scannen")
                setBeepEnabled(false)
                setOrientationLocked(false)
            }
        )
    }

    val askCamera = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) startScan() else scanError = "Ohne Kamera bleibt nur das Abtippen."
    }

    val ready = serverUrl.length > 8 && serverPub.isNotBlank() && code.isNotBlank() && !busy

    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        Column(
            Modifier
                .padding(padding)
                .padding(24.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
        ) {
            Text("Gerät anmelden", style = MaterialTheme.typography.displaySmall, color = TextPrimary)
            Spacer(Modifier.height(8.dp))
            Text(
                "Den Einladungscode und den Server-Schlüssel gibt `tracker-server bootstrap` aus.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextMuted,
            )
            Spacer(Modifier.height(24.dp))

            // Der schnelle Weg zuerst. Die Felder darunter bleiben sichtbar, damit
            // erkennbar ist, was der Scan eingetragen hat -- und damit ein Handy ohne
            // Kamera oder mit verweigerter Berechtigung nicht in einer Sackgasse steht.
            Button(
                onClick = {
                    val granted = ContextCompat.checkSelfPermission(
                        context, android.Manifest.permission.CAMERA
                    ) == PackageManager.PERMISSION_GRANTED
                    if (granted) startScan() else askCamera.launch(android.Manifest.permission.CAMERA)
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().height(54.dp),
                shape = RectangleShape,
            ) {
                Text("QR-Code scannen")
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "Auf dem Laptop `snus invite` ausführen — oder die Werte unten abtippen.",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
            )
            scanError?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelMedium)
            }

            Spacer(Modifier.height(24.dp))

            OutlinedTextField(
                value = serverUrl,
                onValueChange = { serverUrl = it },
                label = { Text("Server-Adresse") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = serverPub,
                onValueChange = { serverPub = it },
                label = { Text("Server-Schlüssel (base64)") },
                supportingText = {
                    Text(
                        "Muss zum Fingerprint passen, den der Server angezeigt hat.",
                        style = MaterialTheme.typography.labelSmall,
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = code,
                onValueChange = { code = it.uppercase() },
                label = { Text("Einladungscode") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Gerätename") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            error?.let {
                Spacer(Modifier.height(16.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }

            Spacer(Modifier.height(28.dp))
            Button(
                onClick = { onEnroll(serverUrl.trim(), serverPub.trim(), code.trim(), name.trim()) },
                enabled = ready,
                modifier = Modifier.fillMaxWidth().height(54.dp),
                shape = RectangleShape,
            ) {
                if (busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                } else {
                    Text("Anmelden")
                }
            }

            Spacer(Modifier.height(16.dp))
            Text(
                "Ist dies nicht das erste Gerät, muss danach auf einem bereits angemeldeten " +
                    "Gerät „Gerät freischalten“ ausgeführt werden — der Server kann keinen " +
                    "Datenschlüssel herausgeben, den er nicht hat.",
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted,
            )
        }
    }
}

/** Die drei Anmeldewerte, wie sie im QR-Code stehen. */
private data class Enrollment(val url: String, val key: String, val code: String)

/**
 * Liest `snus://enroll?url=…&key=…&code=…`.
 *
 * Streng gegen das eigene Schema geprüft: Ein beliebiger QR-Code aus der Umgebung
 * darf nicht versehentlich eine Serveradresse setzen. Der Nutzen des von Hand
 * verglichenen Schlüssels wäre dahin, wenn ein fremdes Bild ihn überschreiben könnte.
 */
private fun parseEnrollmentUri(raw: String): Enrollment? {
    val uri = runCatching { android.net.Uri.parse(raw.trim()) }.getOrNull() ?: return null
    if (!uri.scheme.equals("snus", ignoreCase = true)) return null
    if (!uri.host.equals("enroll", ignoreCase = true)) return null
    val url = uri.getQueryParameter("url")?.trim().orEmpty()
    val key = uri.getQueryParameter("key")?.trim().orEmpty()
    val code = uri.getQueryParameter("code")?.trim().orEmpty()
    if (url.isEmpty() || key.isEmpty() || code.isEmpty()) return null
    return Enrollment(url, key, code)
}
