package de.liforra.snustracker

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import de.liforra.snustracker.ui.HomeScreen
import de.liforra.snustracker.ui.SetupScreen
import de.liforra.snustracker.ui.StatsScreen
import de.liforra.snustracker.ui.SnusTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Asked for once, at launch. The alarm that tells you a pouch is spent is
        // useless without it, and asking later -- at the moment the pouch runs out --
        // would interrupt exactly the thing it is trying to report.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            registerForActivityResult(ActivityResultContracts.RequestPermission()) {}
                .launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        val repository = TrackerRepository(this)

        setContent {
            SnusTheme {
                Surface(
                    Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    App(repository)
                }
            }
        }
    }
}

private sealed interface Screen {
    data object Loading : Screen
    data object Setup : Screen
    data object Home : Screen
    data object Stats : Screen
}

@Composable
private fun App(repository: TrackerRepository) {
    val scope = rememberCoroutineScope()
    var screen by remember { mutableStateOf<Screen>(Screen.Loading) }
    var snapshot by remember { mutableStateOf(Snapshot()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var curves by remember { mutableStateOf<Curves?>(null) }
    var invite by remember { mutableStateOf<Invite?>(null) }
    val context = LocalContext.current

    fun apply(result: NativeResult<Snapshot>) {
        when (result) {
            is NativeResult.Ok -> {
                snapshot = result.value
                message = null
                // Book or drop the "pouch is spent" alarm from the same snapshot the UI
                // draws, so the two can never disagree about the state of the pouch.
                val open = result.value.openSession
                val left = open?.releaseLeftSecs
                if (open != null && !open.paused && left != null && left > 0) {
                    SpentReceiver.schedule(context, open.productName, left)
                } else {
                    SpentReceiver.cancel(context)
                }
            }
            is NativeResult.Err -> {
                // The one error worth acting on rather than showing: the account has
                // cut this device off, so there is nothing left to display.
                if (result.message.contains("revoked")) {
                    repository.wipe()
                    screen = Screen.Setup
                    message = "Dieses Gerät wurde gesperrt. Lokale Daten sind gelöscht."
                } else {
                    message = result.message
                }
            }
        }
    }

    // Open once on first composition, and refresh whenever the app comes back to the
    // foreground so the home screen is never showing a stale session.
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(Unit) {
        if (!repository.isEnrolled) {
            screen = Screen.Setup
            return@LaunchedEffect
        }
        apply(repository.open())
        screen = Screen.Home

        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                apply(repository.snapshot())
                // The level curve moves on its own; a minute is often enough to matter.
                delay(60_000)
            }
        }
    }

    when (screen) {
        Screen.Loading -> Box(Modifier.fillMaxSize(), Alignment.Center) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        }

        Screen.Setup -> SetupScreen(
            busy = busy,
            error = message,
            onEnroll = { url, key, code, name ->
                scope.launch {
                    busy = true
                    when (val result = repository.enroll(url, key, code, name)) {
                        is NativeResult.Err -> message = result.message
                        is NativeResult.Ok -> {
                            apply(repository.open())
                            screen = Screen.Home
                        }
                    }
                    busy = false
                }
            },
        )

        Screen.Home -> HomeScreen(
            snapshot = snapshot,
            busy = busy,
            message = message,
            onStart = { product ->
                scope.launch {
                    busy = true
                    apply(repository.startSession(product.id))
                    busy = false
                }
            },
            onEnd = { session ->
                scope.launch {
                    busy = true
                    apply(repository.endSession(session.sessionId))
                    busy = false
                }
            },
            onPauseToggle = { session ->
                scope.launch {
                    busy = true
                    apply(
                        if (session.paused) repository.resumeSession(session.sessionId)
                        else repository.pauseSession(session.sessionId)
                    )
                    busy = false
                }
            },
            onDiscard = { session ->
                scope.launch {
                    busy = true
                    apply(repository.discardSession(session.sessionId))
                    busy = false
                }
            },
            onSetDuration = { product, minutes ->
                scope.launch {
                    busy = true
                    apply(repository.setProductDuration(product.id, minutes))
                    busy = false
                }
            },
            onRetire = { product ->
                scope.launch {
                    busy = true
                    apply(repository.retireProduct(product.id))
                    busy = false
                }
            },
            onSetBodyMass = { kg ->
                scope.launch {
                    busy = true
                    apply(repository.updateSubject(kg, null))
                    busy = false
                }
            },
            onApproveDevices = {
                scope.launch {
                    busy = true
                    val result = repository.approveDevices()
                    apply(result)
                    busy = false
                    // Only claim success on success: this used to overwrite the error
                    // apply() had just shown with a cheerful message.
                    if (result is NativeResult.Ok) {
                        message = "Neue Geräte freigeschaltet — sie können jetzt lesen."
                    }
                }
            },
            invite = invite,
            onInviteDevice = {
                scope.launch {
                    busy = true
                    when (val result = repository.createInvite()) {
                        is NativeResult.Ok -> invite = result.value
                        is NativeResult.Err -> message = result.message
                    }
                    busy = false
                }
            },
            onDismissInvite = { invite = null },
            onOpenStats = {
                scope.launch {
                    val now = System.currentTimeMillis() / 1000
                    when (val result = repository.samples(now - 24 * 3600, now, 180)) {
                        is NativeResult.Ok -> curves = result.value
                        is NativeResult.Err -> message = result.message
                    }
                    screen = Screen.Stats
                }
            },
            onAddProduct = { name, mg ->
                scope.launch {
                    busy = true
                    apply(repository.addProduct(name, mg, null))
                    busy = false
                }
            },
            onSync = {
                scope.launch {
                    busy = true
                    apply(repository.sync())
                    busy = false
                }
            },
            onDismissMessage = { message = null },
        )

        Screen.Stats -> StatsScreen(
            snapshot = snapshot,
            curves = curves,
            onBack = { screen = Screen.Home },
        )
    }
}
