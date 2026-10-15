plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "de.liforra.snustracker"
    compileSdk = 35

    defaultConfig {
        applicationId = "de.liforra.snustracker"
        minSdk = 26          // Android 8: the floor for the Keystore guarantees we rely on
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            // The only target that matters here; add others when there is a device.
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    // The Rust library is built by `cargo ndk` into this tree; see README.md.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // Bringt eine fertige Scanner-Activity mit. Der Alternativweg ueber CameraX
    // plus ML Kit waere deutlich groesser und laedt Modelle nach -- fuer einen
    // QR-Code, den wir selbst erzeugt haben, ist das nicht zu rechtfertigen.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
