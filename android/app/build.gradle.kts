plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.bibavpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.bibavpn"
        minSdk = 29
        targetSdk = 34
        versionCode = 2
        versionName = "0.2.0"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation("com.ooimi.library:tun2socks:1.0.4")
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-service:2.7.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

// Native: cargo-ndk from https://github.com/bbqsrc/cargo-ndk
//   cargo install cargo-ndk
//   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
// From repo root `biba-vpn/`:
//   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 -o android/app/src/main/jniLibs build -p bibavpn-jni --release
