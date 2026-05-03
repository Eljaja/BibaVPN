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
        versionCode = 4
        versionName = "0.3.0"
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
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    // Предпочтительно локальный AAR (16 KB ELF): scripts/build-tun2socks-gomobile.sh
    val tun2socksAar = file("${project.projectDir}/libs/tun2socks.aar")
    if (tun2socksAar.exists()) {
        implementation(files(tun2socksAar))
    } else {
        logger.lifecycle(
            "BibaVPN: нет libs/tun2socks.aar — используется Maven tun2socks (старый libgojni; на устройствах с 16 KB страниц возможны предупреждения и вылеты). Сборка 16 KB: bash scripts/build-tun2socks-gomobile.sh",
        )
        implementation("com.ooimi.library:tun2socks:1.0.4")
    }
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
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
// From repo root:
//   cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 -o apps/android/app/src/main/jniLibs build -p bibavpn-jni --release
