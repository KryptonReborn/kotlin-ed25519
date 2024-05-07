# KOTLIN ed25519

[![GitHub release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/KryptonReborn/kotlin-ed25519/releases/tag/v0.1.0) [![Kotlin Version](https://img.shields.io/badge/Kotlin-1.9.23-B125EA?logo=kotlin)](https://kotlinlang.org)
[![Build Status](https://github.com/saschpe/kase64/workflows/Main/badge.svg)](https://github.com/KryptonReborn/kotlin-ed25519/actions)
[![License](http://img.shields.io/:License-Apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

![badge-android](http://img.shields.io/badge/Platform-Android-brightgreen.svg?logo=android)
![badge-ios](http://img.shields.io/badge/Platform-iOS-orange.svg?logo=apple)
![badge-js](http://img.shields.io/badge/Platform-NodeJS-yellow.svg?logo=javascript)
![badge-jvm](http://img.shields.io/badge/Platform-JVM-red.svg?logo=openjdk)
![badge-linux](http://img.shields.io/badge/Platform-Linux-lightgrey.svg?logo=linux)
![badge-macos](http://img.shields.io/badge/Platform-macOS-orange.svg?logo=apple)
![badge-windows](http://img.shields.io/badge/Platform-Windows-blue.svg?logo=windows)

[//]: # (![badge-tvos]&#40;http://img.shields.io/badge/Platform-tvOS-orange.svg?logo=apple&#41;)

[//]: # (![badge-watchos]&#40;http://img.shields.io/badge/Platform-watchOS-orange.svg?logo=apple&#41;)

Kotlin implementation of group operations on Curve25519.

## Download

You must use a personal access token (classic) with the appropriate scopes to publish and install
packages
in [GitHub Packages](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages#authenticating-to-github-packages).

Add the following repository to your settings.gradle.kts file

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/KryptonReborn/kotlin-ed25519")
        credentials {
            username = "user name"
            password = "personal access token"
        }
    }
}
```

Add the following dependency to your build.gradle.kts file

```build.gradle.kts
dependencies {
    implementation("dev.kryptonreborn.ed25519:ed25519:[version]")
}
```

## Acknowledgements

This library is inspired
by [subtle](https://github.com/cashapp/zipline/tree/trunk/zipline-loader/src/commonMain/kotlin/app/cash/zipline/loader/internal/tink/subtle)
by [cashapp](https://github.com/cashapp).