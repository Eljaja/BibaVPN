#!/usr/bin/env python3
"""Run the Android engine ownership regressions on a host JVM, without Android/ADB."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE = ROOT / "apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/Tun2socksLifecycle.kt"
DRIVER = ROOT / "apps/scripts/tun2socks_lifecycle_driver.kt"
MAIN = "Tun2socks_lifecycle_driverKt"
CACHE = Path(os.environ.get("GRADLE_USER_HOME", Path.home() / ".gradle")) / "caches/modules-2/files-2.1"


def cached_jar(group: str, module: str, version: str = "*") -> Path:
    jars = list((CACHE / group / module).glob(f"{version}/*/{module}-*.jar"))
    if not jars:
        raise RuntimeError(f"Missing cached {module}; install kotlinc or populate the Gradle Kotlin cache")
    return max(jars, key=lambda path: path.stat().st_mtime)


def main() -> None:
    java = shutil.which("java")
    if java is None:
        raise RuntimeError("java is required")
    with tempfile.TemporaryDirectory(prefix="biba-tun2socks-lifecycle-") as work:
        compiler = shutil.which("kotlinc")
        kotlin = shutil.which("kotlin")
        if compiler and kotlin:
            compile_command = [compiler, str(LIFECYCLE), str(DRIVER), "-d", work]
            run_command = [kotlin, "-classpath", work, MAIN]
        else:
            compiler_jar = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable")
            version = compiler_jar.parent.parent.name
            stdlib = cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", version)
            runtime = [
                compiler_jar,
                stdlib,
                cached_jar("org.jetbrains.kotlin", "kotlin-script-runtime", version),
                cached_jar("org.jetbrains.kotlin", "kotlin-reflect", "1.6.10"),
                cached_jar("org.jetbrains.intellij.deps", "trove4j", "1.0.20200330"),
                cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.6.4"),
                cached_jar("org.jetbrains", "annotations"),
            ]
            compile_command = [
                java, "-cp", os.pathsep.join(map(str, runtime)),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
                "-no-stdlib", "-no-reflect", "-classpath", str(stdlib),
                str(LIFECYCLE), str(DRIVER), "-d", work,
            ]
            run_command = [java, "-cp", os.pathsep.join([work, str(stdlib)]), MAIN]
        subprocess.run(compile_command, cwd=ROOT, check=True)
        subprocess.run(run_command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
