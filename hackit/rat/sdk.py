"""Android SDK discovery plus a one-command bootstrap.

Discovery is deterministic and explicit: env vars first, then a remembered
path, then the handful of conventional install locations. When nothing is
found ``ensure()`` downloads the official command-line tools, accepts the
licences non-interactively and installs the exact platform/build-tools the
builder pins. That is the whole point — a fresh machine reaches a working
toolchain without the operator assembling it by hand.

Bootstrap writes only under the SDK root it chose. The zip is unpacked into a
scratch directory first, then moved into place, so an interrupted download
never leaves a half-written ``cmdline-tools`` that discovery would trust.
"""
from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from typing import Callable, Iterator, Optional

DEFAULT_ROOT = os.environ.get("HACKIT_ANDROID_SDK") or os.path.join(os.path.expanduser("~"), "Android", "Sdk")
PLATFORM_PACKAGE = "platforms;android-35"
BUILD_TOOLS_PACKAGE = "build-tools;35.0.0"
NDK_PACKAGE = "ndk;27.2.12479018"

# Google publishes a stable "latest" command-line tools archive per host.
CMD_TOOLS = {
    "linux": "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip",
    "darwin": "https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip",
    "win32": "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip",
}
MIN_ARCHIVE_BYTES = 40 * 1024 * 1024


class SdkError(Exception):
    """No SDK and bootstrap could not produce one."""


def _state_dir() -> str:
    return os.environ.get("HACKIT_RAT_HOME") or os.path.join(os.path.expanduser("~"), ".hackit", "rat")


def _remember_path() -> str:
    return os.path.join(_state_dir(), "sdk_path")


def remember(path: str) -> None:
    try:
        os.makedirs(_state_dir(), exist_ok=True)
        with open(_remember_path(), "w", encoding="utf-8") as handle:
            handle.write(os.path.abspath(path) + "\n")
    except OSError:
        pass


def remembered() -> Optional[str]:
    try:
        with open(_remember_path(), "r", encoding="utf-8") as handle:
            path = handle.read().strip()
    except OSError:
        return None
    return path if path and os.path.isdir(path) else None


def is_sdk(path: Optional[str]) -> bool:
    """A directory only counts once it can actually satisfy a build."""
    if not path or not os.path.isdir(path):
        return False
    have_platform = any(
        os.path.isfile(os.path.join(path, "platforms", name, "android.jar"))
        for name in _listing(os.path.join(path, "platforms"))
    )
    return bool(have_platform)


def _listing(folder: str) -> list[str]:
    try:
        return sorted(os.listdir(folder))
    except OSError:
        return []


def candidates() -> Iterator[str]:
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "HACKIT_ANDROID_SDK"):
        value = os.environ.get(key)
        if value:
            yield value
    remembered_path = remembered()
    if remembered_path:
        yield remembered_path
    home = os.path.expanduser("~")
    for guess in (
        os.path.join(home, "Android", "Sdk"),
        os.path.join(home, "android-sdk"),
        os.path.join(home, ".android", "sdk"),
        "/tmp/opencode/sdk",
        "/opt/android-sdk",
        "/usr/lib/android-sdk",
        "/usr/local/lib/android/sdk",
    ):
        yield guess


def find() -> Optional[str]:
    seen: set[str] = set()
    for path in candidates():
        real = os.path.abspath(os.path.expanduser(path))
        if real in seen:
            continue
        seen.add(real)
        if is_sdk(real):
            return real
    return None


def java_bin(name: str = "java") -> Optional[str]:
    """A JDK from PATH or a conventional JAVA_HOME, never a hard requirement."""
    found = shutil.which(name)
    if found:
        return found
    roots = [os.environ.get("JAVA_HOME", "")]
    roots += [
        "/usr/lib/jvm/default-java",
        "/usr/lib/jvm/java-21-openjdk-amd64",
        "/usr/lib/jvm/java-17-openjdk-amd64",
        "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
    ]
    for root in roots:
        if not root:
            continue
        candidate = os.path.join(root, "bin", name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _progress_printer(label: str) -> Callable[[int, Optional[int]], None]:
    state = {"last": 0.0}

    def report(done: int, total: Optional[int]) -> None:
        now = time.time()
        if now - state["last"] < 0.15 and total and done < total:
            return
        state["last"] = now
        if total:
            pct = min(100, int(done * 100 / total))
            sys.stdout.write(f"\r  {label}  {pct:3d}%  {done / 1_048_576:6.1f} MiB")
        else:
            sys.stdout.write(f"\r  {label}  {done / 1_048_576:6.1f} MiB")
        sys.stdout.flush()

    return report


def _download(url: str, target: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "hackit-rat-setup"})
    report = _progress_printer("download")
    try:
        with urllib.request.urlopen(request, timeout=60) as response, open(target, "wb") as handle:
            total_header = response.headers.get("Content-Length")
            total = int(total_header) if total_header and total_header.isdigit() else None
            done = 0
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                done += len(chunk)
                report(done, total)
    finally:
        sys.stdout.write("\n")
        sys.stdout.flush()
    if os.path.getsize(target) < MIN_ARCHIVE_BYTES:
        raise SdkError(f"command-line tools archive too small ({os.path.getsize(target)} bytes)")


def _unzip(archive: str, target: str) -> None:
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = member.filename
            if name.startswith("/") or ".." in name.split("/"):
                continue
            bundle.extract(member, target)


def _sdkmanager(root: str) -> str:
    name = "sdkmanager.bat" if os.name == "nt" else "sdkmanager"
    for folder in ("latest", "cmdline-tools", ""):
        candidate = os.path.join(root, "cmdline-tools", folder, "bin", name) if folder else os.path.join(root, "bin", name)
        if os.path.isfile(candidate):
            return candidate
    raise SdkError("sdkmanager missing after unpack — archive layout changed")


def _sdk_env(root: str) -> dict:
    env = dict(os.environ)
    env["ANDROID_HOME"] = root
    env["ANDROID_SDK_ROOT"] = root
    java_home = os.environ.get("JAVA_HOME")
    java = java_bin("java")
    if not java_home and java:
        env["JAVA_HOME"] = os.path.dirname(os.path.dirname(java))
    return env


def _run_checked(cmd: list[str], root: str, label: str, stdin: Optional[str] = None) -> None:
    proc = subprocess.run(
        cmd, env=_sdk_env(root), input=stdin,
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-12:]
        raise SdkError(f"{label} failed ({proc.returncode}): " + " | ".join(tail))


def install(
    destination: Optional[str] = None,
    with_ndk: bool = True,
    echo: Callable[[str], None] = print,
) -> str:
    """Download and install an SDK. Returns its root; raises SdkError on doubt."""
    if os.name not in ("posix", "nt"):
        raise SdkError(f"unsupported host {os.name}")
    key = "win32" if os.name == "nt" else ("darwin" if platform.system() == "Darwin" else "linux")
    url = CMD_TOOLS.get(key)
    if not url:
        raise SdkError(f"no command-line tools archive for {platform.system()}")
    if not java_bin("java") or not java_bin("javac"):
        raise SdkError("JDK not found — install OpenJDK 17 first (apt/brew install openjdk@17)")

    root = os.path.abspath(os.path.expanduser(destination or DEFAULT_ROOT))
    os.makedirs(root, exist_ok=True)
    echo(f"  sdk root    {root}")
    echo(f"  archive     {url}")

    with tempfile.TemporaryDirectory(prefix="hackit-sdk-") as scratch:
        archive = os.path.join(scratch, "cmdline-tools.zip")
        _download(url, archive)
        _unzip(archive, scratch)
        unpacked = os.path.join(scratch, "cmdline-tools")
        if not os.path.isdir(unpacked):
            # Newer archives nest one level deeper.
            for entry in _listing(scratch):
                candidate = os.path.join(scratch, entry, "cmdline-tools")
                if os.path.isdir(candidate):
                    unpacked = candidate
                    break
        if not os.path.isdir(unpacked):
            raise SdkError("archive did not contain cmdline-tools")

        tools_root = os.path.join(root, "cmdline-tools")
        os.makedirs(tools_root, exist_ok=True)
        target = os.path.join(tools_root, "latest")
        if os.path.isdir(target):
            shutil.rmtree(target)
        shutil.move(unpacked, target)
        for folder, _dirs, names in os.walk(target):
            for name in names:
                path = os.path.join(folder, name)
                try:
                    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
                except OSError:
                    pass

    manager = _sdkmanager(root)
    echo("  licences    accepting")
    _run_checked([manager, "--sdk_root=" + root, "--licenses"], root, "sdkmanager --licenses",
                 stdin=("y\n" * 64))
    packages = ["platform-tools", PLATFORM_PACKAGE, BUILD_TOOLS_PACKAGE]
    if with_ndk:
        packages.append(NDK_PACKAGE)
    echo("  packages    " + "  ".join(packages))
    _run_checked([manager, "--sdk_root=" + root, *packages], root, "sdkmanager install")

    if not is_sdk(root):
        raise SdkError(f"bootstrap finished but {root} still has no platform android.jar")
    remember(root)
    os.environ["ANDROID_HOME"] = root
    os.environ["ANDROID_SDK_ROOT"] = root
    echo(f"  done        {root}")
    return root


def ensure(destination: Optional[str] = None, with_ndk: bool = True,
           echo: Callable[[str], None] = print) -> str:
    """Return a usable SDK, installing one only when discovery comes up empty."""
    found = find()
    if found:
        os.environ.setdefault("ANDROID_HOME", found)
        os.environ.setdefault("ANDROID_SDK_ROOT", found)
        return found
    return install(destination, with_ndk=with_ndk, echo=echo)
