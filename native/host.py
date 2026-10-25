"""Hôte natif lancé par le navigateur : relaie un message de l'extension vers
l'app CoffreFort (tube nommé) et renvoie la réponse. Ne lit jamais le coffre lui-même."""

import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from multiprocessing.connection import Client  # noqa: E402

from bridge import PIPE, ipc_key, recv, send  # noqa: E402


def read_message():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    (length,) = struct.unpack("<I", raw)
    return json.loads(sys.stdin.buffer.read(length).decode("utf-8"))


def write_message(obj):
    data = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)) + data)
    sys.stdout.buffer.flush()


def launch_app():
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([pythonw, os.path.join(ROOT, "app.pyw")], cwd=ROOT, creationflags=flags, close_fds=True)


def main():
    msg = read_message()
    if not isinstance(msg, dict):
        return
    if msg.get("type") == "launch":
        launch_app()
        write_message({"ok": True})
        return
    try:
        conn = Client(PIPE, family="AF_PIPE", authkey=ipc_key())
    except FileNotFoundError:
        write_message({"error": "not_running"})
        return
    except Exception as ex:  # noqa: BLE001
        write_message({"error": "bridge", "message": str(ex)})
        return
    try:
        send(conn, msg)
        write_message(recv(conn))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
