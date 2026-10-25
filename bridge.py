"""Pont entre CoffreFort et l'extension navigateur.

Chaîne : extension --(native messaging)--> native/host.py --(tube nommé Windows)--> app CoffreFort.

Garde-fous :
- le tube est authentifié par une clé locale (challenge HMAC de multiprocessing) ;
- l'app ne répond que si elle est déverrouillée et que l'extension a été associée
  (empreinte du jeton stockée DANS le coffre chiffré, association validée à la main) ;
- un mot de passe n'est renvoyé que pour une entrée dont l'adresse correspond au site
  de l'onglet (protection anti-hameçonnage) ; aucune requête « tout lister ».
"""

import getpass
import hashlib
import json
import os
import queue
import re
import secrets
import threading
from multiprocessing.connection import AuthenticationError, Client, Listener
from urllib.parse import urlsplit

DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "CoffreFort")
IPC_KEY_PATH = os.path.join(DATA_DIR, "ipc.key")
PIPE = r"\\.\pipe\coffrefort-" + hashlib.sha256(getpass.getuser().encode("utf-8")).hexdigest()[:12]


def ipc_key(create: bool = False) -> bytes:
    try:
        with open(IPC_KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) == 32:
            return key
    except FileNotFoundError:
        if not create:
            raise
    os.makedirs(DATA_DIR, exist_ok=True)
    key = secrets.token_bytes(32)
    with open(IPC_KEY_PATH, "wb") as f:
        f.write(key)
    return key


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def pairing_code(token: str) -> str:
    """Code à 6 chiffres affiché des deux côtés pour vérifier l'association."""
    n = int(token_hash(token)[:8], 16) % 1_000_000
    return f"{n // 1000:03d} {n % 1000:03d}"


def _host(url: str) -> str:
    parts = urlsplit(url if "://" in url else "https://" + url)
    host = (parts.hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def page_host(url: str) -> str | None:
    """Hôte d'une page web (http/https uniquement), sans « www. »."""
    if not isinstance(url, str) or urlsplit(url).scheme not in ("http", "https"):
        return None
    return _host(url) or None


# Pages servies par d'autres extensions connues : le navigateur interdit d'y écrire,
# mais on peut proposer les comptes du service pour les copier.
KNOWN_EXTENSIONS = {
    "bigefpfhnfcobdlfbedofhhaibnlghod": {"name": "MEGA", "hosts": ["mega.nz", "mega.io", "mega.co.nz"], "words": ["mega"]},
}


def extension_page(url: str) -> dict | None:
    """Infos du service si `url` est une page d'une extension connue (ex. MEGA), sinon None."""
    if not isinstance(url, str):
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("chrome-extension", "extension"):
        return None
    return KNOWN_EXTENSIONS.get((parts.hostname or "").lower())


def entry_matches_service(entry: dict, service: dict) -> bool:
    if any(entry_matches(entry, h) for h in service["hosts"]):
        return True
    site = entry.get("site", "").lower()
    return any(re.search(rf"\b{re.escape(w)}\b", site) for w in service["words"])


def entry_matches(entry: dict, host: str) -> bool:
    """Vrai si l'URL (ou le nom, s'il ressemble à un domaine) de l'entrée
    correspond au site : même domaine ou sous-domaine de celui-ci."""
    for candidate in (entry.get("url", ""), entry.get("site", "")):
        c = candidate.strip()
        if not c or " " in c or "." not in c:
            continue
        e = _host(c)
        if e and (host == e or host.endswith("." + e)):
            return True
    return False


def send(conn, obj):
    conn.send_bytes(json.dumps(obj).encode("utf-8"))


def recv(conn):
    return json.loads(conn.recv_bytes(1 << 20).decode("utf-8"))


def ping_existing() -> bool:
    """Si une instance de CoffreFort tourne déjà, la ramène au premier plan."""
    try:
        conn = Client(PIPE, family="AF_PIPE", authkey=ipc_key())
        send(conn, {"type": "focus"})
        recv(conn)
        conn.close()
        return True
    except Exception:  # noqa: BLE001
        return False


class BridgeServer:
    """Accepte les connexions sur le tube dans un thread ; les requêtes sont
    traitées par le thread de l'interface via la file `requests`."""

    def __init__(self):
        self.requests: queue.Queue = queue.Queue()
        self._listener = None
        self._closed = False

    def start(self):
        self._listener = Listener(PIPE, family="AF_PIPE", authkey=ipc_key(create=True))
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self):
        self._closed = True
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass

    def _serve(self):
        while not self._closed:
            try:
                conn = self._listener.accept()
            except (AuthenticationError, EOFError):
                continue
            except OSError:
                if self._closed:
                    return
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            req = recv(conn)
            if not isinstance(req, dict):
                return
            box, done = {}, threading.Event()
            self.requests.put((req, box, done))
            done.wait(180)
            send(conn, box.get("reply", {"error": "timeout"}))
        except (EOFError, OSError, ValueError):
            pass
        finally:
            conn.close()
