"""Synchronisation Wi-Fi avec l'appli Android CoffreFort (consultation seule).

- Le téléphone garde une copie du fichier du coffre, chiffrée exactement comme sur le PC :
  il faut le mot de passe maître pour l'ouvrir. Rien ne circule en clair.
- Association : échange de clés ECDH P-256 ; le PC et le téléphone affichent le même code
  à 6 chiffres, que l'utilisateur compare (un intermédiaire sur le réseau ne peut pas l'imiter).
- Ensuite chaque demande est signée (HMAC-SHA256) avec le secret de l'association et datée :
  un autre appareil du réseau ne peut ni récupérer le fichier ni rejouer une demande.
- Les secrets sont rangés dans les réglages, chiffrés par Windows (DPAPI) pour ce compte.
- Le serveur ne lit que le fichier du coffre sur le disque : il marche même coffre verrouillé.

Protocole (TCP) : une ligne JSON de demande, une ligne JSON de réponse, puis `size` octets bruts.
Découverte (UDP, même port) : le téléphone diffuse « COFFREFORT? », le PC répond son nom et son port.
"""

import base64
import hashlib
import hmac
import json
import os
import queue
import secrets
import socket
import socketserver
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import winsec

HERE = os.path.dirname(os.path.abspath(__file__))
APK_PATH = os.path.join(HERE, "mobile", "CoffreFort.apk")
APK_INFO = os.path.join(HERE, "mobile", "version.json")
DOWNLOAD_QR = os.path.join(HERE, "mobile", "telecharger.png")
APK_URL = "https://github.com/RedRiot1000/CoffreFort/raw/main/mobile/CoffreFort.apk"
PORTS = range(47321, 47331)  # le premier libre ; le téléphone le retrouve par la découverte
DISCOVER = b"COFFREFORT?"
MAX_SKEW = 600       # s d'écart d'horloge toléré entre le PC et le téléphone
PAIR_SECONDS = 180   # durée du mode association
CONFIRM_SECONDS = 120
MAX_LINE = 16384


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def mac(secret: bytes, *parts) -> str:
    return hmac.new(secret, "|".join(str(p) for p in parts).encode("utf-8"), hashlib.sha256).hexdigest()


def pair_material(shared: bytes, phone_pub: bytes, pc_pub: bytes):
    """Secret de l'association + code à 6 chiffres affiché des deux côtés."""
    km = HKDF(hashes.SHA256(), 36, phone_pub + pc_pub, b"coffrefort-pair").derive(shared)
    code = int.from_bytes(km[32:], "big") % 1_000_000
    return km[:32], f"{code // 1000:03d} {code % 1000:03d}"


def pc_name() -> str:
    return os.environ.get("COMPUTERNAME") or socket.gethostname()


def local_addresses() -> list[str]:
    """Adresses IPv4 de ce PC sur le réseau local (pour la saisie manuelle sur le téléphone)."""
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # aucune donnée envoyée : sert seulement à choisir l'interface
        found.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.append(info[4][0])
    except OSError:
        pass
    out = []
    for a in found:
        if a not in out and not a.startswith(("127.", "169.254.")):
            out.append(a)
    return out


def apk_info() -> dict | None:
    try:
        with open(APK_INFO, encoding="utf-8") as f:
            info = json.load(f)
        return info if os.path.isfile(APK_PATH) else None
    except (OSError, ValueError):
        return None


def file_sha256(path: str) -> tuple[bytes, str]:
    with open(path, "rb") as f:
        data = f.read()
    return data, hashlib.sha256(data).hexdigest()


class _Handler(socketserver.StreamRequestHandler):
    timeout = CONFIRM_SECONDS + 30

    def handle(self):
        try:
            line = self.rfile.readline(MAX_LINE)
            req = json.loads(line.decode("utf-8"))
            if not isinstance(req, dict):
                return
            for reply, data in self.server.owner.handle(req, self.client_address[0]):
                self.wfile.write(json.dumps(reply).encode("utf-8") + b"\n")
                if data:
                    self.wfile.write(data)
                self.wfile.flush()
        except (OSError, ValueError, UnicodeDecodeError):
            pass


class _TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


class MobileServer:
    """Serveur de synchro. Les événements pour l'interface arrivent dans `events` :
    ("pair", infos, boîte) — demander confirmation du code, puis boîte["accept"] et boîte["done"].set() ;
    ("synced", phone_id, horodatage) — un téléphone vient de se synchroniser."""

    def __init__(self, vault_path: str, pc_id: str):
        self.vault_path = vault_path
        self.pc_id = pc_id
        self.phones: dict[str, dict] = {}  # id -> {"name", "secret" (octets)}
        self.events: queue.Queue = queue.Queue()
        self.pairing_until = 0.0
        self.port = None
        self._seen: dict[str, float] = {}
        self._pair_busy = False
        self._lock = threading.Lock()
        self._tcp = self._udp = None

    # ---------- démarrage ----------
    def start(self):
        last = None
        for port in PORTS:
            try:
                tcp = _TCP(("0.0.0.0", port), _Handler)
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    udp.bind(("0.0.0.0", port))
                except OSError:
                    tcp.server_close()
                    raise
                break
            except OSError as ex:
                last = ex
        else:
            raise last or OSError("aucun port libre")
        tcp.owner = self
        self._tcp, self._udp, self.port = tcp, udp, port
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        threading.Thread(target=self._discovery, daemon=True).start()

    def close(self):
        if self._tcp:
            self._tcp.shutdown()
            self._tcp.server_close()
            self._tcp = None
        if self._udp:
            self._udp.close()
            self._udp = None

    def set_phones(self, phones: list[dict]):
        with self._lock:
            self.phones = {p["id"]: {"name": p["name"], "secret": p["secret"]} for p in phones}

    def start_pairing(self):
        self.pairing_until = time.time() + PAIR_SECONDS

    def stop_pairing(self):
        self.pairing_until = 0.0

    @property
    def pairing(self) -> bool:
        return time.time() < self.pairing_until

    def _discovery(self):
        udp = self._udp
        while self._udp is udp:
            try:
                data, addr = udp.recvfrom(512)
            except OSError:
                return
            if data.startswith(DISCOVER):
                reply = {"coffrefort": 1, "pc": self.pc_id, "name": pc_name(), "port": self.port,
                         "pairing": self.pairing}
                try:
                    udp.sendto(json.dumps(reply).encode("utf-8"), addr)
                except OSError:
                    pass

    # ---------- demandes ----------
    def handle(self, req: dict, addr: str):
        kind = req.get("type")
        if kind == "pair":
            yield from self._pair(req, addr)
            return
        if kind == "hello":  # saisie manuelle de l'adresse : le téléphone vérifie qu'il parle à CoffreFort
            yield {"coffrefort": 1, "pc": self.pc_id, "name": pc_name(), "port": self.port, "pairing": self.pairing}, None
            return
        phone, secret, err = self._authenticate(req, kind)
        if err:
            yield {"error": err}, None
            return
        nonce = req["nonce"]
        if kind == "sync":
            try:
                blob, sha = file_sha256(self.vault_path)
            except OSError:
                yield {"error": "no_vault"}, None
                return
            info = apk_info() or {}
            send = sha != req.get("have")
            reply = {"ok": True, "sha": sha, "size": len(blob) if send else 0, "pc_name": pc_name(),
                     "apk": int(info.get("version_code", 0)), "apk_name": str(info.get("version_name", "")),
                     "apk_sha": str(info.get("sha256", ""))}
            reply["mac"] = mac(secret, "vault", nonce, sha, reply["size"], reply["apk"], reply["apk_sha"])
            self.events.put(("synced", phone, time.time()))
            yield reply, blob if send else None
            return
        if kind == "apk":
            info = apk_info()
            if not info:
                yield {"error": "no_apk"}, None
                return
            data, sha = file_sha256(APK_PATH)
            reply = {"ok": True, "size": len(data), "sha": sha}
            reply["mac"] = mac(secret, "apkdata", nonce, sha, len(data))
            yield reply, data
            return
        yield {"error": "unknown"}, None

    def _authenticate(self, req, kind):
        if req.get("pc") not in (None, self.pc_id):
            return None, None, "other_pc"  # téléphone associé à un autre PC qui a eu cette adresse
        phone, nonce, ts = req.get("phone"), req.get("nonce"), req.get("ts")
        with self._lock:
            entry = self.phones.get(phone) if isinstance(phone, str) else None
        if entry is None:
            return None, None, "unknown_phone"
        if not isinstance(nonce, str) or not 16 <= len(nonce) <= 64 or not isinstance(ts, int):
            return None, None, "bad_request"
        secret = entry["secret"]
        fields = [kind, phone, ts, nonce] + ([req.get("have", ""), req.get("app", 0)] if kind == "sync" else [])
        if not hmac.compare_digest(mac(secret, *fields), str(req.get("mac", ""))):
            return None, None, "bad_mac"
        now = time.time()
        if abs(now - ts) > MAX_SKEW:
            return None, None, "clock"
        with self._lock:
            self._seen = {n: t for n, t in self._seen.items() if now - t < 2 * MAX_SKEW}
            if nonce in self._seen:
                return None, None, "replay"
            self._seen[nonce] = now
        return phone, secret, None

    def _pair(self, req, addr):
        if not self.pairing:
            yield {"error": "not_pairing"}, None
            return
        # Une seule demande à la fois : un autre appareil du Wi-Fi ne peut pas glisser sa fenêtre
        # de confirmation à côté de celle du vrai téléphone.
        with self._lock:
            if self._pair_busy:
                busy = True
            else:
                busy, self._pair_busy = False, True
        if busy:
            yield {"error": "busy"}, None
            return
        try:
            yield from self._pair_one(req, addr)
        finally:
            with self._lock:
                self._pair_busy = False

    def _pair_one(self, req, addr):
        try:
            phone_pub = _b64d(req["pub"])
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), phone_pub)
        except (KeyError, ValueError, TypeError):
            yield {"error": "bad_request"}, None
            return
        name = str(req.get("name") or "Téléphone")[:60]
        key = ec.generate_private_key(ec.SECP256R1())
        pc_pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        secret, code = pair_material(key.exchange(ec.ECDH(), peer), phone_pub, pc_pub)
        yield {"pub": _b64e(pc_pub), "pc": self.pc_id, "name": pc_name(), "port": self.port}, None

        box = {"accept": False, "done": threading.Event()}
        phone_id = secrets.token_hex(8)
        self.events.put(("pair", {"name": name, "code": code, "address": addr, "id": phone_id, "secret": secret}, box))
        if not box["done"].wait(CONFIRM_SECONDS) or not box["accept"]:
            yield {"error": "denied"}, None
            return
        with self._lock:
            self.phones[phone_id] = {"name": name, "secret": secret}
        self.stop_pairing()
        yield {"ok": True, "phone": phone_id, "mac": mac(secret, "paired", phone_id)}, None


# ---------- stockage dans les réglages ----------
def load_phones(settings: dict) -> list[dict]:
    """Téléphones associés, secrets déchiffrés (illisibles sur un autre PC ou compte Windows)."""
    out = []
    for p in settings.get("mobile_phones", []):
        try:
            out.append(dict(p, secret=winsec.unprotect_data(_b64d(p["secret"]))))
        except (OSError, KeyError, ValueError):
            pass
    return out


def store_phone(settings: dict, phone_id: str, name: str, secret: bytes):
    phones = [p for p in settings.get("mobile_phones", []) if p.get("id") != phone_id]
    phones.append({"id": phone_id, "name": name, "secret": _b64e(winsec.protect_data(secret)),
                   "added": time.time(), "last_sync": 0})
    settings["mobile_phones"] = phones


def pc_id(settings: dict) -> str:
    if not settings.get("mobile_pc_id"):
        settings["mobile_pc_id"] = secrets.token_hex(8)
    return settings["mobile_pc_id"]
