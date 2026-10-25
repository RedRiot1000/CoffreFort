"""Cœur cryptographique du coffre-fort.

Principe : les données sont chiffrées avec une clé aléatoire (la « clé de données »).
Cette clé est elle-même enfermée dans deux « serrures » indépendantes :
  - une ouverte par le mot de passe maître,
  - une ouverte par la clé de secours (à noter sur papier).
L'une ou l'autre suffit pour ouvrir le coffre.

Format du fichier (JSON) :
    {
      "format": "coffrefort", "version": 2,
      "slots": {
        "master":   {"kdf": {...}, "nonce", "wrapped"},
        "recovery": {"kdf": {...}, "nonce", "wrapped"}
      },
      "nonce": <b64>, "ciphertext": <b64>
    }

- Clés des serrures dérivées par Argon2id (résistant GPU/ASIC).
- Clé de données et contenu chiffrés en AES-256-GCM (confidentialité + intégrité).
- Les paramètres de chaque serrure sont authentifiés (AAD) : toute modification
  du fichier fait échouer le déchiffrement.
- Nouveau nonce à chaque sauvegarde, écriture atomique + .bak.
"""

import base64
import json
import os
import secrets
import string
import tempfile
import time
import uuid

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "coffrefort"
VERSION = 2

# ~256 Mio de RAM et 10 passes : environ 0,3-1 s par tentative sur un PC récent,
# ce qui rend une attaque par force brute sur le fichier extrêmement coûteuse.
DEFAULT_KDF = {"time_cost": 10, "memory_cost": 256 * 1024, "parallelism": 4}

# Clé de secours : 30 caractères parmi 30 (sans 0/O/1/I/L/U, qu'on confond à la
# lecture) = ~147 bits d'aléa, hors de portée de toute force brute.
RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
RECOVERY_GROUPS, RECOVERY_GROUP_LEN = 6, 5


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_key(secret: str, salt: bytes, kdf: dict) -> bytes:
    return hash_secret_raw(
        secret=secret.encode("utf-8"),
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
        hash_len=32,
        type=Type.ID,
    )


def _aad(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wrap(data_key: bytes, secret: str, name: str) -> dict:
    kdf = dict(DEFAULT_KDF, name="argon2id", salt=_b64e(secrets.token_bytes(16)))
    nonce = secrets.token_bytes(12)
    k = derive_key(secret, _b64d(kdf["salt"]), kdf)
    wrapped = AESGCM(k).encrypt(nonce, data_key, _aad({"slot": name, "kdf": kdf}))
    return {"kdf": kdf, "nonce": _b64e(nonce), "wrapped": _b64e(wrapped)}


def _unwrap(slot: dict, secret: str, name: str) -> bytes:
    kdf = slot["kdf"]
    k = derive_key(secret, _b64d(kdf["salt"]), kdf)
    try:
        return AESGCM(k).decrypt(_b64d(slot["nonce"]), _b64d(slot["wrapped"]), _aad({"slot": name, "kdf": kdf}))
    except InvalidTag:
        raise WrongPassword("Mot de passe incorrect ou fichier altéré.")


def generate_recovery_key() -> str:
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_GROUPS * RECOVERY_GROUP_LEN))
    return "-".join(raw[i:i + RECOVERY_GROUP_LEN] for i in range(0, len(raw), RECOVERY_GROUP_LEN))


def normalize_recovery_key(text: str) -> str:
    """Tolère minuscules, espaces et tirets oubliés ou en trop."""
    raw = "".join(c for c in text.upper() if c.isalnum())
    return "-".join(raw[i:i + RECOVERY_GROUP_LEN] for i in range(0, len(raw), RECOVERY_GROUP_LEN))


DEFAULT_CATEGORIES = ["Jeux", "Réseaux sociaux", "Mails", "Banque", "Achats", "Travail"]


class Vault:
    def __init__(self, path: str):
        self.path = path
        self.entries: list[dict] = []
        self.paired: list[dict] = []  # extensions navigateur associées (empreintes de jetons)
        self.categories: list[str] = []
        self.on_saved = None  # appelé après chaque écriture réussie (sauvegarde cloud)
        self._data_key: bytearray | None = None
        self._slots: dict = {}

    # ---------- état ----------
    @property
    def exists(self) -> bool:
        return os.path.isfile(self.path)

    @property
    def unlocked(self) -> bool:
        return self._data_key is not None

    @property
    def has_recovery(self) -> bool:
        return "recovery" in self._slots

    def lock(self):
        if self._data_key is not None:
            # Écrase la copie qu'on contrôle (Python ne garantit pas l'effacement
            # des copies intermédiaires, mais on limite ce qui traîne).
            for i in range(len(self._data_key)):
                self._data_key[i] = 0
        self._data_key = None
        self._slots = {}
        self.entries = []
        self.paired = []
        self.categories = []
        self.forget_suspended()

    # ---------- verrouillage rapide (Windows Hello) ----------
    @property
    def suspended(self) -> bool:
        return getattr(self, "_suspended", None) is not None

    def suspend(self):
        """Verrouille, mais garde la clé de données chiffrée par Windows pour CE processus seulement
        (CryptProtectMemory) : resume() la retrouve sans mot de passe, après Windows Hello."""
        import winsec
        if self._data_key is None:
            raise VaultError("Coffre verrouillé.")
        kept = bytearray(self._data_key)
        winsec.protect_memory(kept)
        self.lock()
        self._suspended = kept

    def resume(self):
        import winsec
        if not self.suspended:
            raise VaultError("Aucun verrouillage rapide en cours.")
        key = bytearray(self._suspended)
        winsec.unprotect_memory(key)
        try:
            self._open(self._read(), bytes(key))
        finally:
            for i in range(len(key)):
                key[i] = 0
        self.forget_suspended()

    def forget_suspended(self):
        kept = getattr(self, "_suspended", None)
        if kept is not None:
            for i in range(len(kept)):
                kept[i] = 0
        self._suspended = None

    # ---------- création / ouverture ----------
    def create(self, password: str) -> str:
        """Crée le coffre et renvoie la clé de secours (à montrer une seule fois)."""
        if self.exists:
            raise VaultError("Un coffre existe déjà à cet emplacement.")
        data_key = secrets.token_bytes(32)
        recovery = generate_recovery_key()
        self._slots = {"master": _wrap(data_key, password, "master"),
                       "recovery": _wrap(data_key, recovery, "recovery")}
        self._data_key = bytearray(data_key)
        self.entries = []
        self.categories = list(DEFAULT_CATEGORIES)
        self.save()
        return recovery

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        if blob.get("format") != FORMAT or blob.get("version") != VERSION:
            raise VaultError("Fichier de coffre non reconnu.")
        return blob

    def _open(self, blob: dict, data_key: bytes):
        try:
            plain = AESGCM(data_key).decrypt(_b64d(blob["nonce"]), _b64d(blob["ciphertext"]),
                                             _aad({"format": FORMAT, "version": VERSION}))
        except InvalidTag:
            raise VaultError("Le contenu du coffre est altéré ou corrompu.")
        data = json.loads(plain.decode("utf-8"))
        self.entries = data.get("entries", [])
        self.paired = data.get("paired", [])
        self.categories = data.get("categories", list(DEFAULT_CATEGORIES))
        self._slots = blob["slots"]
        self._data_key = bytearray(data_key)

    def unlock(self, password: str):
        blob = self._read()
        self._open(blob, _unwrap(blob["slots"]["master"], password, "master"))

    def unlock_with_recovery(self, recovery_key: str):
        blob = self._read()
        if "recovery" not in blob["slots"]:
            raise VaultError("Ce coffre n'a pas de clé de secours.")
        self._open(blob, _unwrap(blob["slots"]["recovery"], normalize_recovery_key(recovery_key), "recovery"))

    def save(self):
        if self._data_key is None:
            raise VaultError("Coffre verrouillé.")
        nonce = secrets.token_bytes(12)
        plain = json.dumps({"entries": self.entries, "paired": self.paired, "categories": self.categories},
                           ensure_ascii=False).encode("utf-8")
        ct = AESGCM(bytes(self._data_key)).encrypt(nonce, plain, _aad({"format": FORMAT, "version": VERSION}))
        blob = {"format": FORMAT, "version": VERSION, "slots": self._slots,
                "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}

        folder = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".coffre-", dir=folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(blob, f)
                f.flush()
                os.fsync(f.fileno())
            if self.exists:
                os.replace(self.path, self.path + ".bak")
            os.replace(tmp, self.path)
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        if self.on_saved:
            self.on_saved()

    # ---------- serrures ----------
    def set_password(self, new: str):
        """Remplace le mot de passe maître (après ouverture par clé de secours)."""
        if self._data_key is None:
            raise VaultError("Coffre verrouillé.")
        self._slots["master"] = _wrap(bytes(self._data_key), new, "master")
        self.save()

    def change_password(self, old: str, new: str):
        if self._data_key is None:
            raise VaultError("Coffre verrouillé.")
        if not secrets.compare_digest(_unwrap(self._slots["master"], old, "master"), bytes(self._data_key)):
            raise WrongPassword("Ancien mot de passe incorrect.")
        self.set_password(new)

    def new_recovery_key(self) -> str:
        """Génère une nouvelle clé de secours ; l'ancienne ne fonctionne plus."""
        if self._data_key is None:
            raise VaultError("Coffre verrouillé.")
        recovery = generate_recovery_key()
        self._slots["recovery"] = _wrap(bytes(self._data_key), recovery, "recovery")
        self.save()
        return recovery

    # ---------- entrées ----------
    def add(self, site: str, username: str, password: str, url: str = "", notes: str = "", email: str = "",
            apps: list | None = None, category: str = "", favorite: bool = False) -> dict:
        now = time.time()
        entry = {
            "id": uuid.uuid4().hex, "site": site, "username": username, "email": email, "password": password,
            "url": url, "notes": notes, "apps": list(apps or []), "category": category, "favorite": favorite, "created": now, "modified": now,
        }
        self.entries.append(entry)
        self.save()
        return entry

    def update(self, entry_id: str, **fields):
        for e in self.entries:
            if e["id"] == entry_id:
                e.update(fields)
                e["modified"] = time.time()
                self.save()
                return e
        raise VaultError("Entrée introuvable.")

    # ---------- catégories ----------
    def add_category(self, name: str):
        name = name.strip()
        if not name:
            raise VaultError("Nom de catégorie vide.")
        if name.lower() in (c.lower() for c in self.categories):
            raise VaultError("Cette catégorie existe déjà.")
        self.categories.append(name)
        self.save()

    def rename_category(self, old: str, new: str):
        new = new.strip()
        if not new:
            raise VaultError("Nom de catégorie vide.")
        if new.lower() != old.lower() and new.lower() in (c.lower() for c in self.categories):
            raise VaultError("Cette catégorie existe déjà.")
        self.categories = [new if c == old else c for c in self.categories]
        for e in self.entries:
            if e.get("category") == old:
                e["category"] = new
        self.save()

    def delete_category(self, name: str):
        """Supprime la catégorie ; ses comptes passent « Sans catégorie » (rien n'est effacé)."""
        self.categories = [c for c in self.categories if c != name]
        for e in self.entries:
            if e.get("category") == name:
                e["category"] = ""
        self.save()

    def delete(self, entry_id: str):
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        self.save()

    def search(self, query: str) -> list[dict]:
        q = query.strip().lower()
        items = sorted(self.entries, key=lambda e: e["site"].lower())
        if not q:
            return items
        return [e for e in items if q in e["site"].lower() or q in e["username"].lower()
                or q in e.get("email", "").lower() or q in e["url"].lower()]


# ---------- générateur ----------
AMBIGUOUS = set("Il1O0o|`'\"")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?~"


def generate_password(length: int = 24, lower=True, upper=True, digits=True, symbols=True,
                      avoid_ambiguous=False) -> str:
    """Mot de passe aléatoire cryptographiquement sûr (module secrets),
    avec au moins un caractère de chaque famille choisie."""
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("Choisis au moins un type de caractères.")
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    if length < len(pools):
        raise ValueError("Longueur trop courte pour les familles choisies.")

    alphabet = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]
    # Mélange de Fisher-Yates avec une source sûre.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def estimate_entropy(password: str) -> float:
    """Estimation grossière (bits) d'après les familles de caractères présentes."""
    import math
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    if size == 0:
        return 0.0
    bits = len(password) * math.log2(size)
    # Pénalise les répétitions évidentes.
    unique_ratio = len(set(password)) / len(password)
    return bits * min(1.0, 0.5 + unique_ratio)


def strength_label(bits: float) -> tuple[str, str]:
    if bits < 40:
        return "Très faible", "#d9534f"
    if bits < 60:
        return "Faible", "#f0ad4e"
    if bits < 80:
        return "Correct", "#e6c200"
    if bits < 110:
        return "Fort", "#5cb85c"
    return "Très fort", "#2e8b57"
