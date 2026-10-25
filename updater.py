"""Mise à jour en ligne de CoffreFort, pour les copies partagées.

Actif seulement si update.json est présent : il n'existe que dans la copie
publiée sur GitHub. Le dossier de développement n'en a pas et ne contacte
jamais Internet.

Chaque version est décrite par release/manifest.json, signé (Ed25519) avec une
clé qui ne quitte jamais le PC de l'auteur ; seule la clé publique est dans
update.json. Une mise à jour non signée, modifiée, plus ancienne ou qui
changerait la clé est refusée, même si le dépôt GitHub était piraté.
"""

import hashlib
import io
import json
import os
import re
import shutil
import time
import urllib.request
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "update.json")
STAGING = os.path.join(HERE, ".maj")
TIMEOUT = 8
MAX_ZIP = 10 * 1024 * 1024
ALLOWED_SUFFIXES = (".py", ".pyw", ".bat", ".ps1", ".md", ".json", ".js", ".html", ".css", ".png")
MACHINE_FILES = ("native/host.bat", "native/com.coffrefort.host.json")  # propres à chaque PC, jamais remplacés


class UpdateError(Exception):
    pass


def load_config():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    if not (isinstance(cfg.get("version"), int)
            and re.fullmatch(r"[\w.-]+/[\w.-]+", str(cfg.get("repo", "")))
            and re.fullmatch(r"[\w.-]+", str(cfg.get("branch", "")))
            and re.fullmatch(r"[0-9a-f]{64}", str(cfg.get("public_key", "")))):
        return None
    return cfg


def enabled() -> bool:
    return load_config() is not None


def current_version():
    cfg = load_config()
    return cfg["version"] if cfg else None


def _url(cfg, path):
    return f"https://raw.githubusercontent.com/{cfg['repo']}/{cfg['branch']}/{path}"


def _get(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "CoffreFort-updater", "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise UpdateError("fichier trop gros")
    return data


def _check_path(name):
    if (name.startswith(("/", "\\")) or ":" in name or "\\" in name
            or any(part in ("", ".", "..") for part in name.split("/"))
            or not name.endswith(ALLOWED_SUFFIXES) or name in MACHINE_FILES):
        raise UpdateError(f"chemin refusé dans la mise à jour : {name!r}")


def check(cfg):
    """Renvoie le manifeste signé d'une version plus récente, ou None."""
    data = _get(_url(cfg, "release/manifest.json") + f"?t={int(time.time())}", 64 * 1024)
    sig = _get(_url(cfg, "release/manifest.sig") + f"?t={int(time.time())}", 1024)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(cfg["public_key"])).verify(
            bytes.fromhex(sig.decode("ascii").strip()), data)
    except (InvalidSignature, ValueError) as e:
        raise UpdateError("signature invalide : mise à jour refusée") from e
    m = json.loads(data)
    if m.get("format") != "coffrefort-update" or m.get("repo") != cfg["repo"]:
        raise UpdateError("manifeste inattendu")
    if not isinstance(m.get("version"), int) or m["version"] <= cfg["version"]:
        return None
    if not re.fullmatch(r"release/coffrefort-\d+\.zip", str(m.get("zip", ""))):
        raise UpdateError("manifeste inattendu")
    return m


def apply(cfg, m):
    blob = _get(_url(cfg, m["zip"]), MAX_ZIP)
    if hashlib.sha256(blob).hexdigest() != m.get("sha256"):
        raise UpdateError("archive corrompue")
    shutil.rmtree(STAGING, ignore_errors=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        for name in names:
            _check_path(name)
        if "update.json" not in names or "app.pyw" not in names:
            raise UpdateError("archive incomplète")
        new_cfg = json.loads(z.read("update.json"))
        if (new_cfg.get("version") != m["version"] or new_cfg.get("repo") != cfg["repo"]
                or new_cfg.get("public_key") != cfg["public_key"]):
            raise UpdateError("archive incohérente avec le manifeste signé")
        for name in names:
            dest = os.path.join(STAGING, *name.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(z.read(name))
    try:
        for name in names:
            if name.endswith((".py", ".pyw")):
                path = os.path.join(STAGING, *name.split("/"))
                with open(path, encoding="utf-8") as f:
                    compile(f.read(), path, "exec")
        # update.json en dernier : tant qu'il n'est pas remplacé, la version est retentée au prochain lancement.
        for name in sorted(names, key=lambda n: n == "update.json"):
            dest = os.path.join(HERE, *name.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.replace(os.path.join(STAGING, *name.split("/")), dest)
    finally:
        shutil.rmtree(STAGING, ignore_errors=True)
    return m["version"]


def update_now():
    """Installe la dernière version publiée. Renvoie le nouveau numéro, ou None si déjà à jour."""
    cfg = load_config()
    if cfg is None:
        return None
    m = check(cfg)
    return apply(cfg, m) if m else None
