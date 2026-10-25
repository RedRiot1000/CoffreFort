"""Sauvegarde automatique vers un dossier synchronisé dans le cloud (MEGA, OneDrive…).

Le coffre est déjà chiffré : on copie le fichier tel quel, le cloud ne voit
jamais rien en clair. À chaque sauvegarde du coffre :
  <dossier>/coffre.vault                     dernière version
  <dossier>/versions/coffre-AAAA-MM-JJ.vault une copie par jour (30 derniers jours)
  <dossier>/CoffreFort-programme.zip          le programme, pour pouvoir tout réinstaller
  <dossier>/RESTAURER.txt                     la marche à suivre
Les versions protègent contre un coffre abîmé qui serait synchronisé tel quel.
"""

import glob
import hashlib
import io
import json
import os
import shutil
import tempfile
import time
import zipfile

from bridge import DATA_DIR

SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
HERE = os.path.dirname(os.path.abspath(__file__))
KEEP_VERSIONS = 30
PROGRAM_GLOBS = ["*.py", "*.pyw", "*.bat", "*.ps1", "update.json", "LISEZMOI.md", "native/host.py", "extension/*.*", "extension/icons/*.png"]

RESTORE_TEXT = """CoffreFort — restaurer après une panne
=====================================

Ce dossier contient ton coffre CHIFFRÉ. Sans ton mot de passe maître ou ta clé de
secours, il est illisible : il ne craint rien dans le cloud.

Sur le nouveau PC :
1. Installe Python 3 (python.org, coche « Add python.exe to PATH »).
2. Dans un terminal :  python -m pip install --user cryptography argon2-cffi
3. Dézippe CoffreFort-programme.zip où tu veux.
4. Lance « Lancer CoffreFort.bat » puis, sur l'écran de création,
   clique « Restaurer une sauvegarde… » et choisis coffre.vault
   (ou une version datée dans le dossier versions si la dernière pose problème).
5. Ouvre avec ton mot de passe maître (ou « Mot de passe oublié ? » + clé de secours).
6. Pour l'extension navigateur : relance « Installer extension.bat », recharge l'extension
   et ré-associe-la.
"""


def suggest_folder() -> str:
    home = os.path.expanduser("~")
    for root in (os.path.join(home, "Documents", "MEGA"), os.path.join(home, "MEGA"), os.path.join(home, "MEGAsync")):
        if os.path.isdir(root):
            return os.path.join(root, "CoffreFort-Sauvegarde")
    return ""


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {"backup_dir": suggest_folder(), "last_backup": 0}


def save_settings(settings: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)


def _atomic_write(path: str, data: bytes):
    # Préfixe « . » : MEGA ignore ces fichiers par défaut, il ne verra que le fichier final.
    fd, tmp = tempfile.mkstemp(prefix=".coffre-tmp-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _program_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for pattern in PROGRAM_GLOBS:
            for path in sorted(glob.glob(os.path.join(HERE, pattern))):
                arc = os.path.join("CoffreFort", os.path.relpath(path, HERE))
                info = zipfile.ZipInfo(arc, date_time=(2020, 1, 1, 0, 0, 0))  # date fixe : zip identique si rien n'a changé
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(path, "rb") as f:
                    z.writestr(info, f.read())
    return buf.getvalue()


def _write_if_changed(path: str, data: bytes):
    try:
        with open(path, "rb") as f:
            if hashlib.sha256(f.read()).digest() == hashlib.sha256(data).digest():
                return
    except FileNotFoundError:
        pass
    _atomic_write(path, data)


def run_backup(vault_path: str, folder: str) -> float:
    """Copie le coffre chiffré dans `folder`. Renvoie l'heure de la sauvegarde."""
    versions = os.path.join(folder, "versions")
    os.makedirs(versions, exist_ok=True)
    with open(vault_path, "rb") as f:
        data = f.read()
    _atomic_write(os.path.join(folder, "coffre.vault"), data)
    _atomic_write(os.path.join(versions, time.strftime("coffre-%Y-%m-%d.vault")), data)
    for old in sorted(glob.glob(os.path.join(versions, "coffre-*.vault")))[:-KEEP_VERSIONS]:
        os.remove(old)
    _write_if_changed(os.path.join(folder, "CoffreFort-programme.zip"), _program_zip())
    _write_if_changed(os.path.join(folder, "RESTAURER.txt"), RESTORE_TEXT.encode("utf-8"))
    return time.time()


def restore_file(source: str, vault_path: str):
    """Met un fichier de sauvegarde en place comme coffre (s'il n'en existe pas déjà un)."""
    with open(source, encoding="utf-8") as f:
        blob = json.load(f)
    if blob.get("format") != "coffrefort":
        raise ValueError("Ce fichier n'est pas un coffre CoffreFort.")
    if os.path.exists(vault_path):
        raise ValueError("Un coffre existe déjà sur ce PC.")
    os.makedirs(os.path.dirname(vault_path), exist_ok=True)
    shutil.copyfile(source, vault_path)
