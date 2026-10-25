"""Installe le lien entre l'extension navigateur et CoffreFort (Chrome, Brave, Opera GX, Edge).

- Fixe l'identifiant de l'extension (clé publique dans manifest.json) ;
- écrit le manifeste de l'hôte natif, qui n'autorise QUE cette extension ;
- l'enregistre dans le registre utilisateur (HKCU) de chaque navigateur.

Usage : python install_extension.py            (installer)
        python install_extension.py --uninstall
"""

import base64
import hashlib
import json
import os
import sys
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
EXT_DIR = os.path.join(HERE, "extension")
NATIVE_DIR = os.path.join(HERE, "native")
HOST_NAME = "com.coffrefort.host"
HOST_MANIFEST = os.path.join(NATIVE_DIR, HOST_NAME + ".json")

REG_PATHS = [
    r"Software\Google\Chrome\NativeMessagingHosts",          # Chrome (lu aussi par Opera / Opera GX)
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    r"Software\Opera Software\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
    r"Software\Chromium\NativeMessagingHosts",
]


def ensure_extension_key() -> str:
    path = os.path.join(EXT_DIR, "manifest.json")
    with open(path, encoding="utf-8") as f:
        manifest = json.load(f)
    if "key" not in manifest:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        # Seule la clé publique sert (identifiant stable) ; la clé privée est jetée.
        public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        manifest["key"] = base64.b64encode(der).decode("ascii")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest["key"]


def extension_id(key_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key_b64)).hexdigest()[:32]
    return "".join(chr(ord("a") + int(c, 16)) for c in digest)


def install():
    ext_id = extension_id(ensure_extension_key())
    python = sys.executable
    if os.path.basename(python).lower() == "pythonw.exe":
        python = os.path.join(os.path.dirname(python), "python.exe")
    bat = os.path.join(NATIVE_DIR, "host.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as f:
        f.write(f'@echo off\n"{python}" -I -u "%~dp0host.py" %*\n')
    with open(HOST_MANIFEST, "w", encoding="utf-8") as f:
        json.dump({
            "name": HOST_NAME,
            "description": "CoffreFort - lien avec l'application",
            "path": bat,
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{ext_id}/"],
        }, f, indent=2)
    for base in REG_PATHS:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + "\\" + HOST_NAME) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, HOST_MANIFEST)

    print("Lien installé pour Chrome, Brave, Opera / Opera GX et Edge.")
    print(f"Identifiant de l'extension : {ext_id}\n")
    print("Il reste à charger l'extension dans ton navigateur :")
    print("  1. Ouvre  brave://extensions  (ou opera://extensions, chrome://extensions)")
    print("  2. Active le « Mode développeur »")
    print("  3. « Charger l'extension non empaquetée » et choisis le dossier :")
    print(f"     {EXT_DIR}")
    print("  4. Épingle l'icône CoffreFort, ouvre-la et clique sur « Associer ».")


def uninstall():
    for base in REG_PATHS:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + "\\" + HOST_NAME)
        except FileNotFoundError:
            pass
    print("Lien désinstallé. Retire aussi l'extension de ton navigateur.")


if __name__ == "__main__":
    uninstall() if "--uninstall" in sys.argv else install()
