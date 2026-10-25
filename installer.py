"""Installe CoffreFort sur ce PC (lancé par « Installer CoffreFort.bat », Python déjà présent).

- copie le programme dans %LOCALAPPDATA%\\Programs\\CoffreFort ;
- crée les raccourcis Bureau et menu Démarrer ;
- branche l'extension navigateur (install_extension.py).
Le coffre lui-même (%LOCALAPPDATA%\\CoffreFort) n'est jamais touché.
"""

import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEST = os.path.join(os.environ["LOCALAPPDATA"], "Programs", "CoffreFort")
IGNORE = shutil.ignore_patterns(".git", "release", "__pycache__", ".maj", "README.md",
                                "host.bat", "com.coffrefort.host.json")


def version_of(folder):
    try:
        with open(os.path.join(folder, "update.json"), encoding="utf-8") as f:
            return json.load(f)["version"]
    except (OSError, ValueError, KeyError):
        return 0


def shortcut(path, pythonw):
    ps = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK);"
        "$s.TargetPath = $env:PYW; $s.Arguments = '\"' + $env:APP + '\"';"
        "$s.WorkingDirectory = $env:DEST; $s.IconLocation = \"$env:SystemRoot\\System32\\imageres.dll,54\";"
        "$s.Description = 'CoffreFort - gestionnaire de mots de passe'; $s.Save()"
    )
    env = dict(os.environ, LNK=path, PYW=pythonw, APP=os.path.join(DEST, "app.pyw"), DEST=DEST)
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], env=env, check=True)


def special_folder(name):
    out = subprocess.run(["powershell", "-NoProfile", "-Command", f"[Environment]::GetFolderPath('{name}')"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def main():
    try:
        import argon2  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError as e:
        sys.exit(f"Bibliothèque manquante ({e.name}) : relance « Installer CoffreFort.bat ».")

    sys.path.insert(0, HERE)
    import bridge
    if bridge.ping_existing():
        sys.exit("CoffreFort est ouvert : ferme-le (bouton X), puis relance l'installation.")

    if os.path.normcase(HERE) != os.path.normcase(DEST):
        if version_of(DEST) > version_of(HERE):
            print("Une version plus récente est déjà installée : programme conservé.")
        else:
            shutil.copytree(HERE, DEST, ignore=IGNORE, dirs_exist_ok=True)
            print(f"Programme installé dans {DEST}")

    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    shortcut(os.path.join(special_folder("Desktop"), "CoffreFort.lnk"), pythonw)
    shortcut(os.path.join(special_folder("Programs"), "CoffreFort.lnk"), pythonw)
    print("Raccourcis créés (Bureau et menu Démarrer).\n")

    subprocess.run([sys.executable, os.path.join(DEST, "install_extension.py")], check=True)
    print("\n  ⚠ Choisis bien CE dossier-là, pas celui du zip téléchargé : sinon l'extension")
    print("    ne pourra pas se mettre à jour. Le dossier s'ouvre dans l'Explorateur.")
    os.startfile(os.path.join(DEST, "extension"))

    print("\nInstallation terminée. CoffreFort se met à jour tout seul à chaque lancement.")
    subprocess.Popen([pythonw, os.path.join(DEST, "app.pyw")], cwd=DEST)


if __name__ == "__main__":
    main()
