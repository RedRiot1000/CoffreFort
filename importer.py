"""Import des mots de passe exportés par un navigateur (ou un autre gestionnaire) au format CSV.

CoffreFort ne lit pas les mots de passe enregistrés dans le navigateur : il faut les exporter depuis
le navigateur (fichier CSV), puis les importer ici. Le fichier exporté est EN CLAIR : la fenêtre
d'import propose de l'effacer une fois l'import fait.

Formats reconnus par le nom des colonnes : Chrome, Brave, Opera / Opera GX, Edge, Vivaldi
(name,url,username,password,note), Firefox (url,username,password,…), Bitwarden (login_uri,…),
LastPass (url,username,password,extra,name,…), et la plupart des autres.
"""

import csv
import io
import os
from urllib.parse import urlsplit

from bridge import entry_matches

COLUMNS = {
    "url": ("url", "login_uri", "website", "origin", "web site", "site web", "adresse"),
    "username": ("username", "login_username", "login", "user", "user name", "identifiant", "nom d'utilisateur"),
    "password": ("password", "login_password", "pass", "mot de passe"),
    "name": ("name", "title", "titre", "nom"),
    "notes": ("note", "notes", "extra", "comment", "comments"),
    "email": ("email", "e-mail", "mail"),
}

# Où trouver l'export dans chaque navigateur (affiché dans la fenêtre d'import).
BROWSERS = [
    ("Chrome", "chrome://password-manager/settings → Exporter les mots de passe"),
    ("Brave", "brave://password-manager/settings → Exporter les mots de passe"),
    ("Opera / Opera GX", "opera://password-manager/settings → Exporter les mots de passe"),
    ("Edge", "edge://wallet/passwords → ⋯ → Exporter les mots de passe"),
    ("Firefox", "about:logins → ⋯ → Exporter les identifiants"),
]

MAX_SIZE = 20 * 1024 * 1024


class ImportError_(Exception):
    pass


def _host(url: str) -> str:
    try:
        parts = urlsplit(url if "://" in url else "https://" + url)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https", ""):
        return ""  # android://… (applis du téléphone) : on garde le nom tel quel
    host = (parts.hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def site_name(name: str, url: str) -> str:
    """Nom lisible : celui de l'export s'il est parlant, sinon le domaine sans « www. »."""
    name = (name or "").strip()
    if url.startswith("android://"):
        # Compte d'une appli du téléphone : android://empreinte@com.instagram.android/ → « Instagram (appli) »
        package = url.split("@", 1)[-1].strip("/")
        words = [p for p in package.split(".") if p not in ("com", "android", "app", "apps", "mobile", "org", "net", "fr")]
        return (words[0].capitalize() if words else package) + " (appli)"
    host = _host(url)
    if name and name.lower() not in (host, "www." + host, url.lower()):
        return name
    # « accounts.google.com », « login.live.com » → « google.com », « live.com »
    labels = host.split(".")
    while len(labels) > 2 and labels[0] in ("accounts", "account", "login", "signin", "auth", "secure", "id", "m", "web"):
        labels = labels[1:]
    return ".".join(labels) or name or url or "Sans nom"


def read_csv(path: str) -> list[dict]:
    """Lit un export CSV et renvoie [{site, url, username, email, password, notes}]."""
    if os.path.getsize(path) > MAX_SIZE:
        raise ImportError_("Fichier trop gros pour un export de mots de passe.")
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if not rows:
        raise ImportError_("Fichier vide.")
    header = [h.strip().lower() for h in rows[0]]
    col = {}
    for field, names in COLUMNS.items():
        for n in names:
            if n in header:
                col[field] = header.index(n)
                break
    if "password" not in col or ("url" not in col and "name" not in col):
        raise ImportError_("Ce fichier ne ressemble pas à un export de mots de passe "
                           "(il faut au moins les colonnes « url » ou « name », et « password »).")

    def get(row, field):
        i = col.get(field)
        return row[i].strip() if i is not None and i < len(row) else ""

    out, seen = [], set()
    for row in rows[1:]:
        password = get(row, "password")
        if not password:
            continue
        url, username, email = get(row, "url"), get(row, "username"), get(row, "email")
        if not email and "@" in username and " " not in username and "." in username.split("@")[-1]:
            email, username = username, ""  # identifiant qui est en fait un e-mail
        item = {"site": site_name(get(row, "name"), url), "url": url, "username": username, "email": email,
                "password": password, "notes": get(row, "notes")}
        key = (_host(url) or item["site"].lower(), username.lower(), email.lower(), password)
        if key in seen:
            continue  # les navigateurs exportent souvent le même compte plusieurs fois
        seen.add(key)
        out.append(item)
    return sorted(out, key=lambda i: (i["site"].lower(), i["username"] or i["email"]))


def compare(items: list[dict], entries: list[dict]) -> None:
    """Ajoute à chaque élément son état par rapport au coffre : "new", "same" (déjà là) ou "changed"
    (même compte, mot de passe différent). Les comptes déjà présents sont décochés par défaut."""
    for it in items:
        host = _host(it["url"])
        login = (it["username"] or it["email"]).lower()
        twins = [e for e in entries
                 if ((host and entry_matches(e, host)) or e["site"].lower() == it["site"].lower())
                 and login in ((e.get("username") or "").lower(), (e.get("email") or "").lower())]
        it["twin"] = twins[0]["id"] if twins else None
        if any(e["password"] == it["password"] for e in twins):
            it["state"] = "same"
        elif twins:
            it["state"] = "changed"  # coché : l'import demande remplacer / garder les deux / ignorer
        else:
            it["state"] = "new"
        it["checked"] = it["state"] == "new"


def wipe(path: str) -> None:
    """Efface le fichier exporté : contenu écrasé puis fichier supprimé (pas de passage par la corbeille)."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(os.urandom(size))
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)
